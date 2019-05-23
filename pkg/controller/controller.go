// Copyright 2018, Oath Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package controller

import (
	"log"
	"strings"
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/clusterrbacconfig"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/servicerole"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/servicerolebinding"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/util"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/zms"
)

// TODO, make these private
type Controller struct {
	PollInterval      time.Duration
	DNSSuffix         string
	srMgr             *servicerole.ServiceRoleMgr
	srbMgr            *servicerolebinding.ServiceRoleBindingMgr
	NamespaceIndexer  cache.Indexer
	NamespaceInformer cache.Controller
	serviceInformer   cache.Controller
	store             model.ConfigStoreCache
}

// getNamespaces is responsible for retrieving the namespaces currently in the indexer
func (c *Controller) getNamespaces() *v1.NamespaceList {
	namespaceList := v1.NamespaceList{}
	nList := c.NamespaceIndexer.List()

	for _, n := range nList {
		namespace, ok := n.(*v1.Namespace)
		if !ok {
			log.Println("Namespace cast failed")
			continue
		}

		namespaceList.Items = append(namespaceList.Items, *namespace)
	}

	return &namespaceList
}

// sync will be ran at every poll interval and will be responsible for the following:
// 1. Get the current ServiceRoles and ServiceRoleBindings on the cluster.
// 2. Call every Athenz domain which has a corresponding namespace in the cluster.
// 3. For every role name prefixed with service.role, call its corresponding policy in order to get the actions defined.
// 4. Each role / policy combo will create or update the associated ServiceRole if there were any changes.
// 5. The members of the role will be used to create or update the ServiceRoleBindings if there were any changes.
// 6. Delete any ServiceRoles or ServiceRoleBindings which do not have a corresponding Athenz mapping.
func (c *Controller) sync() error {
	serviceRoleMap, err := c.srMgr.GetServiceRoleMap()
	if err != nil {
		return err
	}
	log.Println("serviceRoleMap:", serviceRoleMap)

	serviceRoleBindingMap, err := c.srbMgr.GetServiceRoleBindingMap()
	if err != nil {
		return err
	}
	log.Println("serviceRoleBindingMap:", serviceRoleBindingMap)

	domainMap := make(map[string]*zms.Domain)
	errDomainMap := make(map[string]bool)
	namespaceList := c.getNamespaces()
	for _, namespace := range namespaceList.Items {
		domainName := util.NamespaceToDomain(namespace.Name)
		domain, err := zms.GetServiceMapping(domainName)
		if err != nil {
			log.Println(err)
			errDomainMap[domainName] = true
			continue
		}
		domainMap[domainName] = domain
	}
	log.Println("domainMap:", domainMap)

	for domainName, domain := range domainMap {
		for _, role := range domain.Roles {
			// ex: service.role.domain.service
			namespace := util.DomainToNamespace(domainName)
			roleName := strings.TrimPrefix(string(role.Role.Name), domainName+":role.service.role.")
			serviceRole, exists := serviceRoleMap[roleName+"-"+namespace]
			if !exists {
				log.Println("Service role", roleName, "does not exist, creating...")
				err := c.srMgr.CreateServiceRole(namespace, c.DNSSuffix, roleName, role.Policy)
				if err != nil {
					log.Println("Error creating service role:", err)
					continue
				}
				log.Println("Created service role", roleName, "in namespace", namespace)
				continue
			}

			log.Println("Service role", roleName, "already exists, updating...")
			serviceRole.Processed = true
			updated, err := c.srMgr.UpdateServiceRole(serviceRole.ServiceRole, c.DNSSuffix, roleName, role.Policy)
			if err != nil {
				log.Println("Error updating service role:", err)
				continue
			}
			if updated {
				log.Println("Updated service role", roleName, "in namespace", namespace)
			} else {
				log.Println("No difference found for service role", roleName, "in namespace", namespace,
					"not updating")
			}

			if len(role.Role.Members) == 0 {
				log.Println("Role", roleName, "has no members, skipping service role binding creation")
				continue
			}

			serviceRoleBinding, exists := serviceRoleBindingMap[roleName+"-"+namespace]
			if !exists {
				err = c.srbMgr.CreateServiceRoleBinding(namespace, roleName, role.Role.Members)
				if err != nil {
					log.Println("Error creating service role binding:", err)
					continue
				}
				log.Println("Created service role binding", roleName, "in namespace", namespace)
				continue
			}
			log.Println("Service role binding", roleName, "already exists, updating...")
			serviceRoleBinding.Processed = true
			updated, err = c.srbMgr.UpdateServiceRoleBinding(serviceRoleBinding.ServiceRoleBinding,
				namespace, roleName, role.Role.Members)
			if err != nil {
				log.Println("Error updating service role binding:", err)
				continue
			}

			if updated {
				log.Println("Updated service role binding", roleName, "in namespace", namespace)
			} else {
				log.Println("No difference found for service role binding", roleName, "in namespace", namespace,
					"not updating")
			}
		}
	}

	for _, serviceRole := range serviceRoleMap {
		domain := util.NamespaceToDomain(serviceRole.ServiceRole.Namespace)
		if _, exists := errDomainMap[domain]; exists {
			log.Println("Skipping delete for service role", serviceRole.ServiceRole.Name, "in namespace",
				serviceRole.ServiceRole.Namespace, "due to Athens error")
			continue
		}

		if !serviceRole.Processed {
			err := c.srMgr.DeleteServiceRole(serviceRole.ServiceRole.Name, serviceRole.ServiceRole.Namespace)
			if err != nil {
				log.Println("Error deleting service role:", err)
				continue
			}
			log.Println("Deleted service role", serviceRole.ServiceRole.Name, "in namespace",
				serviceRole.ServiceRole.Namespace)
		}
	}

	for _, serviceRoleBinding := range serviceRoleBindingMap {
		domain := util.NamespaceToDomain(serviceRoleBinding.ServiceRoleBinding.Namespace)
		if _, exists := errDomainMap[domain]; exists {
			log.Println("Skipping delete for service role binding", serviceRoleBinding.ServiceRoleBinding.Name,
				"in namespace", serviceRoleBinding.ServiceRoleBinding.Namespace, "due to Athens error")
			continue
		}

		if !serviceRoleBinding.Processed {
			err := c.srbMgr.DeleteServiceRoleBinding(serviceRoleBinding.ServiceRoleBinding.Name,
				serviceRoleBinding.ServiceRoleBinding.Namespace)
			if err != nil {
				log.Println("Error deleting service role binding:", err)
				continue
			}
			log.Println("Deleted service role binding", serviceRoleBinding.ServiceRoleBinding.Name, "in namespace",
				serviceRoleBinding.ServiceRoleBinding.Namespace)
		}
	}

	return nil
}

func NewController(pi time.Duration, dnsSuffix string) (*Controller, error) {
	configDescriptor := model.ConfigDescriptor{
		model.ServiceRole,
		model.ServiceRoleBinding,
		model.ClusterRbacConfig,
	}

	c, err := crd.NewClient("", "", configDescriptor, "svc.cluster.local")
	if err != nil {
		return nil, err
	}

	store := crd.NewController(c, kube.ControllerOptions{})
	srMgr := servicerole.NewServiceRoleMgr(c, store)
	srbMgr := servicerolebinding.NewServiceRoleBindingMgr(c, store)
	crcMgr := clusterrbacconfig.NewClusterRbacConfigMgr(c, store)

	// TODO, handle resync if object gets modified?
	store.RegisterEventHandler(model.ServiceRole.Type, srMgr.EventHandler)
	store.RegisterEventHandler(model.ServiceRoleBinding.Type, srbMgr.EventHandler)

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Panicln("failed to create InClusterConfig: " + err.Error())
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panicln(err.Error())
	}

	namespaceListWatch := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "namespaces",
		v1.NamespaceAll, fields.Everything())
	namespaceIndexer, namespaceInformer := cache.NewIndexerInformer(namespaceListWatch, &v1.Namespace{}, 0,
		cache.ResourceEventHandlerFuncs{}, cache.Indexers{})

	serviceListWatch := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "services", v1.NamespaceAll, fields.Everything())
	_, serviceInformer := cache.NewInformer(serviceListWatch, &v1.Service{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			crcMgr.SyncService(cache.Added, obj)
		},
		UpdateFunc: func(old interface{}, new interface{}) {
			crcMgr.SyncService(cache.Updated, new)
		},
		DeleteFunc: func(obj interface{}) {
			crcMgr.SyncService(cache.Deleted, obj)
		},
	})

	return &Controller{
		PollInterval:      pi,
		DNSSuffix:         dnsSuffix,
		srMgr:             srMgr,
		srbMgr:            srbMgr,
		serviceInformer:   serviceInformer,
		NamespaceIndexer:  namespaceIndexer,
		NamespaceInformer: namespaceInformer,
		store:             store,
	}, nil
}

// Run starts the main controller loop running sync at every poll interval
func (c *Controller) Run(stop chan struct{}) {
	go c.serviceInformer.Run(stop)
	go c.NamespaceInformer.Run(stop)
	go c.store.Run(stop)

	if !cache.WaitForCacheSync(stop, c.store.HasSynced, c.NamespaceInformer.HasSynced, c.serviceInformer.HasSynced) {
		// TODO
		//runtime.HandleError(errors.New("Timed out waiting for namespace cache to sync"))
		log.Panicln("Timed out waiting for namespace cache to sync.")
	}

	for {
		err := c.sync()
		if err != nil {
			log.Println("Error running sync:", err)
		}
		log.Println("Sleeping for", c.PollInterval)
		time.Sleep(c.PollInterval)
	}
}
