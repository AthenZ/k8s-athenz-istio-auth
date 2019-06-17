// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package controller

import (
	"errors"
	"fmt"
	"log"
	"time"

	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	adv1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/apis/athenz/v1"
	m "github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	athenzClientset "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/clientset/versioned"
	athenzInformer "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/informers/externalversions/athenz/v1"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/onboarding"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac"
	rbacv1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/v1"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/util"
)

const queueNumRetries = 3

// TODO, rename store
type Controller struct {
	pollInterval         time.Duration
	dnsSuffix            string
	configStoreCache     model.ConfigStoreCache
	crcController        *onboarding.Controller
	serviceIndexInformer cache.SharedIndexInformer
	rbacProvider         rbac.Provider
	queue                workqueue.RateLimitingInterface
	adIndexInformer      cache.SharedIndexInformer
}

// TODO, update comments
// sync will be ran at every poll interval and will be responsible for the following:
// 1. Get the current ServiceRoles and ServiceRoleBindings on the cluster.
// 2. Call every Athenz domain which has a corresponding namespace in the cluster.
// 3. For every role name prefixed with service.role, call its corresponding policy in order to get the actions defined.
// 4. Each role / policy combo will create or update the associated ServiceRole if there were any changes.
// 5. The members of the role will be used to create or update the ServiceRoleBindings if there were any changes.
// 6. Delete any ServiceRoles or ServiceRoleBindings which do not have a corresponding Athenz mapping.
func (c *Controller) sync(key string) error {
	athenzDomainRaw, exists, err := c.adIndexInformer.GetIndexer().GetByKey(key)
	if err != nil {
		return err
	}

	if !exists {
		return fmt.Errorf("athenz domain %s does not exist in cache", key)
	}

	athenzDomain, ok := athenzDomainRaw.(*adv1.AthenzDomain)
	if !ok {
		return errors.New("cast failed for athenz domain")
	}

	signedDomain := athenzDomain.Spec.SignedDomain
	domainRBAC := m.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain)
	rbacCRs := c.rbacProvider.ConvertAthenzModelIntoIstioRbac(domainRBAC)

	for _, v := range rbacCRs {
		log.Printf("CustomResource: %s/%s/%s: ", v.Type, v.Namespace, v.Name)
		log.Println("Contents: ", v.Spec)
	}

	return nil
}

// NewController is responsible for creating the main controller object and
// all of its dependencies:
// 1. Rate limiting queue
// 2 Istio custom resource config store cache for service role, service role bindings, and clusterrbacconfig
// 3. Onboarding controller responsible for creating / updating / deleting the clusterrbacconfig object based on a service label
// 4. Kubernetes clientset
// 5. Service shared index informer
// 6. Athenz Domain shared index informer
func NewController(pollInterval time.Duration, dnsSuffix string, istioClient *crd.Client, k8sClient kubernetes.Interface, adClient athenzClientset.Interface) *Controller {
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	configStoreCache := crd.NewController(istioClient, kube.ControllerOptions{})

	// TODO, change resync periods, will this cause more events?
	// TODO understand shared index informer compared to normal informer / indexer
	serviceListWatch := cache.NewListWatchFromClient(k8sClient.CoreV1().RESTClient(), "services", v1.NamespaceAll, fields.Everything())
	serviceIndexInformer := cache.NewSharedIndexInformer(serviceListWatch, &v1.Service{}, 0, nil)
	crcController := onboarding.NewController(configStoreCache, dnsSuffix, serviceIndexInformer)
	adIndexInformer := athenzInformer.NewAthenzDomainInformer(adClient, v1.NamespaceAll, 0, cache.Indexers{})

	c := &Controller{
		pollInterval:         pollInterval,
		dnsSuffix:            dnsSuffix,
		serviceIndexInformer: serviceIndexInformer,
		configStoreCache:     configStoreCache,
		crcController:        crcController,
		rbacProvider:         rbacv1.NewProvider(),
		queue:                queue,
		adIndexInformer:      adIndexInformer,
	}

	// TODO, add full resync for objects
	configStoreCache.RegisterEventHandler(model.ServiceRole.Type, c.processConfigEvent)
	configStoreCache.RegisterEventHandler(model.ServiceRoleBinding.Type, c.processConfigEvent)
	configStoreCache.RegisterEventHandler(model.ClusterRbacConfig.Type, crcController.EventHandler)

	adIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.processAthenzDomainEvent(cache.MetaNamespaceKeyFunc, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			c.processAthenzDomainEvent(cache.MetaNamespaceKeyFunc, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			c.processAthenzDomainEvent(cache.DeletionHandlingMetaNamespaceKeyFunc, obj)
		},
	})

	return c
}

func (c *Controller) processAthenzDomainEvent(fn cache.KeyFunc, obj interface{}) {
	key, err := fn(obj)
	if err == nil {
		c.queue.Add(key)
		return
	}
	log.Println("err calling key func:", err)
}

func (c *Controller) processConfigEvent(config model.Config, e model.Event) {
	domain := util.NamespaceToDomain(config.Namespace)
	key := config.Namespace + "/" + domain
	c.queue.Add(key)
}

// Run starts the main controller loop running sync at every poll interval. It
// also starts the following controller dependencies:
// 1. Service informer
// 2. Istio custom resource informer
// 3. Athenz Domain informer
func (c *Controller) Run(stop chan struct{}) {
	go c.serviceIndexInformer.Run(stop)
	go c.configStoreCache.Run(stop)
	go c.adIndexInformer.Run(stop)

	if !cache.WaitForCacheSync(stop, c.configStoreCache.HasSynced, c.serviceIndexInformer.HasSynced, c.adIndexInformer.HasSynced) {
		log.Panicln("Timed out waiting for namespace cache to sync.")
	}

	// crc controller must wait for service informer to sync before starting
	go c.crcController.Run(stop)

	defer c.queue.ShutDown()
	wait.Until(c.runWorker, 0, stop)
}

// runWorker calls processNextItem to process events of the work queue
func (c *Controller) runWorker() {
	for c.processNextItem() {
	}
}

// processNextItem takes an item off the queue and calls the controllers sync
// function, handles the logic of requeuing in case any errors occur
func (c *Controller) processNextItem() bool {
	keyRaw, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(keyRaw)

	key, ok := keyRaw.(string)
	if !ok {
		log.Printf("string cast failed for key %v", key)
		return true
	}

	log.Println("Processing key:", key)
	err := c.sync(key)
	if err != nil {
		log.Printf("Error syncing athenz state for key %s: %s", keyRaw, err)
		if c.queue.NumRequeues(keyRaw) < queueNumRetries {
			log.Printf("Retrying key %s due to sync error", keyRaw)
			c.queue.AddRateLimited(keyRaw)
			return true
		}
	}

	c.queue.Forget(keyRaw)
	return true
}
