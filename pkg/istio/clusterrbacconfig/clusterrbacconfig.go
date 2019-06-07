package clusterrbacconfig

import (
	"errors"
	"log"

	"k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"fmt"
	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"
)

const authzEnabledAnnotation = "authz.istio.io/enabled"

type Controller struct {
	store           model.ConfigStoreCache
	dnsSuffix       string
	serviceIndexer  cache.Indexer
	serviceInformer cache.Controller
	queue           workqueue.RateLimitingInterface
}

// NewClusterRbacConfigMgr initializes the Controller object
func NewController(k8sClient kubernetes.Interface, store model.ConfigStoreCache, dnsSuffix string, queue workqueue.RateLimitingInterface) *Controller {
	serviceListWatch := cache.NewListWatchFromClient(k8sClient.CoreV1().RESTClient(), "services", v1.NamespaceAll, fields.Everything())
	c := &Controller{
		store:     store,
		dnsSuffix: dnsSuffix,
		//serviceIndexer: serviceIndexer,
		//serviceInformer: serviceInformer,
		queue: queue,
	}

	serviceIndexer, serviceInformer := cache.NewIndexerInformer(serviceListWatch, &v1.Service{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			svc, ok := obj.(*v1.Service)
			if !ok {
				log.Println("error")
				return
			}

			ann, exists := svc.Annotations[authzEnabledAnnotation]
			if exists && ann == "true" {
				err := c.Sync()
				if err != nil {
					log.Println(err)
				}
			}
			//log.Println("inside of add event")
			//
			//key, err := cache.MetaNamespaceKeyFunc(obj)
			//if err == nil {
			//	svc, ok := obj.(*v1.Service)
			//	if !ok {
			//		log.Println("error")
			//		return
			//	}
			//
			//	ann, exists := svc.Annotations[authzEnabledAnnotation]
			//	if exists && ann == "true" {
			//		log.Println("in add")
			//		queue.Add(key)
			//	}
			//} else {
			//	log.Println("err:", err)
			//}
		},
		UpdateFunc: func(old interface{}, new interface{}) {
			svc, ok := new.(*v1.Service)
			if !ok {
				log.Println("error")
				return
			}

			ann, exists := svc.Annotations[authzEnabledAnnotation]
			if exists && ann == "true" {
				err := c.Sync()
				if err != nil {
					log.Println(err)
				}
			}
			//log.Println("inside of update event")
			//
			//key, err := cache.MetaNamespaceKeyFunc(new)
			//if err == nil {
			//	svc, ok := new.(*v1.Service)
			//	if !ok {
			//		log.Println("error")
			//		return
			//	}
			//
			//	ann, exists := svc.Annotations[authzEnabledAnnotation]
			//	if exists && ann == "true" {
			//		log.Println("in update")
			//		queue.Add(key)
			//	}
			//} else {
			//	log.Println("err:", err)
			//}
		},
		DeleteFunc: func(obj interface{}) {
			svc, ok := obj.(*v1.Service)
			if !ok {
				log.Println("error")
				return
			}

			ann, exists := svc.Annotations[authzEnabledAnnotation]
			if exists && ann == "true" {
				err := c.Sync()
				if err != nil {
					log.Println(err)
				}
			}
			//log.Println("inside of delete event")
			//
			//key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			//if err == nil {
			//	svc, ok := obj.(*v1.Service)
			//	if !ok {
			//		log.Println("error")
			//		return
			//	}
			//
			//	ann, exists := svc.Annotations[authzEnabledAnnotation]
			//	if exists && ann == "true" {
			//		log.Println("in delete")
			//		queue.Add(key)
			//	}
			//} else {
			//	log.Println("err:", err)
			//}
		},
	}, nil)

	c.serviceInformer = serviceInformer
	c.serviceIndexer = serviceIndexer
	return c
}

func (c *Controller) Run(stop chan struct{}) {
	defer c.queue.ShutDown()
	go c.serviceInformer.Run(stop)

	if !cache.WaitForCacheSync(stop, c.serviceInformer.HasSynced) {
		log.Println("timed out waiting for cache to sync")
	}

	go wait.Until(c.runWorker, 0, stop)
	<-stop
	//go c.runWorker()
}

func (c *Controller) runWorker() {
	for c.processNextItem() {
	}
}

func (c *Controller) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(key)

	// TODO, how to handle error, requeue
	err := c.Sync()
	if err != nil {
		log.Println(err)
	}

	c.queue.Forget(key)
	return true
}

// addService will add a service to the ClusterRbacConfig object
func (crcMgr *Controller) addServices(services []string, clusterRbacConfig *v1alpha1.RbacConfig) {
	for _, service := range services {
		clusterRbacConfig.Inclusion.Services = append(clusterRbacConfig.Inclusion.Services, service)
	}
}

// deleteService will delete a service from the ClusterRbacConfig object
func (crcMgr *Controller) deleteServices(services []string, clusterRbacConfig *v1alpha1.RbacConfig) {
	for _, service := range services {
		var indexToRemove = -1
		for i, svc := range clusterRbacConfig.Inclusion.Services {
			if svc == service {
				indexToRemove = i
				break
			}
		}

		if indexToRemove != -1 {
			clusterRbacConfig.Inclusion.Services = remove(clusterRbacConfig.Inclusion.Services, indexToRemove)
		}
	}
}

// createClusterRbacConfig creates the ClusterRbacConfig object
func (crcMgr *Controller) createClusterRbacConfig(services []string) error {
	config := model.Config{
		ConfigMeta: model.ConfigMeta{
			Type:    model.ClusterRbacConfig.Type,
			Name:    model.DefaultRbacConfigName,
			Group:   model.ClusterRbacConfig.Group + model.IstioAPIGroupDomain,
			Version: model.ClusterRbacConfig.Version,
		},
		Spec: &v1alpha1.RbacConfig{
			Mode: v1alpha1.RbacConfig_ON_WITH_INCLUSION,
			Inclusion: &v1alpha1.RbacConfig_Target{
				Services: services,
			},
		},
	}

	_, err := crcMgr.store.Create(config)
	return err
}

func findDiff(a, b []string) []string {
	myMap := make(map[string]bool, len(b))
	for _, item := range b {
		myMap[item] = true
	}

	myArray := make([]string, len(a))
	for _, item := range a {
		if _, exists := myMap[item]; !exists {
			myArray = append(myArray, item)
		}
	}

	return myArray
}

func (crcMgr *Controller) getServiceList() []string {
	serviceList := crcMgr.serviceIndexer.List()
	//log.Println("serviceList:", serviceList)
	log.Println("serviceList length:", len(serviceList))
	svcList := make([]string, 0)

	for _, service := range serviceList {
		svc, ok := service.(*v1.Service)
		if !ok {
			log.Println("error")
			continue
		}

		key, exists := svc.Annotations[authzEnabledAnnotation]
		if exists && key == "true" {
			dns := svc.Name + "." + svc.Namespace + "." + crcMgr.dnsSuffix
			log.Println("appending to svc list", dns)
			svcList = append(svcList, dns)
			log.Println("svcList:", svcList)
			log.Println("svcList length:", len(svcList))
		}
	}

	return svcList
}

// syncClusterRbacConfig decides whether to create / update / delete the ClusterRbacConfig
// object based on a service create / update / delete action and if it has the authz enabled
// annotation set.
func (crcMgr *Controller) Sync() error {
	log.Println("inside of sync log")
	fmt.Println("inside of sync fmt")
	svcList := crcMgr.getServiceList()
	config := crcMgr.store.Get(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, "")
	if config == nil {
		log.Println("creating cluster rbac config")
		return crcMgr.createClusterRbacConfig(svcList)
	}

	clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
	if !ok {
		return errors.New("Could not cast to ClusterRbacConfig")
	}

	log.Println("svcList:", svcList)
	log.Println("crc list:", clusterRbacConfig.Inclusion.Services)

	newServices := findDiff(svcList, clusterRbacConfig.Inclusion.Services)
	crcMgr.addServices(newServices, clusterRbacConfig)

	oldServices := findDiff(clusterRbacConfig.Inclusion.Services, svcList)
	crcMgr.deleteServices(oldServices, clusterRbacConfig)

	if len(clusterRbacConfig.Inclusion.Services) == 0 {
		log.Println("deleting cluster rbac config")
		return crcMgr.store.Delete(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, "default")
	}

	if len(newServices) > 0 || len(oldServices) > 0 {
		log.Println("updating cluster rbac config")
		_, err := crcMgr.store.Update(model.Config{
			ConfigMeta: config.ConfigMeta,
			Spec:       clusterRbacConfig,
		})
		return err
	}

	return nil
}

// remove removes an element from an array at the given index
func remove(s []string, i int) []string {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]
	return s[:len(s)-1]
}
