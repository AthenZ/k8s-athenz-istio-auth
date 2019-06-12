package onboarding

import (
	"errors"
	"log"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
)

const (
	authzEnabled           = "true"
	authzEnabledAnnotation = "authz.istio.io/enabled"
	numRetries             = 3
)

type Controller struct {
	store                model.ConfigStoreCache
	dnsSuffix            string
	serviceIndexInformer cache.SharedIndexInformer
	queue                workqueue.RateLimitingInterface
}

// NewController initializes the Controller object and its dependencies
func NewController(store model.ConfigStoreCache, dnsSuffix string, serviceIndexInformer cache.SharedIndexInformer) *Controller {
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	c := &Controller{
		store:                store,
		dnsSuffix:            dnsSuffix,
		serviceIndexInformer: serviceIndexInformer,
		queue:                queue,
	}

	serviceIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.processEvent(cache.MetaNamespaceKeyFunc, obj)
		},
		UpdateFunc: func(old interface{}, new interface{}) {
			c.processEvent(cache.MetaNamespaceKeyFunc, new)
		},
		DeleteFunc: func(obj interface{}) {
			c.processEvent(cache.DeletionHandlingMetaNamespaceKeyFunc, obj)
		},
	})

	return c
}

// processEvent processes the service watch events and puts them into the queue
func (c *Controller) processEvent(metaNamespaceKeyFunc func(obj interface{}) (string, error), obj interface{}) {
	key, err := metaNamespaceKeyFunc(obj)
	if err == nil {
		c.queue.Add(key)
		return
	}
	log.Println("Error converting object to key:", err)
}

// Run starts the worker thread
func (c *Controller) Run(stop chan struct{}) {
	defer c.queue.ShutDown()
	go wait.Until(c.runWorker, 0, stop)
	<-stop
}

// runWorker calls processNextItem to process events of the work queue
func (c *Controller) runWorker() {
	for c.processNextItem() {
	}
}

// processNextItem takes an item off the queue and calls the controllers sync
// function, handles the logic of requeuing in case any errors occur.
func (c *Controller) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(key)

	err := c.sync()
	if err != nil {
		log.Println("Error syncing cluster rbac config:", err)
		if c.queue.NumRequeues(key) < numRetries {
			c.queue.AddRateLimited(key)
			return true
		}
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

// createClusterRbacConfig creates the ClusterRbacConfig object in the cluster
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

// TODO, add service indexer with annotation check
func (crcMgr *Controller) getServiceList() []string {
	cacheServiceList := crcMgr.serviceIndexInformer.GetIndexer().List()
	serviceList := make([]string, 0)

	for _, service := range cacheServiceList {
		svc, ok := service.(*v1.Service)
		if !ok {
			log.Println("Could not cast to service object, skipping service list addition...")
			continue
		}

		key, exists := svc.Annotations[authzEnabledAnnotation]
		if exists && key == authzEnabled {
			serviceList = append(serviceList, svc.Name+"."+svc.Namespace+"."+crcMgr.dnsSuffix)
		}
	}

	return serviceList
}

// sync decides whether to create / update / delete the ClusterRbacConfig
// object based on the current onboarded services in the cluster.
func (crcMgr *Controller) sync() error {
	serviceList := crcMgr.getServiceList()
	config := crcMgr.store.Get(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, "")
	if config == nil {
		log.Println("Creating cluster rbac config...")
		return crcMgr.createClusterRbacConfig(serviceList)
	}

	clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
	if !ok {
		return errors.New("Could not cast to ClusterRbacConfig")
	}

	if clusterRbacConfig.Inclusion == nil {
		return errors.New("ClusterRbacConfig inclusion service list is empty")
	}

	newServices := findArrayDiff(serviceList, clusterRbacConfig.Inclusion.Services)
	crcMgr.addServices(newServices, clusterRbacConfig)

	oldServices := findArrayDiff(clusterRbacConfig.Inclusion.Services, serviceList)
	crcMgr.deleteServices(oldServices, clusterRbacConfig)

	if len(clusterRbacConfig.Inclusion.Services) == 0 {
		log.Println("Deleting cluster rbac config...")
		return crcMgr.store.Delete(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, v1.NamespaceDefault)
	}

	if len(newServices) > 0 || len(oldServices) > 0 {
		log.Println("Updating cluster rbac config...")
		_, err := crcMgr.store.Update(model.Config{
			ConfigMeta: config.ConfigMeta,
			Spec:       clusterRbacConfig,
		})
		return err
	}

	return nil
}

// TODO, rename the variables
// findArrayDiff compares the two arrays and returns the difference
func findArrayDiff(a, b []string) []string {
	myMap := make(map[string]bool, len(b))
	for _, item := range b {
		myMap[item] = true
	}

	// TODO, 0 will need to resize the array
	myArray := make([]string, 0)
	for _, item := range a {
		if _, exists := myMap[item]; !exists {
			myArray = append(myArray, item)
		}
	}

	return myArray
}

// remove removes an element from an array at the given index
func remove(s []string, i int) []string {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]
	return s[:len(s)-1]
}
