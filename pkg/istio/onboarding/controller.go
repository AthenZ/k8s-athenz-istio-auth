// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package onboarding

import (
	"errors"
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/processor"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
)

const (
	queueNumRetries        = 3
	authzEnabled           = "true"
	authzEnabledAnnotation = "authz.istio.io/enabled"
	queueKey               = v1.NamespaceDefault + "/" + model.DefaultRbacConfigName
	logPrefix              = "[onboarding]"
)

type Controller struct {
	configStoreCache     model.ConfigStoreCache
	dnsSuffix            string
	serviceIndexInformer cache.SharedIndexInformer
	processor            *processor.Controller
	queue                workqueue.RateLimitingInterface
	crcResyncInterval    time.Duration
}

// NewController initializes the Controller object and its dependencies
func NewController(configStoreCache model.ConfigStoreCache, dnsSuffix string, serviceIndexInformer cache.SharedIndexInformer, crcResyncInterval time.Duration, processor *processor.Controller) *Controller {
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	c := &Controller{
		configStoreCache:     configStoreCache,
		dnsSuffix:            dnsSuffix,
		serviceIndexInformer: serviceIndexInformer,
		processor:            processor,
		queue:                queue,
		crcResyncInterval:    crcResyncInterval,
	}

	serviceIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(_ interface{}) {
			c.queue.Add(queueKey)
		},
		UpdateFunc: func(_ interface{}, _ interface{}) {
			c.queue.Add(queueKey)
		},
		DeleteFunc: func(_ interface{}) {
			c.queue.Add(queueKey)
		},
	})

	return c
}

// Run starts the worker thread
func (c *Controller) Run(stopCh <-chan struct{}) {
	go c.resync(stopCh)

	defer c.queue.ShutDown()
	wait.Until(c.runWorker, 0, stopCh)
}

// runWorker calls processNextItem to process events of the work queue
func (c *Controller) runWorker() {
	for c.processNextItem() {
	}
}

// processNextItem takes an item off the queue and calls the controllers sync
// function, handles the logic of requeuing in case any errors occur
func (c *Controller) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(key)

	err := c.sync()
	if err != nil {
		log.Errorf("%s Error syncing cluster rbac config for key %s: %s", logPrefix, key, err)
		if c.queue.NumRequeues(key) < queueNumRetries {
			log.Infof("%s Retrying key %s due to sync error", logPrefix, key)
			c.queue.AddRateLimited(key)
			return true
		}
	}

	c.queue.Forget(key)
	return true
}

// addService will add a service to the ClusterRbacConfig object
func addServices(services []string, clusterRbacConfig *v1alpha1.RbacConfig) {
	if clusterRbacConfig == nil || clusterRbacConfig.Inclusion == nil {
		return
	}

	for _, service := range services {
		clusterRbacConfig.Inclusion.Services = append(clusterRbacConfig.Inclusion.Services, service)
	}
}

// deleteService will delete a service from the ClusterRbacConfig object
func deleteServices(services []string, clusterRbacConfig *v1alpha1.RbacConfig) {
	if clusterRbacConfig == nil || clusterRbacConfig.Inclusion == nil {
		return
	}

	for _, service := range services {
		var indexToRemove = -1
		for i, svc := range clusterRbacConfig.Inclusion.Services {
			if svc == service {
				indexToRemove = i
				break
			}
		}

		if indexToRemove != -1 {
			clusterRbacConfig.Inclusion.Services = removeIndexElement(clusterRbacConfig.Inclusion.Services, indexToRemove)
		}
	}
}

// newClusterRbacSpec creates the rbac config object with the inclusion field
func newClusterRbacSpec(services []string) *v1alpha1.RbacConfig {
	return &v1alpha1.RbacConfig{
		Mode: v1alpha1.RbacConfig_ON_WITH_INCLUSION,
		Inclusion: &v1alpha1.RbacConfig_Target{
			Services: services,
		},
		Exclusion: nil,
	}
}

// newClusterRbacConfig creates the ClusterRbacConfig model config object
func newClusterRbacConfig(services []string) model.Config {
	return model.Config{
		ConfigMeta: model.ConfigMeta{
			Type:    model.ClusterRbacConfig.Type,
			Name:    model.DefaultRbacConfigName,
			Group:   model.ClusterRbacConfig.Group + model.IstioAPIGroupDomain,
			Version: model.ClusterRbacConfig.Version,
		},
		Spec: newClusterRbacSpec(services),
	}
}

// getOnboardedServiceList extracts all services from the indexer with the authz
// annotation set to true.
func (c *Controller) getOnboardedServiceList() []string {
	cacheServiceList := c.serviceIndexInformer.GetIndexer().List()
	serviceList := make([]string, 0)

	for _, service := range cacheServiceList {
		svc, ok := service.(*v1.Service)
		if !ok {
			log.Errorf("%s Could not cast to service object, skipping service list addition...", logPrefix)
			continue
		}

		key, exists := svc.Annotations[authzEnabledAnnotation]
		if exists && key == authzEnabled {
			serviceName := svc.Name + "." + svc.Namespace + "." + c.dnsSuffix
			serviceList = append(serviceList, serviceName)
		}
	}

	return serviceList
}

// errHandler re-adds the key for a failed processor.sync operation
func (c *Controller) errHandler(err error, item *processor.Item) error {
	if err != nil {
		if item != nil {
			log.Errorf("%s Error performing %s on %s: %s", logPrefix, item.Operation, item.Resource.Key(), err)
		}
		c.queue.AddRateLimited(queueKey)
	}
	return nil
}

// sync decides whether to create / update / delete the ClusterRbacConfig
// object based on the current onboarded services in the cluster
func (c *Controller) sync() error {
	serviceList := c.getOnboardedServiceList()
	config := c.configStoreCache.Get(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, "")
	if config == nil && len(serviceList) == 0 {
		log.Infof("%s Service list is empty and cluster rbac config does not exist, skipping sync...", logPrefix)
		return nil
	}

	if config == nil {
		log.Infof("%s Creating cluster rbac config...", logPrefix)
		item := processor.Item{
			Operation:    model.EventAdd,
			Resource:     newClusterRbacConfig(serviceList),
			ErrorHandler: c.errHandler,
		}
		c.processor.ProcessConfigChange(&item)
		return nil
	}

	if len(serviceList) == 0 {
		log.Infof("%s Deleting cluster rbac config...", logPrefix)
		item := processor.Item{
			Operation:    model.EventDelete,
			Resource:     newClusterRbacConfig(serviceList),
			ErrorHandler: c.errHandler,
		}
		c.processor.ProcessConfigChange(&item)
		return nil
	}

	clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
	if !ok {
		return errors.New("Could not cast to ClusterRbacConfig")
	}

	if clusterRbacConfig.Inclusion == nil || clusterRbacConfig.Mode != v1alpha1.RbacConfig_ON_WITH_INCLUSION {
		log.Infof("%s ClusterRBacConfig inclusion field is nil or ON_WITH_INCLUSION mode is not set, syncing...", logPrefix)
		config := model.Config{
			ConfigMeta: config.ConfigMeta,
			Spec:       newClusterRbacSpec(serviceList),
		}
		item := processor.Item{
			Operation:    model.EventUpdate,
			Resource:     config,
			ErrorHandler: c.errHandler,
		}
		c.processor.ProcessConfigChange(&item)
		return nil
	}

	newServices := compareServiceLists(serviceList, clusterRbacConfig.Inclusion.Services)
	if len(newServices) > 0 {
		addServices(newServices, clusterRbacConfig)
	}

	oldServices := compareServiceLists(clusterRbacConfig.Inclusion.Services, serviceList)
	if len(oldServices) > 0 {
		deleteServices(oldServices, clusterRbacConfig)
	}

	if len(newServices) > 0 || len(oldServices) > 0 {
		log.Infof("%s Updating cluster rbac config...", logPrefix)
		config := model.Config{
			ConfigMeta: config.ConfigMeta,
			Spec:       clusterRbacConfig,
		}
		item := processor.Item{
			Operation:    model.EventUpdate,
			Resource:     config,
			ErrorHandler: c.errHandler,
		}
		c.processor.ProcessConfigChange(&item)
		return nil
	}

	log.Infof("%s Sync state is current, no changes needed...", logPrefix)
	return nil
}

func (c *Controller) EventHandler(config model.Config, e model.Event) {
	log.Infof("%s Received %s event for cluster rbac config: %+v", logPrefix, e.String(), config)
	c.queue.Add(queueKey)
}

// resync will run as a periodic resync at a given interval, it will put the
// cluster rbac config key onto the queue
func (c *Controller) resync(stopCh <-chan struct{}) {
	t := time.NewTicker(c.crcResyncInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			log.Infof("%s Running resync for cluster rbac config...", logPrefix)
			c.queue.Add(queueKey)
		case <-stopCh:
			log.Infof("%s Stopping cluster rbac config resync...", logPrefix)
			return
		}
	}
}

// compareServices returns a list of which items in list A are not in list B
func compareServiceLists(serviceListA, serviceListB []string) []string {
	serviceMapB := make(map[string]bool, len(serviceListB))
	for _, item := range serviceListB {
		serviceMapB[item] = true
	}

	serviceListDiff := make([]string, 0)
	for _, item := range serviceListA {
		if _, exists := serviceMapB[item]; !exists {
			serviceListDiff = append(serviceListDiff, item)
		}
	}

	return serviceListDiff
}

// removeIndexElement removes an element from an array at the given index
func removeIndexElement(serviceList []string, indexToRemove int) []string {
	if indexToRemove > len(serviceList) || indexToRemove < 0 {
		return serviceList
	}

	serviceList[len(serviceList)-1],
		serviceList[indexToRemove] = serviceList[indexToRemove],
		serviceList[len(serviceList)-1]
	return serviceList[:len(serviceList)-1]
}
