// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package onboarding

import (
	"errors"
	"time"

	"k8s.io/api/core/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/constants"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/processor"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
)

const (
	queueNumRetries        = 3
	authzEnabled           = "true"
	authzEnabledAnnotation = "authz.istio.io/enabled"
	queueKey               = v1.NamespaceDefault + "/" + constants.DefaultRbacConfigName
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
		log.Errorf("Error syncing cluster rbac config for key %s: %s", key, err.Error())
		if c.queue.NumRequeues(key) < queueNumRetries {
			log.Infof("Retrying key %s due to sync error", key)
			c.queue.AddRateLimited(key)
			return true
		}
	}

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
			Name:    constants.DefaultRbacConfigName,
			Group:   model.ClusterRbacConfig.Group + constants.IstioAPIGroupDomain,
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
			log.Errorln("Could not cast to service object, skipping service list addition...")
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

// callbackHandler re-adds the key for a failed processor.sync operation
func (c *Controller) callbackHandler(err error, item *processor.Item) error {
	if err == nil {
		return nil
	}
	if item != nil {
		log.Errorf("Error performing %s on %s: %s", item.Operation, item.Resource.Key(), err)
	}
	if apiErrors.IsNotFound(err) || apiErrors.IsAlreadyExists(err) {
		log.Infof("Error is non-retryable %s", err)
		return nil
	}
	if !apiErrors.IsConflict(err) {
		log.Infof("Retrying operation %s on %s due to processing error for %s", item.Operation, item.Resource.Key(), queueKey)
		return err
	}
	if c.queue.NumRequeues(queueKey) >= queueNumRetries {
		log.Errorf("Max number of retries reached for %s.", queueKey)
		return nil
	}
	if item != nil {
		log.Infof("Retrying operation %s on %s due to processing error for %s", item.Operation, item.Resource.Key(), queueKey)
	}
	c.queue.AddRateLimited(queueKey)
	return nil
}

// sync decides whether to create / update / delete the ClusterRbacConfig
// object based on the current onboarded services in the cluster
func (c *Controller) sync() error {
	serviceList := c.getOnboardedServiceList()
	config := c.configStoreCache.Get(model.ClusterRbacConfig.Type, constants.DefaultRbacConfigName, "")
	if config == nil && len(serviceList) == 0 {
		log.Infoln("Service list is empty and cluster rbac config does not exist, skipping sync...")
		c.queue.Forget(queueKey)
		return nil
	}

	if config == nil {
		log.Infoln("Creating cluster rbac config...")
		item := processor.Item{
			Operation:       model.EventAdd,
			Resource:        newClusterRbacConfig(serviceList),
			CallbackHandler: c.callbackHandler,
		}
		c.processor.ProcessConfigChange(&item)
		return nil
	}

	if len(serviceList) == 0 {
		log.Infoln("Deleting cluster rbac config...")
		item := processor.Item{
			Operation:       model.EventDelete,
			Resource:        newClusterRbacConfig(serviceList),
			CallbackHandler: c.callbackHandler,
		}
		c.processor.ProcessConfigChange(&item)
		return nil
	}

	clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
	if !ok {
		return errors.New("Could not cast to ClusterRbacConfig")
	}

	if clusterRbacConfig.Inclusion == nil || clusterRbacConfig.Mode != v1alpha1.RbacConfig_ON_WITH_INCLUSION {
		log.Infoln("ClusterRBacConfig inclusion field is nil or ON_WITH_INCLUSION mode is not set, syncing...")
		config := model.Config{
			ConfigMeta: config.ConfigMeta,
			Spec:       newClusterRbacSpec(serviceList),
		}
		item := processor.Item{
			Operation:       model.EventUpdate,
			Resource:        config,
			CallbackHandler: c.callbackHandler,
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
		log.Infoln("Updating cluster rbac config...")
		config := model.Config{
			ConfigMeta: config.ConfigMeta,
			Spec:       clusterRbacConfig,
		}
		item := processor.Item{
			Operation:       model.EventUpdate,
			Resource:        config,
			CallbackHandler: c.callbackHandler,
		}
		c.processor.ProcessConfigChange(&item)
		return nil
	}

	log.Infoln("Sync state is current, no changes needed...")
	c.queue.Forget(queueKey)
	return nil
}

func (c *Controller) EventHandler(config model.Config, e model.Event) {
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
			log.Infoln("Running resync for cluster rbac config...")
			c.queue.Add(queueKey)
		case <-stopCh:
			log.Infoln("Stopping cluster rbac config resync...")
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
