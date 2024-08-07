// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package controller

import (
	"time"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	"istio.io/client-go/pkg/clientset/versioned"
	"istio.io/istio/pkg/config/schema/collections"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	authzpolicy "github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/authorizationpolicy"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/onboarding"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/processor"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	crd "istio.io/istio/pilot/pkg/config/kube/crd/controller"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller"
	v1 "k8s.io/api/core/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	adClientset "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned"
	adInformer "github.com/yahoo/k8s-athenz-syncer/pkg/client/informers/externalversions/athenz/v1"
)

const queueNumRetries = 3

type Controller struct {
	configStoreCache            model.ConfigStoreCache
	crcController               *onboarding.Controller
	processor                   *processor.Controller
	serviceIndexInformer        cache.SharedIndexInformer
	adIndexInformer             cache.SharedIndexInformer
	apController                *authzpolicy.Controller
	queue                       workqueue.RateLimitingInterface
	adResyncInterval            time.Duration
	enableAuthzPolicyController bool
}

// getCallbackHandler returns a error handler func that re-adds the athenz domain back to queue
// this explicit func definition takes in the key to avoid data race while accessing key
func (c *Controller) getCallbackHandler(key string) common.OnCompleteFunc {
	return func(err error, item *common.Item) error {

		if err == nil {
			return nil
		}
		if item != nil {
			log.Errorf("Error performing %s on %s: %s", item.Operation, item.Resource.Key(), err.Error())
		}
		if apiErrors.IsNotFound(err) || apiErrors.IsAlreadyExists(err) {
			log.Infof("Error is non-retryable %s", err)
			return nil
		}
		if !apiErrors.IsConflict(err) {
			log.Infof("Retrying operation %s on %s due to processing error for %s", item.Operation, item.Resource.Key(), key)
			return err
		}
		if c.queue.NumRequeues(key) >= queueNumRetries {
			log.Errorf("Max number of retries reached for %s.", key)
			return nil
		}
		if item != nil {
			log.Infof("Retrying operation %s on %s due to processing error for %s", item.Operation, item.Resource.Key(), key)
		}
		c.queue.AddRateLimited(key)
		return nil
	}
}

// NewController is responsible for creating the main controller object and
// initializing all of its dependencies:
//  1. Rate limiting queue
//  2. Istio custom resource config store cache for service role, service role
//     bindings, and cluster rbac config
//  3. Onboarding controller responsible for creating / updating / deleting the
//     cluster rbac config object based on a service label
//  4. Service shared index informer
//  5. Athenz Domain shared index informer
//  6. Authorization Policy controller responsible for creating / updating / deleting
//     the authorization policy object based on service annotation and athenz domain spec
func NewController(dnsSuffix string, istioClient *crd.Client, k8sClient kubernetes.Interface, adClient adClientset.Interface,
	istioClientSet versioned.Interface, adResyncInterval, crcResyncInterval, apResyncInterval time.Duration, enableOriginJwtSubject bool,
	enableAuthzPolicyController bool, componentsEnabledAuthzPolicy *common.ComponentEnabled, combinationPolicyTag string, enableSpiffeTrustDomain bool,
	systemNamespaces []string, customServicetMap map[string]string, adminDomains []string) *Controller {
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	configStoreCache := crd.NewController(istioClient, controller.Options{})

	serviceListWatch := cache.NewListWatchFromClient(k8sClient.CoreV1().RESTClient(), "services", v1.NamespaceAll, fields.Everything())
	serviceIndexInformer := cache.NewSharedIndexInformer(serviceListWatch, &v1.Service{}, 0, nil)
	processor := processor.NewController(configStoreCache)
	crcController := onboarding.NewController(configStoreCache, dnsSuffix, serviceIndexInformer, crcResyncInterval, processor)
	adIndexInformer := adInformer.NewAthenzDomainInformer(adClient, 0, cache.Indexers{})

	// If enableAuthzPolicyController is enabled start the authzpolicy controller
	var apController *authzpolicy.Controller
	if enableAuthzPolicyController {
		apController = authzpolicy.NewController(configStoreCache, serviceIndexInformer, adIndexInformer, istioClientSet, apResyncInterval, enableOriginJwtSubject, componentsEnabledAuthzPolicy, combinationPolicyTag, false, enableSpiffeTrustDomain, systemNamespaces, customServicetMap, adminDomains)
		configStoreCache.RegisterEventHandler(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), apController.EventHandler)
	}

	c := &Controller{
		serviceIndexInformer: serviceIndexInformer,
		adIndexInformer:      adIndexInformer,
		configStoreCache:     configStoreCache,
		crcController:        crcController,
		processor:            processor,
		apController:         apController,

		queue:                       queue,
		adResyncInterval:            adResyncInterval,
		enableAuthzPolicyController: enableAuthzPolicyController,
	}

	configStoreCache.RegisterEventHandler(collections.IstioRbacV1Alpha1Serviceroles.Resource().GroupVersionKind(), c.processConfigEvent)
	configStoreCache.RegisterEventHandler(collections.IstioRbacV1Alpha1Servicerolebindings.Resource().GroupVersionKind(), c.processConfigEvent)
	configStoreCache.RegisterEventHandler(collections.IstioRbacV1Alpha1Clusterrbacconfigs.Resource().GroupVersionKind(), crcController.EventHandler)

	adIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.processEvent(cache.MetaNamespaceKeyFunc, obj)
		},
		UpdateFunc: func(_, obj interface{}) {
			c.processEvent(cache.MetaNamespaceKeyFunc, obj)
		},
		DeleteFunc: func(obj interface{}) {
			c.processEvent(cache.DeletionHandlingMetaNamespaceKeyFunc, obj)
		},
	})

	return c
}

// processEvent is responsible for calling the key function and adding the
// key of the item to the queue
func (c *Controller) processEvent(fn cache.KeyFunc, obj interface{}) {
	key, err := fn(obj)
	if err == nil {
		c.queue.Add(key)
		return
	}
	log.Errorf("Error calling key func: %s", err.Error())
}

// processConfigEvent is responsible for adding the key of the item to the queue
func (c *Controller) processConfigEvent(_ model.Config, config model.Config, e model.Event) {
	domain := athenz.NamespaceToDomain(config.Namespace)
	c.queue.Add(domain)
}

// Run starts the main controller loop running sync at every poll interval. It
// also starts the following controller dependencies:
// 1. Service informer
// 2. Istio custom resource informer
// 3. Athenz Domain informer
func (c *Controller) Run(stopCh <-chan struct{}) {
	go c.serviceIndexInformer.Run(stopCh)
	go c.configStoreCache.Run(stopCh)
	go c.adIndexInformer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, c.configStoreCache.HasSynced, c.serviceIndexInformer.HasSynced, c.adIndexInformer.HasSynced) {
		log.Panicln("Timed out waiting for namespace cache to sync.")
	}

	// crc controller must wait for service informer to sync before starting
	go c.processor.Run(stopCh)
	go c.crcController.Run(stopCh)
	if c.enableAuthzPolicyController {
		go c.apController.Run(stopCh)
	}
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
	keyRaw, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(keyRaw)
	key, ok := keyRaw.(string)
	if !ok {
		log.Errorf("String cast failed for key %v", key)
		c.queue.Forget(keyRaw)
		return true
	}

	return true
}

// resync will run as a periodic resync at a given interval, it will take all
// the current athenz domains in the cache and put them onto the queue
func (c *Controller) resync(stopCh <-chan struct{}) {
	t := time.NewTicker(c.adResyncInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			log.Infoln("Running resync for athenz domains...")
			adListRaw := c.adIndexInformer.GetIndexer().List()
			for _, adRaw := range adListRaw {
				c.processEvent(cache.MetaNamespaceKeyFunc, adRaw)
			}
		case <-stopCh:
			log.Infoln("Stopping athenz domain resync...")
			return
		}
	}
}
