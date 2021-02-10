// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package authzpolicy

import (
	"errors"
	"fmt"
	"github.com/ghodss/yaml"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	rbacv1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/v1"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	adv1 "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	"io/ioutil"
	"istio.io/client-go/pkg/clientset/versioned"
	istioCache "istio.io/client-go/pkg/informers/externalversions/security/v1beta1"
	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/collections"
	corev1 "k8s.io/api/core/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"os"
	"strings"
	"time"
)

const (
	queueNumRetries            = 3
	authzEnabled               = "true"
	authzEnabledAnnotation     = "authz.istio.io/enabled"
	overrideAnnotation         = "overrideAuthzPolicy"
	DryRunStoredFilesDirectory = "/root/authzpolicy/"
)

type Controller struct {
	configStoreCache         model.ConfigStoreCache
	serviceIndexInformer     cache.SharedIndexInformer
	adIndexInformer          cache.SharedIndexInformer
	authzpolicyIndexInformer cache.SharedIndexInformer
	queue                    workqueue.RateLimitingInterface
	rbacProvider             rbac.Provider
	apResyncInterval         time.Duration
	enableOriginJwtSubject   bool
	dryrun                   bool
}

func NewController(configStoreCache model.ConfigStoreCache, serviceIndexInformer cache.SharedIndexInformer, adIndexInformer cache.SharedIndexInformer, istioClientSet versioned.Interface, apResyncInterval time.Duration, enableOriginJwtSubject bool, DryRun bool) *Controller {
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	if DryRun {
		if _, err := os.Stat(DryRunStoredFilesDirectory); os.IsNotExist(err) {
			os.MkdirAll(DryRunStoredFilesDirectory, 0644)
		}
	}

	authzpolicyIndexInformer := istioCache.NewAuthorizationPolicyInformer(istioClientSet, "", 0, cache.Indexers{})

	c := &Controller{
		configStoreCache:         configStoreCache,
		serviceIndexInformer:     serviceIndexInformer,
		adIndexInformer:          adIndexInformer,
		authzpolicyIndexInformer: authzpolicyIndexInformer,
		queue:                    queue,
		rbacProvider:             rbacv1.NewProvider(enableOriginJwtSubject),
		apResyncInterval:         apResyncInterval,
		enableOriginJwtSubject:   enableOriginJwtSubject,
		dryrun:                   DryRun,
	}

	serviceIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.processEvent(cache.MetaNamespaceKeyFunc, obj)
		},
		UpdateFunc: func(_, newObj interface{}) {
			c.processEvent(cache.MetaNamespaceKeyFunc, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			c.processEvent(cache.DeletionHandlingMetaNamespaceKeyFunc, obj)
		},
	})

	adIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.processEvent(cache.MetaNamespaceKeyFunc, obj)
		},
		UpdateFunc: func(_, newObj interface{}) {
			c.processEvent(cache.MetaNamespaceKeyFunc, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			c.processEvent(cache.DeletionHandlingMetaNamespaceKeyFunc, obj)
		},
	})

	authzpolicyIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.processEvent(cache.MetaNamespaceKeyFunc, obj)
		},
		UpdateFunc: func(_, newObj interface{}) {
			c.processEvent(cache.MetaNamespaceKeyFunc, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			c.processEvent(cache.DeletionHandlingMetaNamespaceKeyFunc, obj)
		},
	})

	return c
}

func (c *Controller) EventHandler(config model.Config, _ model.Config, e model.Event) {
	c.queue.Add(config.Key())
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

// Run starts the main controller loop running sync at every poll interval.
func (c *Controller) Run(stopCh <-chan struct{}) {
	go c.authzpolicyIndexInformer.Run(stopCh)
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
// function, handles the logic of re-queuing in case any errors occur
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

	log.Infof("Processing key: %s", key)
	err := c.sync(key)
	if err != nil {
		log.Errorf("Error syncing authz policy state for key %s: %s", keyRaw, err)
		if c.queue.NumRequeues(keyRaw) < queueNumRetries {
			log.Infof("Retrying key %s due to sync error", keyRaw)
			c.queue.AddRateLimited(keyRaw)
			return true
		}
	}

	return true
}

// draft: remodeled sync function. sync function receives a key string function, key can have three format:
// Case 1: for athenzdomain crd, key string is in format: <athenz domain name>, perform a service list scan.
//         Compute, compare and update authz policy specs based on current state in cluster
// Case 2: for service resource, key string is in format: <namespace name>/<service name>, look up svc in
//         cache and generate corresponding authz policy, update based on current state in cluster
// Case 3: for authorization policy, key string is in format: AuthorizationPolicy/<namespace name>/<service name>,
//         look up svc in cache and generate corresponding authz policy, update based on current state in cluster
func (c *Controller) sync(key string) error {
	var serviceName, athenzDomainName string

	parseKeyList := strings.Split(key, "/")
	if len(parseKeyList) > 1 {
		athenzDomainName = athenz.NamespaceToDomain(parseKeyList[len(parseKeyList)-2])
		serviceName = parseKeyList[len(parseKeyList)-1]
	} else {
		athenzDomainName = key
	}

	athenzDomainRaw, exists, err := c.adIndexInformer.GetIndexer().GetByKey(athenzDomainName)
	if err != nil {
		return err
	}

	if !exists {
		return fmt.Errorf("athenz domain %s does not exist in cache", athenzDomainName)
	}

	athenzDomain, ok := athenzDomainRaw.(*adv1.AthenzDomain)
	if !ok {
		return errors.New("athenz domain cast failed")
	}

	signedDomain := athenzDomain.Spec.SignedDomain
	domainRBAC := athenz.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &c.adIndexInformer)
	var serviceList []*corev1.Service
	if serviceName != "" {
		serviceObj, err := c.getSvcObj(athenz.DomainToNamespace(athenzDomainName) + "/" + serviceName)
		if err != nil {
			return fmt.Errorf("error getting service from cache: %s", err.Error())
		}
		serviceList = append(serviceList, serviceObj)
	} else {
		// handle case 2
		// fetch all services in the namespace
		// error checking
		// add to serviceList
		svcKeys := c.serviceIndexInformer.GetStore().ListKeys()
		for _, svcKey := range svcKeys {
			if strings.Split(svcKey, "/")[0] == athenz.DomainToNamespace(athenzDomainName) {
				serviceObj, err := c.getSvcObj(svcKey)
				if err != nil {
					return fmt.Errorf("error getting service from cache: %s", err.Error())
				}
				serviceList = append(serviceList, serviceObj)
			}
		}
	}

	var desiredCRs []model.Config
	// range over serviceList
	for _, service := range serviceList {
		if !c.checkAuthzEnabledAnnotation(service) {
			continue
		}
		// if svc annotation authz.istio.io/enabled is not present - skip processing and continue
		desiredCR := c.rbacProvider.ConvertAthenzModelIntoIstioAuthzPolicy(domainRBAC, service.Namespace, service.Name, service.Labels["svc"])
		// append to desiredCRs array
		desiredCRs = append(desiredCRs, desiredCR)
	}

	// get current APs from cache
	currentCRs := c.rbacProvider.GetCurrentIstioAuthzPolicy(domainRBAC, c.configStoreCache, serviceName)
	cbHandler := c.getCallbackHandler(key)
	changeList := common.ComputeChangeList(currentCRs, desiredCRs, cbHandler, c.checkOverrideAnnotation)

	// If change list is empty, nothing to do
	if len(changeList) == 0 {
		log.Infof("Everything is up-to-date for key: %s", key)
		c.queue.Forget(key)
		return nil
	}

	for _, item := range changeList {
		log.Infof("Adding resource action to queue: %s on %s for key: %s", item.Operation, item.Resource.Key(), key)
		c.ProcessConfigChange(item)
	}
	return nil
}

// checkOverrideAnnotation checks if current config has override annotation, skips process if override annotation is set
// to true
func (c *Controller) checkOverrideAnnotation(existingConfig model.Config) bool {
	if res, exists := existingConfig.ConfigMeta.Annotations[overrideAnnotation]; exists {
		return res == "true"
	} else {
		return exists
	}
}

// ProcessConfigChange receives resource and event action, and perform update on resource
func (c *Controller) ProcessConfigChange(item *common.Item) error {
	if item == nil {
		return nil
	}
	var err error

	// dry run mode on, create and store files
	if c.dryrun {
		switch item.Operation {
		case model.EventAdd:
			err = c.createDryrunResource(item.Resource, item.Resource.ConfigMeta.Name, item.Resource.ConfigMeta.Namespace)
		case model.EventUpdate:
			err = c.createDryrunResource(item.Resource, item.Resource.ConfigMeta.Name, item.Resource.ConfigMeta.Namespace)
		case model.EventDelete:
			err = c.findDeleteDryrunResource(item.Resource.ConfigMeta.Name, item.Resource.ConfigMeta.Namespace)
		}
		return err
	}

	// dry run mode off, call apis with operations
	switch item.Operation {
	case model.EventAdd:
		_, err = c.configStoreCache.Create(item.Resource)
	case model.EventUpdate:
		_, err = c.configStoreCache.Update(item.Resource)
	case model.EventDelete:
		res := item.Resource
		err = c.configStoreCache.Delete(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), res.Name, res.Namespace)
	}

	return err
}

// getSvcObj return single service resource in the cache
func (c *Controller) getSvcObj(svcKey string) (*corev1.Service, error) {
	serviceRaw, exists, err := c.serviceIndexInformer.GetIndexer().GetByKey(svcKey)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("service %s does not exist in cache", svcKey)
	}
	serviceObj, ok := serviceRaw.(*corev1.Service)
	if !ok {
		return nil, fmt.Errorf("service cast failed, raw object: %s", serviceRaw)
	}
	return serviceObj, nil
}

// getCallbackHandler returns an error handler func that re-adds the key "athenzdomain-service(optional)" back to queue
// this explicit func definition takes in the key to avoid data race while accessing key
func (c *Controller) getCallbackHandler(key string) common.OnCompleteFunc {
	return func(err error, item *common.Item) error {

		if err == nil {
			return nil
		}
		if item != nil {
			log.Errorf("Error performing %s on resource: %s, resource key: %s", item.Operation, err.Error(), key)
		}
		if apiErrors.IsNotFound(err) || apiErrors.IsAlreadyExists(err) {
			log.Infof("Error is non-retryable %s", err)
			return nil
		}
		if apiErrors.IsTimeout(err) {
			log.Infof("api request times out due to long processing, retrying key: %s", key)
		}
		if !apiErrors.IsConflict(err) {
			log.Infof("Retrying operation %s on resource due to processing error for %s", item.Operation, key)
			return err
		}
		if c.queue.NumRequeues(key) >= queueNumRetries {
			log.Errorf("Max number of retries reached for %s.", key)
			return nil
		}
		if item != nil {
			log.Infof("Retrying operation %s on resource due to processing error for %s", item.Operation, key)
		}
		c.queue.AddRateLimited(key)
		return nil
	}
}

// resync will run as a periodic resync at a given interval, it will take all
// the current athenz domains in the cache and put them onto the queue
func (c *Controller) resync(stopCh <-chan struct{}) {
	t := time.NewTicker(c.apResyncInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			log.Infoln("Running resync for authorization policies...")
			apListRaw := c.authzpolicyIndexInformer.GetIndexer().List()
			for _, adRaw := range apListRaw {
				//c.ProcessConfigChange(model.EventAdd, adRaw)
				c.processEvent(cache.MetaNamespaceKeyFunc, adRaw)
			}
		case <-stopCh:
			log.Infoln("Stopping authorization policies resync...")
			return
		}
	}
}

// checkAuthzEnabledAnnotation checks if current servce object has "authz.istio.io/enabled" annotation set
func (c *Controller) checkAuthzEnabledAnnotation(serviceObj *corev1.Service) bool {
	if _, ok := serviceObj.Annotations[authzEnabledAnnotation]; ok {
		if serviceObj.Annotations[authzEnabledAnnotation] == authzEnabled {
			return true
		}
	}
	return false
}

func (c *Controller) createDryrunResource(convertedCR model.Config, authzPolicyName string, namespace string) error {
	convertedObj, err := crd.ConvertConfig(collections.IstioSecurityV1Beta1Authorizationpolicies, convertedCR)
	if err != nil {
		return fmt.Errorf("unable to convert authorization policy config to istio objects, resource name: %v", convertedCR.Name)
	}
	configInBytes, err := yaml.Marshal(convertedObj)
	if err != nil {
		return fmt.Errorf("could not marshal %v: %v", convertedCR.Name, err)
	}
	yamlFileName := authzPolicyName + "--" + namespace + ".yaml"
	return ioutil.WriteFile(DryRunStoredFilesDirectory+yamlFileName, configInBytes, 0644)
}

func (c *Controller) findDeleteDryrunResource(authzPolicyName string, namespace string) error {
	yamlFileName := authzPolicyName + "--" + namespace + ".yaml"
	if _, err := os.Stat(DryRunStoredFilesDirectory + yamlFileName); os.IsNotExist(err) {
		log.Infof("file %s does not exist in local directory\n", DryRunStoredFilesDirectory+yamlFileName)
		return nil
	}
	log.Infof("deleting file under path: %s\n", DryRunStoredFilesDirectory+yamlFileName)
	return os.Remove(DryRunStoredFilesDirectory + yamlFileName)
}

func (c *Controller) deleteAuthzPolicyResource(obj *corev1.Service) error {
	log.Infoln("Deleting Authz Policy ...")
	if !c.dryrun {
		if res := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace); res != nil {
			err := c.configStoreCache.Delete(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace)
			if err != nil {
				return fmt.Errorf("error deleting authz policy %v, error: %v", obj.Name, err.Error())
			}
		} else {
			log.Infoln("no authorization policy resource found in cache, authorization policy name:", obj.Name)
			return nil
		}
	} else {
		err := c.findDeleteDryrunResource(obj.Name, obj.Namespace)
		if err != nil {
			return fmt.Errorf("error deleting local authz policy file: %v", err.Error())
		}
	}
	return nil
}

// genAuthzPolicyConfig is a common function uses by multiple events handler, it reads in athenz domain, given authz
// policy name, namespace and matching service label, derives authz policy config and return it
func (c *Controller) genAuthzPolicyConfig(signedDomain zms.SignedDomain, apNamespace, apName, svcLabel string) model.Config {
	domainRBAC := athenz.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &c.adIndexInformer)
	return c.rbacProvider.ConvertAthenzModelIntoIstioAuthzPolicy(domainRBAC, apNamespace, apName, svcLabel)
}
