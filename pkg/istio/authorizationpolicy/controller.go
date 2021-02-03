// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package authzpolicy

import (
	"fmt"
	"github.com/ghodss/yaml"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac"
	rbacv1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/v1"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	adv1 "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	"io/ioutil"
	"istio.io/api/security/v1beta1"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	"istio.io/client-go/pkg/clientset/versioned"
	istioCache "istio.io/client-go/pkg/informers/externalversions/security/v1beta1"
	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/collections"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"os"
	"strings"
	"time"
)

const (
	queueNumRetries        = 3
	authzEnabled           = "true"
	authzEnabledAnnotation = "authz.istio.io/enabled"
	DryRunStoredFilesDirectory   = "/root/authzpolicy/"
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

type Item struct {
	Operation model.Event
	Resource  interface{}
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
			c.ProcessConfigChange(model.EventAdd, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			c.ProcessConfigChange(model.EventUpdate, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			c.ProcessConfigChange(model.EventDelete, obj)
		},
	})

	adIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.ProcessConfigChange(model.EventAdd, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			c.ProcessConfigChange(model.EventUpdate, newObj)
		},
	})

	authzpolicyIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.ProcessConfigChange(model.EventAdd, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			c.ProcessConfigChange(model.EventUpdate, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			c.ProcessConfigChange(model.EventDelete, obj)
		},
	})

	return c
}

func (c *Controller) EventHandler(config model.Config, _ model.Config, e model.Event) {
	item := Item{
		Operation: e,
		Resource: &config,
	}
	c.queue.Add(item)
}

// ProcessConfigChange is responsible for adding the key of the item to the queue
func (c *Controller) ProcessConfigChange(operation model.Event, obj interface{}) {
	item := Item{
		Operation: operation,
		Resource: obj,
	}
	c.queue.Add(item)
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
	itemRaw, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(itemRaw)

	err := c.sync(itemRaw)
	if err != nil {
		log.Errorf("Error syncing k8s resource for item %s: %s", itemRaw, err)
		if c.queue.NumRequeues(itemRaw) < queueNumRetries {
			log.Infof("Retrying item %s due to sync error", itemRaw)
			c.queue.AddRateLimited(itemRaw)
			return true
		}
	}

	return true
}

// sync is responsible for invoking the appropriate API operation on the model.Config resource
func (c *Controller) sync(item interface{}) error {
	castItem, ok := item.(Item)
	if !ok {
		return fmt.Errorf("unable to cast interface to Item object, item: %v", item)
	}

	// check if resource can be cast to service, athenzdomain, or authorizationpolicy object
	svcObj, svcCast := (castItem.Resource).(*corev1.Service)
	adObj, adCast := (castItem.Resource).(*adv1.AthenzDomain)
	apObj, apCast := (castItem.Resource).(*securityv1beta1.AuthorizationPolicy)
	if !(svcCast || adCast || apCast) {
		return fmt.Errorf("unable to cast interface to service or athenzDomain or authz policy object")
	}

	// dealing with service resource
	switch true {
	case svcCast:
		err := c.processSvcResource(castItem.Operation, svcObj)
		if err != nil {
			return fmt.Errorf("error processing service resource, resource name: %v, error: %v", svcObj.Name, err.Error())
		}
	case adCast:
		err := c.processAthenzDomainResource(castItem.Operation, adObj)
		if err != nil {
			return fmt.Errorf("error processing athenz domain resource, resource name: %v, error: %v", adObj.Name, err.Error())
		}
	case apCast:
		err := c.processAuthorizationPolicyResource(castItem.Operation, apObj)
		if err != nil {
			return fmt.Errorf("error processing authorization policy resource, resource name: %v, error: %v", apObj.Name, err.Error())
		}
	}
	return nil
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
				c.ProcessConfigChange(model.EventAdd, adRaw)
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
	return ioutil.WriteFile(DryRunStoredFilesDirectory + yamlFileName, configInBytes, 0644)
}

func (c *Controller) findDeleteDryrunResource(authzPolicyName string, namespace string) error {
	yamlFileName := authzPolicyName + "--" + namespace + ".yaml"
	if _, err := os.Stat(DryRunStoredFilesDirectory + yamlFileName); os.IsNotExist(err) {
		log.Infof("file %s does not exist in local directory\n", DryRunStoredFilesDirectory + yamlFileName)
		return nil
	}
	log.Infof("deleting file under path: %s\n", DryRunStoredFilesDirectory + yamlFileName)
	return os.Remove(DryRunStoredFilesDirectory + yamlFileName)
}

func (c *Controller) createAuthzPolicyResource(obj *corev1.Service) error {
	// form the authorization policy config and send create sign to the queue
	athenzDomainRaw, exists, err := c.adIndexInformer.GetIndexer().GetByKey(athenz.NamespaceToDomain(obj.Namespace))
	if err != nil {
		return fmt.Errorf("error when getting athenz domain from cache: %v", err.Error())
	}
	if !exists {
		// processing controller to delete them
		return fmt.Errorf("athenz domain %v does not exist in cache", obj.Namespace)
	}

	athenzDomain, ok := athenzDomainRaw.(*adv1.AthenzDomain)
	if !ok {
		return fmt.Errorf("athenz domain cast failed, domain: %v", athenz.NamespaceToDomain(obj.Namespace))
	}
	signedDomain := athenzDomain.Spec.SignedDomain
	labels := obj.GetLabels()
	domainRBAC := athenz.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &c.adIndexInformer)
	if _, ok := labels["svc"]; !ok {
		return fmt.Errorf("svc object does not contain label 'svc', unable to auto create authz policy")
	}
	convertedCR := c.rbacProvider.ConvertAthenzModelIntoIstioAuthzPolicy(domainRBAC, obj.Namespace, obj.Name, labels["svc"])
	log.Infoln("Creating Authz Policy ... ")
	if !c.dryrun {
		revision, err := c.configStoreCache.Create(convertedCR)
		if err != nil {
			log.Errorln("error creating authz policy:", err.Error())
			return err
		}
		log.Debugln("Created revision number is: ", revision)
	} else {
		err := c.createDryrunResource(convertedCR, obj.Name, obj.Namespace)
		if err != nil {
			return fmt.Errorf("unable write to file, err: %v", err)
		}
	}
	return nil
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

func (c *Controller) processSvcResource(operation model.Event, svcObj *corev1.Service) error {
	if operation == model.EventAdd || operation == model.EventUpdate {
		// service creation event: check if istio annotation is set to true, if so, create authz policy
		if c.checkAuthzEnabledAnnotation(svcObj) {
			log.Infof("istio authz annotation for service %s is set to true", svcObj.Name)
			err := c.createAuthzPolicyResource(svcObj)
			if err != nil {
				log.Errorln("error creating authz policy:", err.Error())
				return err
			}
		} else {
			// deletion - when there is service update
			// case 1: when service has authz flag switch from true to false, authz policy with the same name present
			// case 2: when service has authzEnabledAnnotation removed, and authz policy with the same name present
			if operation == model.EventUpdate {
				err := c.deleteAuthzPolicyResource(svcObj)
				if err != nil {
					log.Errorln("error deleting authz policy:", err.Error())
					return err
				}
			}
		}
	} else if operation == model.EventDelete {
		err := c.deleteAuthzPolicyResource(svcObj)
		if err != nil {
			log.Errorln("error deleting authz policy:", err.Error())
			return err
		}
	}
	return nil
}

func (c *Controller) processAthenzDomainResource(operation model.Event, adObj *adv1.AthenzDomain) error {
	// athenz domain create/update event should trigger a sync with existing authz policies in the corresponding namespace
	if operation == model.EventUpdate || operation == model.EventAdd {
		res, err := c.configStoreCache.List(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), athenz.DomainToNamespace(adObj.Name))
		if err != nil {
			return fmt.Errorf("unable to list authz policies in namespace: %s", adObj.Namespace)
		}
		// create a slice for the errors
		var errs []string
		for _, authzPolicy := range res {
			authzSpec, ok := (authzPolicy.Spec).(*v1beta1.AuthorizationPolicy)
			if !ok {
				errs = append(errs, fmt.Errorf("unable to cast interface to authorizationpolicies object, object: %v", authzPolicy.Spec).Error())
				continue
			}

			signedDomain := adObj.Spec.SignedDomain
			domainRBAC := athenz.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &c.adIndexInformer)
			convertedCR := c.rbacProvider.ConvertAthenzModelIntoIstioAuthzPolicy(domainRBAC, authzPolicy.Namespace, authzPolicy.Name, authzSpec.Selector.MatchLabels["svc"])
			log.Infof("Athenz Domain %s updated, updating Authz Policy %s in namespace %s ... ", adObj.Name, authzPolicy.Name, athenz.DomainToNamespace(adObj.Name))
			// assign current revision, update function requires a defined resource version
			convertedCR.ResourceVersion = authzPolicy.ResourceVersion
			if !c.dryrun {
				revision, err := c.configStoreCache.Update(convertedCR)
				if err != nil {
					errs = append(errs, fmt.Errorf("error updating authz policy: %v. resource name: %v", err.Error(), authzPolicy.Name).Error())
					continue
				}
				log.Debugln("Revision number is: ", revision)
			} else {
				err := c.createDryrunResource(convertedCR, authzPolicy.Name, athenz.DomainToNamespace(adObj.Name))
				if err != nil {
					errs = append(errs, fmt.Errorf("unable write to file, err: %v. resource name: %v", err.Error(), authzPolicy.Name).Error())
					continue
				}
			}
		}
		if len(errs) != 0 {
			return fmt.Errorf(strings.Join(errs, "\n"))
		}
	}
	// TODO: add delete event action
	return nil
}

func (c *Controller) processAuthorizationPolicyResource(operation model.Event, apObj *securityv1beta1.AuthorizationPolicy) error {
	if _, ok := apObj.Annotations["overrideAuthzPolicy"]; ok {
		return nil
	}
	// to prevent user manually edit authorization policy files
	// check if svc has annotation not set
	getSvc, exists, err := c.serviceIndexInformer.GetIndexer().GetByKey(apObj.Namespace+"/"+apObj.Name)
	if err != nil {
		return err
	}

	if !exists {
		log.Infoln("service does not exist in the cache, skip syncing...")
		return nil
	}
	svcObj := getSvc.(*corev1.Service)
	if !c.checkAuthzEnabledAnnotation(svcObj) {
		log.Infoln("service related to authz policy does not have annotation set, skip syncing...")
		return nil
	}
	//spew.Println("service list keys: ", c.serviceIndexInformer.GetStore().ListKeys())

	athenzDomainRaw, exists, err := c.adIndexInformer.GetIndexer().GetByKey(athenz.NamespaceToDomain(apObj.Namespace))
	if err != nil {
		return fmt.Errorf("error when getting athenz domain from athenz informer cache: %v. domain: %v", err, athenz.NamespaceToDomain(apObj.Namespace))
	}

	if !exists {
		return fmt.Errorf("athenz domain %v does not exist in cache", athenz.NamespaceToDomain(apObj.Namespace))
	}

	athenzDomain, ok := athenzDomainRaw.(*adv1.AthenzDomain)
	if !ok {
		return fmt.Errorf("athenz domain cast failed, domain: " + athenz.NamespaceToDomain(svcObj.Namespace))
	}
	signedDomain := athenzDomain.Spec.SignedDomain
	// regenerate authz policy spec, since for authz policy's name match with service's label 'app' value
	// it can just pass in authz policy name as arg to func convertAthenzModelIntoIstioAuthzPolicy
	label := apObj.Spec.Selector.MatchLabels["svc"]
	domainRBAC := athenz.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &c.adIndexInformer)
	convertedCR := c.rbacProvider.ConvertAthenzModelIntoIstioAuthzPolicy(domainRBAC, apObj.Namespace, apObj.Name, label)
	if !c.dryrun {
		// prevent manual editing the file
		if operation == model.EventUpdate {
			// assign current revision, update function requires a defined resource version
			convertedCR.ResourceVersion = apObj.ResourceVersion
			_, err := c.configStoreCache.Update(convertedCR)
			if err != nil {
				log.Errorln("error updating authz policy:", err.Error())
				return err
			}
		}
		// prevent manually deleting the file
		if operation == model.EventDelete {
			_, err := c.configStoreCache.Create(convertedCR)
			if err != nil {
				log.Errorln("error updating authz policy:", err.Error())
				return err
			}
		}
	} else {
		err := c.createDryrunResource(convertedCR, apObj.Name, apObj.Namespace)
		if err != nil {
			return fmt.Errorf("unable write to file, err: %v", err)
		}
	}
	return nil
}
