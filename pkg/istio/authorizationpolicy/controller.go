// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package authzpolicy

import (
	"errors"
	"fmt"
	"github.com/ghodss/yaml"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	m "github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac"
	rbacv2 "github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/v2"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	adv1 "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	"io/ioutil"
	"istio.io/api/security/v1beta1"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/collections"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"os"
)

const (
	queueNumRetries        = 3
	authzEnabled           = "true"
	authzEnabledAnnotation = "authz.istio.io/enabled"
	DryRunStoredFilesDirectory   = "/root/authzpolicy/"
)

type Controller struct {
	ConfigStoreCache         model.ConfigStoreCache
	ServiceIndexInformer     cache.SharedIndexInformer
	AdIndexInformer          cache.SharedIndexInformer
	AuthzpolicyIndexInformer cache.SharedIndexInformer
	Queue                    workqueue.RateLimitingInterface
	RbacProviderV2           rbac.ProviderV2
	EnableOriginJwtSubject   bool
	Dryrun                   bool
}

type OnCompleteFunc func(err error, item *Item) error

type Item struct {
	Operation model.Event
	Resource  interface{}
}

func NewController(configStoreCache model.ConfigStoreCache, serviceIndexInformer cache.SharedIndexInformer, adIndexInformer cache.SharedIndexInformer, authzpolicyIndexInformer cache.SharedIndexInformer, enableOriginJwtSubject bool, apDryRun bool) *Controller {
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	if apDryRun {
		if _, err := os.Stat(DryRunStoredFilesDirectory); os.IsNotExist(err) {
			os.Mkdir(DryRunStoredFilesDirectory, 0644)
		}
	}

	c := &Controller{
		ConfigStoreCache:         configStoreCache,
		ServiceIndexInformer:     serviceIndexInformer,
		AdIndexInformer:          adIndexInformer,
		AuthzpolicyIndexInformer: authzpolicyIndexInformer,
		Queue:                    queue,
		RbacProviderV2:           rbacv2.NewProvider(enableOriginJwtSubject),
		EnableOriginJwtSubject:   enableOriginJwtSubject,
		Dryrun:                   apDryRun,
	}

	serviceIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			item := Item{
				Operation: model.EventAdd,
				Resource:  obj,
			}
			c.ProcessConfigChange(item)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			item := Item{
				Operation: model.EventUpdate,
				Resource:  newObj,
			}
			c.ProcessConfigChange(item)
		},
		DeleteFunc: func(obj interface{}) {
			item := Item{
				Operation: model.EventDelete,
				Resource:  obj,
			}
			c.ProcessConfigChange(item)
		},
	})

	adIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			item := Item{
				Operation: model.EventAdd,
				Resource:  obj,
			}
			c.ProcessConfigChange(item)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			item := Item{
				Operation: model.EventUpdate,
				Resource:  newObj,
			}
			c.ProcessConfigChange(item)
		},
	})

	authzpolicyIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			item := Item{
				Operation: model.EventAdd,
				Resource:  obj,
			}
			c.ProcessConfigChange(item)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			item := Item{
				Operation: model.EventUpdate,
				Resource:  newObj,
			}
			c.ProcessConfigChange(item)
		},
		DeleteFunc: func(obj interface{}) {
			item := Item{
				Operation: model.EventDelete,
				Resource:  obj,
			}
			c.ProcessConfigChange(item)
		},
	})

	return c
}

// ProcessConfigChange is responsible for adding the key of the item to the queue
func (c *Controller) ProcessConfigChange(item Item) {
	c.Queue.Add(item)
}

// Run starts the main controller loop running sync at every poll interval.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.Queue.ShutDown()
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
	itemRaw, quit := c.Queue.Get()
	if quit {
		return false
	}
	defer c.Queue.Done(itemRaw)
	item, ok := itemRaw.(string)
	if !ok {
		log.Errorf("String cast failed for item %v", item)
		c.Queue.Forget(item)
		return true
	}

	log.Infof("Processing item: %s", item)
	err := c.sync(itemRaw)
	if err != nil {
		log.Errorf("Error syncing k8s resource for item %s: %s", item, err)
		if c.Queue.NumRequeues(itemRaw) < queueNumRetries {
			log.Infof("Retrying item %s due to sync error", itemRaw)
			c.Queue.AddRateLimited(itemRaw)
			return true
		}
	}

	return true
}

// sync is responsible for invoking the appropriate API operation on the model.Config resource
func (c *Controller) sync(item interface{}) error {
	castItem, ok := item.(Item)
	if !ok {
		return fmt.Errorf("Unable to cast interface")
	}

	// check if resource can be cast to service, athenzdomain, or authorizationpolicy object
	_, svcCast := (castItem.Resource).(*corev1.Service)
	_, adCast := (castItem.Resource).(*adv1.AthenzDomain)
	_, apCast := (castItem.Resource).(*securityv1beta1.AuthorizationPolicy)
	if !(svcCast || adCast || apCast) {
		return fmt.Errorf("unable to cast interface to service or athenzDomain or authz policy object")
	}

	// dealing with service resource
	switch true {
	case svcCast:
		obj, _ := (castItem.Resource).(*corev1.Service)
		var convertedCR model.Config
		if castItem.Operation == model.EventAdd {
			// creation of service will check if istio annotation is set to true, will result in creation of authz policy
			// authz policy creation logic
			// check if current service has istio authz annotation set
			if _, ok = obj.Annotations[authzEnabledAnnotation]; ok && c.checkAuthzEnabledAnnotation(obj) {
				// here should check if authz policy is existing in the cluster
				log.Infof("istio authz annotation for service %s is set to true\n", obj.Name)
				err := c.createAuthzPolicyResource(convertedCR, obj)
				if err != nil {
					log.Errorln("error creating authz policy: ", err.Error())
					return err
				}
			}
			if _, ok = obj.Annotations[authzEnabledAnnotation]; !ok || !c.checkAuthzEnabledAnnotation(obj) {
				// case 1: when service has authz flag switch from true to false, authz policy with the same name present
				// case 2: when service has authzEnabledAnnotation removed, and authz policy with the same name present
				if !c.Dryrun {
					if res := c.ConfigStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace); res != nil {
						log.Infoln("Deleting Authz Policy ... ")
						err := c.ConfigStoreCache.Delete(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace)
						if err != nil {
							log.Errorln("error deleting authz policy: ", err.Error())
							return err
						}
					}
				} else {
					err := c.findDeleteDryrunResource(obj.Name, obj.Namespace)
					if err != nil {
						log.Errorln("error deleting local authz policy file: ", err.Error())
						return err
					}
				}
			}
		} else if castItem.Operation == model.EventUpdate {
			if _, ok = obj.Annotations[authzEnabledAnnotation]; ok {
				if c.checkAuthzEnabledAnnotation(obj) {
					if res := c.ConfigStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace); res == nil {
						log.Infof("istio authz annotation for service %s is updated to true\n", obj.Name)
						err := c.createAuthzPolicyResource(convertedCR, obj)
						if err != nil {
							log.Errorln("error creating authz policy: ", err.Error())
							return err
						}
					}
				} else {
					// case when service has authz flag switch from true to false, authz policy with the same name present
					if !c.Dryrun {
						if res := c.ConfigStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace); res != nil {
							log.Infoln("Deleting Authz Policy ... ")
							c.ConfigStoreCache.Delete(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace)
						}
					} else {
						err := c.findDeleteDryrunResource(obj.Name, obj.Namespace)
						if err != nil {
							log.Errorln("error deleting local authz policy file: ", err.Error())
							return err
						}
					}
				}
			} else {
				// case when service has authzEnabledAnnotation removed, and authz policy with the same name present
				if !c.Dryrun {
					if res := c.ConfigStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace); res != nil {
						log.Infoln("Deleting Authz Policy ... ")
						c.ConfigStoreCache.Delete(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace)
					}
				} else {
					err := c.findDeleteDryrunResource(obj.Name, obj.Namespace)
					if err != nil {
						log.Errorln("error deleting local authz policy file: ", err.Error())
						return err
					}
				}
			}
		} else if castItem.Operation == model.EventDelete {
			log.Infoln("Deleting Authz Policy ... ")
			if !c.Dryrun {
				c.ConfigStoreCache.Delete(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace)
			} else {
				err := c.findDeleteDryrunResource(obj.Name, obj.Namespace)
				if err != nil {
					log.Errorln("error deleting local authz policy file: ", err.Error())
					return err
				}
			}
		}
	case adCast:
		obj, _ := (castItem.Resource).(*adv1.AthenzDomain)
		// athenz domain create/update event should trigger a sync with existing authz policies in the corresponding namespace
		if castItem.Operation == model.EventUpdate || castItem.Operation == model.EventAdd {
			res, err := c.ConfigStoreCache.List(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), m.DomainToNamespace(obj.Name))
			if err != nil {
				return fmt.Errorf("Unable to list authz policies in namespace: %s", obj.Namespace)
			}
			for _, authzPolicy := range res {
				signedDomain := obj.Spec.SignedDomain
				domainRBAC := m.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &c.AdIndexInformer)
				authzSpec, ok := (authzPolicy.Spec).(*v1beta1.AuthorizationPolicy)
				if !ok {
					return fmt.Errorf("unable to cast interface to authorizationpolicies object")
				}
				convertedCR := c.RbacProviderV2.ConvertAthenzModelIntoIstioAuthzPolicy(domainRBAC, authzPolicy.Namespace, authzPolicy.Name, authzSpec.Selector.MatchLabels["svc"])
				log.Infof("Athenz Domain %s updated, updating Authz Policy in namespace %s ... ", obj.Name, m.DomainToNamespace(obj.Name))
				// assign current revision, update function requires a defined resource version
				convertedCR.ResourceVersion = authzPolicy.ResourceVersion
				if (!c.Dryrun) {
					revision, err := c.ConfigStoreCache.Update(convertedCR)
					if err != nil {
						log.Errorln("error updating authz policy: ", err.Error())
						return err
					}
					log.Infoln("Revision number is: ", revision)
				} else {
					err := c.createDryrunResource(convertedCR, authzPolicy.Name, obj.Namespace)
					if err != nil {
						return fmt.Errorf("unable write to file, err: %v", err)
					}
				}
			}
		}
	case apCast:
		obj, _ := (castItem.Resource).(*securityv1beta1.AuthorizationPolicy)
		// to prevent user manually edit authorization policy files
		if _, ok = obj.Annotations["overrideAuthzPolicy"]; !ok {
			athenzDomainRaw, exists, err := c.AdIndexInformer.GetIndexer().GetByKey(athenz.NamespaceToDomain(obj.Namespace))
			if err != nil {
				return err
			}

			if !exists {
				return fmt.Errorf("athenz domain %v does not exist in cache", obj.Namespace)
			}

			athenzDomain, ok := athenzDomainRaw.(*adv1.AthenzDomain)
			if !ok {
				return errors.New("athenz domain cast failed")
			}
			signedDomain := athenzDomain.Spec.SignedDomain
			// regenerate authz policy spec, since for authz policy's name match with service's label 'app' value
			// it can just pass in authz policy name as arg to func convertAthenzModelIntoIstioAuthzPolicy
			label := obj.Spec.Selector.MatchLabels["svc"]
			domainRBAC := m.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &c.AdIndexInformer)
			convertedCR := c.RbacProviderV2.ConvertAthenzModelIntoIstioAuthzPolicy(domainRBAC, obj.Namespace, obj.Name, label)
			if !c.Dryrun {
				// prevent manual editing the file
				if castItem.Operation == model.EventUpdate {
					// assign current revision, update function requires a defined resource version
					convertedCR.ResourceVersion = obj.ResourceVersion
					_, err := c.ConfigStoreCache.Update(convertedCR)
					if err != nil {
						log.Errorln("error updating authz policy: ", err.Error())
						return err
					}
				}
				// prevent
				if castItem.Operation == model.EventDelete {
					_, err := c.ConfigStoreCache.Create(convertedCR)
					if err != nil {
						log.Errorln("error updating authz policy: ", err.Error())
						return err
					}
				}
			} else {
				err := c.createDryrunResource(convertedCR, obj.Name, obj.Namespace)
				if err != nil {
					return fmt.Errorf("unable write to file, err: %v", err)
				}
			}
		}
	}
	return nil
}

// checkAuthzEnabledAnnotation checks if current servce object has "authz.istio.io/enabled" annotation set
func (c *Controller) checkAuthzEnabledAnnotation(serviceObj *corev1.Service) bool {
	if _, ok := serviceObj.Annotations[authzEnabledAnnotation]; ok {
		if serviceObj.Annotations[authzEnabledAnnotation] == authzEnabled {
			return true
		} else {
			return false
		}
	}
	return false
}

func (c *Controller) createDryrunResource(convertedCR model.Config, authzPolicyName string, namespace string) error {
	convertedObj, err := crd.ConvertConfig(collections.IstioSecurityV1Beta1Authorizationpolicies, convertedCR)
	if err != nil {
		log.Errorln("Unable to convert authorization policy config to istio objects")
	}
	configInBytes, err := yaml.Marshal(convertedObj)
	if err != nil {
		return fmt.Errorf("could not marshal %v: %v", convertedCR.Name, err)
	}
	yamlFileName := authzPolicyName + "--" + namespace + ".yaml"
	err = ioutil.WriteFile(DryRunStoredFilesDirectory + yamlFileName, configInBytes, 0644)
	if err != nil {
		return fmt.Errorf("unable write to file, err: %v", err)
	}
	return nil
}

func (c *Controller) findDeleteDryrunResource(authzPolicyName string, namespace string) error {
	yamlFileName := authzPolicyName + "--" + namespace + ".yaml"
	if _, err := os.Stat(DryRunStoredFilesDirectory + yamlFileName); os.IsNotExist(err) {
		log.Infof("file %s does not exist in local directory\n", DryRunStoredFilesDirectory + yamlFileName)
		return nil
	}
	log.Infof("deleting file under path: %s\n", DryRunStoredFilesDirectory + yamlFileName)
	err := os.Remove(DryRunStoredFilesDirectory + yamlFileName)

	if err != nil {
		return fmt.Errorf("unable to delete file, err: %v", err)
	}
	return nil
}

func (c *Controller) createAuthzPolicyResource(convertedCR model.Config, obj *corev1.Service) error {
	// form the authorization policy config and send create sign to the queue
	athenzDomainRaw, exists, err := c.AdIndexInformer.GetIndexer().GetByKey(athenz.NamespaceToDomain(obj.Namespace))
	if err != nil {
		return err
	}
	if !exists {
		// TODO, add the non existing athenz domain to the istio custom resource
		// processing controller to delete them
		return fmt.Errorf("athenz domain %v does not exist in cache", obj.Namespace)
	}

	athenzDomain, ok := athenzDomainRaw.(*adv1.AthenzDomain)
	if !ok {
		return errors.New("athenz domain cast failed")
	}
	signedDomain := athenzDomain.Spec.SignedDomain
	labels := obj.GetLabels()
	domainRBAC := m.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &c.AdIndexInformer)
	if _, ok := labels["svc"]; !ok {
		return fmt.Errorf("svc object does not contain label 'svc', unable to auto create authz policy")
	}
	convertedCR = c.RbacProviderV2.ConvertAthenzModelIntoIstioAuthzPolicy(domainRBAC, obj.Namespace, obj.Name, labels["svc"])
	log.Infoln("Creating Authz Policy ... ")
	if !c.Dryrun {
		revision, err := c.ConfigStoreCache.Create(convertedCR)
		if err != nil {
			log.Errorln("error creating authz policy: ", err.Error())
			return err
		}
		log.Infoln("Created revision number is: ", revision)
	} else {
		err := c.createDryrunResource(convertedCR, obj.Name, obj.Namespace)
		if err != nil {
			return fmt.Errorf("unable write to file, err: %v", err)
		}
	}
	return nil
}
