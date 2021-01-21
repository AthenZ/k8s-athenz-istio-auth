// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package authzpolicy

import (
	"errors"
	"fmt"
	"io/ioutil"
	"istio.io/api/security/v1beta1"
	"istio.io/istio/pkg/config/schema/collections"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	m "github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	adv1 "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	workloadv1beta1 "istio.io/api/type/v1beta1"
	securityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const (
	allUsers                     = "user.*"
	WildCardAll                  = "*"
	AthenzJwtPrefix              = "athenz/"
	DryRunStoredFilesDirectory   = "/root/authzpolicy/"
)

const (
	authzEnabled           = "true"
	authzEnabledAnnotation = "authz.istio.io/enabled"
)

var resourceRegex = regexp.MustCompile(`\A(?P<domain>.*):svc.(?P<svc>[^:]*)[:]?(?P<path>.*)\z`)

var supportedMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodPost:    true,
	http.MethodPut:     true,
	http.MethodPatch:   true,
	http.MethodDelete:  true,
	http.MethodConnect: true,
	http.MethodOptions: true,
	http.MethodTrace:   true,
	"*":                true,
}

type Controller struct {
	configStoreCache         model.ConfigStoreCache
	serviceIndexInformer     cache.SharedIndexInformer
	adIndexInformer          cache.SharedIndexInformer
	authzpolicyIndexInformer cache.SharedIndexInformer
	queue                    workqueue.RateLimitingInterface
	enableOriginJwtSubject   bool
	dryrun                   bool
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
		configStoreCache:         configStoreCache,
		serviceIndexInformer:     serviceIndexInformer,
		adIndexInformer:          adIndexInformer,
		authzpolicyIndexInformer: authzpolicyIndexInformer,
		queue:                    queue,
		enableOriginJwtSubject:   enableOriginJwtSubject,
		dryrun:                   apDryRun,
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
	c.queue.Add(item)
}

// Run starts the main controller loop running sync at every poll interval.
func (c *Controller) Run(stopCh <-chan struct{}) {
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

	c.sync(itemRaw)

	return true
}

// sync is responsible for invoking the appropriate API operation on the model.Config resource
func (c *Controller) sync(item interface{}) error {
	castItem, ok := item.(Item)
	if !ok {
		return fmt.Errorf("Unable to cast interface")
	}
	// dealing with service resource
	if obj, ok := (castItem.Resource).(*corev1.Service); ok {
		var convertedCR model.Config
		if castItem.Operation == model.EventAdd {
			// creation of service will check if istio annotation is set to true, will result in creation of authz policy
			// authz policy creation logic
			// check if current service has istio authz annotation set
			if _, ok = obj.Annotations[authzEnabledAnnotation]; ok {
				if c.checkAuthzEnabledAnnotation(obj) {
					// here should check if authz policy is existing in the cluster
					log.Infof("istio authz annotation for service %s is set to true\n", obj.Name)
					// form the authorization policy config and send create sign to the queue
					athenzDomainRaw, exists, err := c.adIndexInformer.GetIndexer().GetByKey(athenz.NamespaceToDomain(obj.Namespace))
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
					domainRBAC := m.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &c.adIndexInformer)
					convertedCR = c.convertAthenzModelIntoIstioAuthzPolicy(domainRBAC, obj.Namespace, obj.Name, labels["svc"])
					log.Infoln("Creating Authz Policy ... ")
					if !c.dryrun {
						revision, err := c.configStoreCache.Create(convertedCR)
						if err != nil {
							log.Errorln("error creating authz policy: ", err.Error())
							return err
						}
						log.Infoln("Created revision number is: ", revision)
					} else {
						err := createDryrunResource(convertedCR, obj.Name, obj.Namespace)
						if err != nil {
							return fmt.Errorf("unable write to file, err: %v", err)
						}
					}
				} else {
					// case when service has authz flag switch from true to false, authz policy with the same name present
					if !c.dryrun {
						if res := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace); res != nil {
							log.Infoln("Deleting Authz Policy ... ")
							err := c.configStoreCache.Delete(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace)
							if err != nil {
								log.Errorln("error deleting authz policy: ", err.Error())
								return err
							}
						}
					} else {
						err := findDeleteDryrunResource(obj.Name, obj.Namespace)
						if err != nil {
							log.Errorln("error deleting local authz policy file: ", err.Error())
							return err
						}
					}
				}
			} else {
				// case when service has authzEnabledAnnotation removed, and authz policy with the same name present
				if !c.dryrun {
					if res := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace); res != nil {
						log.Infoln("Deleting Authz Policy ... ")
						err := c.configStoreCache.Delete(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace)
						if err != nil {
							log.Errorln("error deleting authz policy: ", err.Error())
							return err
						}
					}
				} else {
					err := findDeleteDryrunResource(obj.Name, obj.Namespace)
					if err != nil {
						log.Errorln("error deleting local authz policy file: ", err.Error())
						return err
					}
				}
			}
		} else if castItem.Operation == model.EventUpdate {
			if _, ok = obj.Annotations[authzEnabledAnnotation]; ok {
				if c.checkAuthzEnabledAnnotation(obj) {
					if res := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace); res == nil {
						log.Infof("istio authz annotation for service %s is updated to true\n", obj.Name)
						// form the authorization policy config
						athenzDomainRaw, exists, err := c.adIndexInformer.GetIndexer().GetByKey(athenz.NamespaceToDomain(obj.Namespace))
						if err != nil {
							return err
						}

						if !exists {
							// TODO, add the non existing athenz domain to the istio custom resource
							// processing controller to delete them
							return fmt.Errorf("athenz domain %s does not exist in cache", obj.Namespace)
						}

						athenzDomain, ok := athenzDomainRaw.(*adv1.AthenzDomain)
						if !ok {
							return errors.New("athenz domain cast failed")
						}

						signedDomain := athenzDomain.Spec.SignedDomain
						labels := obj.GetLabels()
						domainRBAC := m.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &c.adIndexInformer)
						convertedCR = c.convertAthenzModelIntoIstioAuthzPolicy(domainRBAC, obj.Namespace, obj.Name, labels["svc"])
						log.Infoln("Creating Authz Policy ... ")
						if !c.dryrun {
							revision, err := c.configStoreCache.Create(convertedCR)
							if err != nil {
								log.Errorln("error creating authz policy: ", err.Error())
								return err
							}
							log.Infoln("Created revision number is: ", revision)
						} else {
							err := createDryrunResource(convertedCR, obj.Name, obj.Namespace)
							if err != nil {
								return fmt.Errorf("unable write to file, err: %v", err)
							}
						}
					}
				} else {
					// case when service has authz flag switch from true to false, authz policy with the same name present
					if !c.dryrun {
						if res := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace); res != nil {
							log.Infoln("Deleting Authz Policy ... ")
							c.configStoreCache.Delete(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace)
						}
					} else {
						err := findDeleteDryrunResource(obj.Name, obj.Namespace)
						if err != nil {
							log.Errorln("error deleting local authz policy file: ", err.Error())
							return err
						}
					}
				}
			} else {
				// case when service has authzEnabledAnnotation removed, and authz policy with the same name present
				if !c.dryrun {
					if res := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace); res != nil {
						log.Infoln("Deleting Authz Policy ... ")
						c.configStoreCache.Delete(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace)
					}
				} else {
					err := findDeleteDryrunResource(obj.Name, obj.Namespace)
					if err != nil {
						log.Errorln("error deleting local authz policy file: ", err.Error())
						return err
					}
				}
			}
		} else if castItem.Operation == model.EventDelete {
			log.Infoln("Deleting Authz Policy ... ")
			if !c.dryrun {
				c.configStoreCache.Delete(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), obj.Name, obj.Namespace)
			} else {
				err := findDeleteDryrunResource(obj.Name, obj.Namespace)
				if err != nil {
					log.Errorln("error deleting local authz policy file: ", err.Error())
					return err
				}
			}
		}
	} else if obj, ok := (castItem.Resource).(*adv1.AthenzDomain); ok {
		// athenz domain update will result in update in the authz policies in the corresponding namespace
		if castItem.Operation == model.EventUpdate {
			// authz policies exist in the namespace
			res, err := c.configStoreCache.List(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), m.DomainToNamespace(obj.Name))
			if err != nil {
				return fmt.Errorf("Unable to list authz policies in namespace: %s", obj.Namespace)
			}
			for _, authzPolicy := range res {
				signedDomain := obj.Spec.SignedDomain
				domainRBAC := m.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &c.adIndexInformer)
				authzSpec, ok := (authzPolicy.Spec).(*v1beta1.AuthorizationPolicy)
				if !ok {
					return fmt.Errorf("unable to cast interface to authorizationpolicies object")
				}
				convertedCR := c.convertAthenzModelIntoIstioAuthzPolicy(domainRBAC, authzPolicy.Namespace, authzPolicy.Name, authzSpec.Selector.MatchLabels["svc"])
				log.Infof("Athenz Domain %s updated, updating Authz Policy in namespace %s ... ", obj.Name, m.DomainToNamespace(obj.Name))
				// assign current revision, update function requires a defined resource version
				convertedCR.ResourceVersion = authzPolicy.ResourceVersion
				if (!c.dryrun) {
					revision, err := c.configStoreCache.Update(convertedCR)
					if err != nil {
						log.Errorln("error updating authz policy: ", err.Error())
						return err
					}
					log.Infoln("Revision number is: ", revision)
				} else {
					err := createDryrunResource(convertedCR, authzPolicy.Name, obj.Namespace)
					if err != nil {
						return fmt.Errorf("unable write to file, err: %v", err)
					}
				}
			}
		}
	} else if obj, ok := (castItem.Resource).(*securityv1beta1.AuthorizationPolicy); ok{
		// to prevent user manually edit authorization policy files
		if _, ok = obj.Annotations["overrideAuthzPolicy"]; !ok {
			athenzDomainRaw, exists, err := c.adIndexInformer.GetIndexer().GetByKey(athenz.NamespaceToDomain(obj.Namespace))
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
			label := obj.Name
			domainRBAC := m.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &c.adIndexInformer)
			convertedCR := c.convertAthenzModelIntoIstioAuthzPolicy(domainRBAC, obj.Namespace, obj.Name, label)
			if !c.dryrun {
				// prevent manual editing the file
				if castItem.Operation == model.EventUpdate {
					// assign current revision, update function requires a defined resource version
					convertedCR.ResourceVersion = obj.ResourceVersion
					_, err := c.configStoreCache.Update(convertedCR)
					if err != nil {
						log.Errorln("error updating authz policy: ", err.Error())
						return err
					}
				}
				// prevent
				if castItem.Operation == model.EventDelete {
					_, err := c.configStoreCache.Create(convertedCR)
					if err != nil {
						log.Errorln("error updating authz policy: ", err.Error())
						return err
					}
				}
			} else {
				err := createDryrunResource(convertedCR, obj.Name, obj.Namespace)
				if err != nil {
					return fmt.Errorf("unable write to file, err: %v", err)
				}
			}
		}
	} else {
		return fmt.Errorf("unable to cast interface to service or athenzDomain object")
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

func (c *Controller) convertAthenzModelIntoIstioAuthzPolicy(athenzModel athenz.Model, namespace string, serviceName string, svcLabel string) model.Config {
	// authz policy is created per service. each rule is created by each role, and form the rules under
	// this authz policy.
	var out model.Config
	// form authorization config meta
	// namespace: service's namespace
	// name: service's name
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	out.ConfigMeta = model.ConfigMeta{
		Type:      schema.Resource().Kind(),
		Group:     schema.Resource().Group(),
		Version:   schema.Resource().Version(),
		Namespace: namespace,
		Name:      serviceName,
	}

	// matching label, same with the service label
	spec := &v1beta1.AuthorizationPolicy{}

	spec.Selector = &workloadv1beta1.WorkloadSelector{
		MatchLabels: map[string]string{"svc": svcLabel},
	}

	// generating rules, iterate through assertions, find the one match with desired format.
	var rules []*v1beta1.Rule
	for role, assertions := range athenzModel.Rules {
		for _, assert := range assertions {
			// assert.Resource contains the svc information that needs to parse and match
			svc, path, err := parseAssertionResource(zms.DomainName(m.NamespaceToDomain(namespace)), assert)
			if err != nil {
				continue
			}
			// if svc match with current svc, process it and add it to the rules
			// note that svc defined on athenz can be a regex, need to match the pattern
			res, e := regexp.MatchString(svc, svcLabel)
			if e != nil {
				log.Errorln("error matching string: ", e.Error())
			}
			if res {
				rule := &v1beta1.Rule{}

				// form rule.From, must initialize internal source here
				from_principal := &v1beta1.Rule_From{
					Source: &v1beta1.Source{},
				}
				from_requestPrincipal := &v1beta1.Rule_From{
					Source: &v1beta1.Source{},
				}
				// role name should match zms resource name
				for _, roleName := range athenzModel.Roles {
					if roleName == role {
						// add function to enableOriginJwtSubject, following code assume enableOriginJwtSubject is true by default
						if c.enableOriginJwtSubject {
							for _, roleMember := range athenzModel.Members[roleName] {
								spiffeName, err := memberToSpiffe(roleMember)
								if err != nil {
									log.Errorln("error converting role name to spiffeName: ", err.Error())
									continue
								}
								from_principal.Source.Principals = append(from_principal.Source.Principals, spiffeName)
								originJwtName, err := memberToOriginJwtSubject(roleMember)
								if err != nil {
									log.Errorln(err.Error())
									continue
								}
								from_requestPrincipal.Source.RequestPrincipals = append(from_requestPrincipal.Source.RequestPrincipals, originJwtName)
							}
						}
						//add role spiffee for role certificate
						roleSpiffeName, err := RoleToSpiffe(string(athenzModel.Name), string(roleName))
						if err != nil {
							log.Println("error when convert role to spiffe name: ", err.Error())
							continue
						}
						from_principal.Source.Principals = append(from_principal.Source.Principals, roleSpiffeName)
					}
				}
				rule.From = append(rule.From, from_principal)
				rule.From = append(rule.From, from_requestPrincipal)
				// form rules_to
				rule_to := &v1beta1.Rule{}
				_, err = parseAssertionEffect(assert)
				if err != nil {
					log.Debugf(err.Error())
					continue
				}
				method, err := parseAssertionAction(assert)
				if err != nil {
					log.Debugf(err.Error())
					continue
				}
				// form rule.To
				to := &v1beta1.Rule_To{
					Operation: &v1beta1.Operation{
						Methods: []string{method},
					},
				}
				if path != "" {
					to.Operation.Paths = []string{path}
				}
				rule_to.To = append(rule_to.To, to)
				rules = append(rules, rule_to)
				rules = append(rules, rule)
			}
		}
	}
	spec.Rules = rules
	out.Spec = spec
	return out
}

// parseAssertionResource parses the resource of an action into the service name (AccessRule constraint) and the
// HTTP paths if specified (suffix :<path>)
func parseAssertionResource(domainName zms.DomainName, assertion *zms.Assertion) (string, string, error) {

	if assertion == nil {
		return "", "", fmt.Errorf("assertion is nil")
	}
	var svc string
	var path string
	resource := assertion.Resource
	parts := resourceRegex.FindStringSubmatch(resource)
	names := resourceRegex.SubexpNames()
	results := map[string]string{}
	for i, part := range parts {
		results[names[i]] = part
	}

	for name, match := range results {
		switch name {
		case "domain":
			if match != string(domainName) {
				return "", "", fmt.Errorf("resource: %s does not belong to the Athenz domain: %s", resource, domainName)
			}
		case "svc":
			svc = match
		case "path":
			path = match
		}
	}

	if svc == "" {
		return "", "", fmt.Errorf("resource: %s does not specify the service using svc.<service-name> format", resource)
	}
	return svc, path, nil
}

// parseAssertionEffect parses the effect of an assertion into a supported Istio RBAC action
func parseAssertionEffect(assertion *zms.Assertion) (string, error) {
	if assertion == nil {
		return "", fmt.Errorf("assertion is nil")
	}
	effect := assertion.Effect
	if effect == nil {
		return "", fmt.Errorf("assertion effect is nil")
	}
	if strings.ToUpper(effect.String()) != zms.ALLOW.String() {
		return "", fmt.Errorf("effect: %s is not a supported assertion effect", effect)
	}
	return zms.ALLOW.String(), nil
}

// parseAssertionAction parses the action of an assertion into a supported Istio RBAC HTTP method
func parseAssertionAction(assertion *zms.Assertion) (string, error) {
	if assertion == nil {
		return "", fmt.Errorf("assertion is nil")
	}
	method := strings.ToUpper(assertion.Action)
	if !supportedMethods[method] {
		return "", fmt.Errorf("method: %s is not a supported HTTP method", assertion.Action)
	}
	return method, nil
}

// memberToOriginSubject parses the Athenz role member into the request.auth.principal
// jwt format. Example: athenz/example.domain.service
func memberToOriginJwtSubject(member *zms.RoleMember) (string, error) {
	if member == nil {
		return "", fmt.Errorf("member is nil")
	}

	memberStr := string(member.MemberName)

	// special condition: if member == 'user.*', return '*'
	if memberStr == allUsers {
		return WildCardAll, nil
	}

	requestAuthPrincipal := AthenzJwtPrefix + memberStr
	return requestAuthPrincipal, nil
}

// memberToSpiffe parses the Athenz role member into a SPIFFE compliant name.
// Example: example.domain/sa/service
func memberToSpiffe(member *zms.RoleMember) (string, error) {
	if member == nil {
		return "", fmt.Errorf("member is nil")
	}

	memberStr := string(member.MemberName)

	// special condition: if member == 'user.*', return '*'
	if memberStr == allUsers {
		return WildCardAll, nil
	}

	return PrincipalToSpiffe(memberStr)
}

func RoleToSpiffe(athenzDomainName string, roleName string) (string, error) {
	if len(athenzDomainName) == 0 {
		return "", fmt.Errorf("athenzDomainName is empty")
	}
	if len(roleName) == 0 {
		return "", fmt.Errorf("roleName is empty")
	}
	spiffeName := fmt.Sprintf("%s/ra/%s", athenzDomainName, roleName)
	return spiffeName, nil
}

// PrincipalToSpiffe converts the Athenz principal into a SPIFFE compliant format
// e.g. client-domain.frontend.some-app -> client-domain.frontend/sa/some-app
func PrincipalToSpiffe(principal string) (string, error) {
	if len(principal) == 0 {
		return "", fmt.Errorf("principal is empty")
	}
	i := strings.LastIndex(principal, ".")
	if i < 0 {
		return "", fmt.Errorf("principal:%s is not of the format <Athenz-domain>.<Athenz-service>", principal)
	}
	memberDomain, memberService := principal[:i], principal[i+1:]
	spiffeName := fmt.Sprintf("%s/sa/%s", memberDomain, memberService)
	return spiffeName, nil
}

func createDryrunResource(convertedCR model.Config, authzPolicyName string, namespace string) error {
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

func findDeleteDryrunResource(authzPolicyName string, namespace string) error {
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