// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package authzpolicy

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	m "github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	adv1 "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	"istio.io/api/security/v1beta1"
	workloadv1beta1 "istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/schemas"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const (
	allUsers                     = "user.*"
	WildCardAll                  = "*"
	ServiceRoleKind              = "ServiceRole"
	AthenzJwtPrefix              = "athenz/"
	RequestAuthPrincipalProperty = "request.auth.principal"
)

const (
	queueNumRetries        = 3
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
	configStoreCache     model.ConfigStoreCache
	serviceIndexInformer cache.SharedIndexInformer
	adIndexInformer      cache.SharedIndexInformer
	queue                workqueue.RateLimitingInterface
}

type OnCompleteFunc func(err error, item *Item) error

type Item struct {
	Operation model.Event
	Resource  model.Config

	// Handler function that should be invoked with the status of the current sync operation on the item
	// If the handler returns an error, the operation is retried up to `queueNumRetries`
	CallbackHandler OnCompleteFunc
}

func NewController(configStoreCache model.ConfigStoreCache, serviceIndexInformer cache.SharedIndexInformer, adIndexInformer cache.SharedIndexInformer) *Controller {
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	c := &Controller{
		configStoreCache:     configStoreCache,
		serviceIndexInformer: serviceIndexInformer,
		adIndexInformer:      adIndexInformer,
		queue:                queue,
	}

	serviceIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.ProcessConfigChange(obj)
		},
		// UpdateFunc: func(oldObj, newObj interface{}) {

		// },
		// DeleteFunc: func(obj interface{}) {

		// },
	})

	return c
}

// ProcessConfigChange is responsible for adding the key of the item to the queue
func (c *Controller) ProcessConfigChange(obj interface{}) {
	c.queue.Add(obj)
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
	obj, ok := item.(*corev1.Service)
	if !ok {
		return fmt.Errorf("Unable to cast interface to service object")
	}

	// authz policy creation logic
	// check if current service has istio authz annotation set
	if _, ok = obj.Annotations[authzEnabledAnnotation]; ok {
		fmt.Println("find the istio authz annotation in service: ", obj.Name)
		if obj.Annotations[authzEnabledAnnotation] == authzEnabled {
			fmt.Println("istio authz annotation is set to true")
			// form the authorization policy config and send create sign to the queue
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
			convertedCR := c.convertAthenzModelIntoIstioAuthzPolicy(domainRBAC, obj.Namespace, obj.Name, labels["svc"])
			revision, err := c.configStoreCache.Create(convertedCR)
			if err != nil {
				fmt.Println(err.Error())
			} else {
				fmt.Println("revision is: ", revision)
			}

		}
	}
	return nil
}

// checkAuthzEnabledAnnotation checks if current servce object has "authz.istio.io/enabled" annotation set
func (c *Controller) checkAuthzEnabledAnnotation(serviceObj *corev1.Service) bool {
	if _, ok := serviceObj.Annotations[authzEnabledAnnotation]; ok {
		return true
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
	schema := schemas.AuthorizationPolicy
	out.ConfigMeta = model.ConfigMeta{
		Type:      schema.Type,
		Group:     schema.Group + constants.IstioAPIGroupDomain,
		Version:   schema.Version,
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
			if svc == serviceName {
				rule := &v1beta1.Rule{}
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
				to := &v1beta1.Rule_To{}
				operation := &v1beta1.Operation{
					Methods: []string{method},
				}
				to.Operation = operation
				if path != "" {
					to.Operation.Paths = []string{path}
				}
				rule.To = append(rule.To, to)
				// form rule.From, must initialize internal source here
				from := &v1beta1.Rule_From{
					Source: &v1beta1.Source{},
				}
				// role name should match zms resource name
				for _, roleName := range athenzModel.Roles {
					if roleName == role {
						// TODO: condition if user is *, rule.From should be entirely empty
						// add function to enableOriginJwtSubject, following code turned this one by default
						for _, roleMember := range athenzModel.Members[roleName] {
							spiffeName, err := PrincipalToSpiffe(string(roleMember.MemberName))
							if err != nil {
								fmt.Println("error converting role name to spiffeName: ", err.Error())
								continue
							}
							from.Source.Principals = append(from.Source.Principals, spiffeName)
							originJwtName, err := memberToOriginJwtSubject(roleMember)
							if err != nil {
								fmt.Println(err.Error())
								continue
							}
							from.Source.RequestPrincipals = append(from.Source.RequestPrincipals, originJwtName)
						}
						//add role spiffee for role certificate
						roleSpiffeName, err := RoleToSpiffe(string(athenzModel.Name), string(roleName))
						if err != nil {
							fmt.Println("error when convert role to spiffe name: ", err.Error())
							continue
						}
						from.Source.Principals = append(from.Source.Principals, roleSpiffeName)
					}
				}
				rule.From = append(rule.From, from)
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
