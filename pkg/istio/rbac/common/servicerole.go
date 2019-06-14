// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package common

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	"k8s.io/api/core/v1"

	"github.com/yahoo/athenz/clients/go/zms"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
)

const (
	emptyPath        = "empty-path"
	ConstraintSvcKey = "destination.labels[svc]"
)

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

var resourceRegex = regexp.MustCompile(`\A(?P<domain>.*):svc.(?P<svc>[^:]*)[:]?(?P<path>.*)\z`)

type ServiceRoleMgr struct {
	store model.ConfigStoreCache
}

type ServiceRoleInfo struct {
	ServiceRole model.Config
	Processed   bool
}

// NewServiceRoleMgr initializes the ServiceRoleMgr object
func NewServiceRoleMgr(store model.ConfigStoreCache) *ServiceRoleMgr {
	return &ServiceRoleMgr{
		store: store,
	}
}

// GetServiceRoleMap creates a map of the form servicerolename-namespace:servicerole for quick lookup
func (srMgr *ServiceRoleMgr) GetServiceRoleMap() (map[string]*ServiceRoleInfo, error) {
	serviceRoleMap := make(map[string]*ServiceRoleInfo)

	serviceRoleList, err := srMgr.store.List(model.ServiceRole.Type, v1.NamespaceAll)
	if err != nil {
		return serviceRoleMap, err
	}

	for _, serviceRole := range serviceRoleList {
		serviceRoleInfo := &ServiceRoleInfo{
			ServiceRole: serviceRole,
		}
		serviceRoleMap[serviceRole.Name+"-"+serviceRole.Namespace] = serviceRoleInfo
	}
	return serviceRoleMap, nil
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

// GetServiceRoleSpec returns the ServiceRoleSpec for a given Athenz role and the associated assertions
func GetServiceRoleSpec(domainName zms.DomainName, roleName string, assertions []*zms.Assertion) (*v1alpha1.ServiceRole, error) {

	rules := make([]*v1alpha1.AccessRule, 0)
	for _, assertion := range assertions {
		assertionRole, err := ParseRoleFQDN(domainName, string(assertion.Role))
		if err != nil {
			log.Println(err.Error())
			continue
		}

		if assertionRole != roleName {
			log.Printf("Assertion: %v does not belong to the role: %s", assertion, roleName)
			continue
		}
		_, err = parseAssertionEffect(assertion)
		if err != nil {
			log.Println(err.Error())
			continue
		}

		method, err := parseAssertionAction(assertion)
		if err != nil {
			log.Println(err.Error())
			continue
		}

		svc, path, err := parseAssertionResource(domainName, assertion)
		if err != nil {
			log.Println(err.Error())
			continue
		}

		rule := &v1alpha1.AccessRule{
			Constraints: []*v1alpha1.AccessRule_Constraint{
				{
					Key:    ConstraintSvcKey,
					Values: []string{svc},
				},
			},
			Methods:  []string{method},
			Services: []string{WildCardAll},
		}
		if path != "" {
			rule.Paths = []string{path}
		}

		rules = append(rules, rule)
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules found for the ServiceRole: %s", roleName)
	}

	spec := &v1alpha1.ServiceRole{
		Rules: rules,
	}

	return spec, nil
}

// createServiceRole will construct the config meta and service role objects
func (srMgr *ServiceRoleMgr) createServiceRole(namespace, dnsSuffix, role string, policy *zms.Policy) (model.ConfigMeta, *v1alpha1.ServiceRole, error) {
	configMeta := model.ConfigMeta{
		Type:      model.ServiceRole.Type,
		Group:     model.ServiceRole.Group + model.IstioAPIGroupDomain,
		Version:   model.ServiceRole.Version,
		Namespace: namespace,
		Name:      role,
	}

	pathToMethods := make(map[string][]string)
	for _, assertion := range policy.Assertions {
		key := emptyPath
		// split role and path from assertion resource, ex: role:/details*
		path := strings.Split(assertion.Resource, ":")
		if len(path) >= 2 && path[1] != "" {
			key = path[1]
		}

		if methods, exists := pathToMethods[key]; !exists {
			pathToMethods[key] = []string{strings.ToUpper(assertion.Action)}
		} else {
			pathToMethods[key] = append(methods, strings.ToUpper(assertion.Action))
		}
	}

	// ex: sa.namespace.svc.cluster.local
	splitArray := strings.Split(role, ".")
	if len(splitArray) == 1 {
		return configMeta, nil, errors.New("Error splitting on . character")
	}

	sa := splitArray[len(splitArray)-1]
	if sa == "" {
		return configMeta, nil, errors.New("Could not get sa from role: " + role)
	}

	service := sa + "." + namespace + "." + dnsSuffix

	rules := make([]*v1alpha1.AccessRule, 0)
	for path, methods := range pathToMethods {
		var rule *v1alpha1.AccessRule
		if path == emptyPath {
			rule = &v1alpha1.AccessRule{Services: []string{service}, Methods: methods}
		} else {
			rule = &v1alpha1.AccessRule{Services: []string{service}, Methods: methods, Paths: []string{path}}
		}
		rules = append(rules, rule)
	}

	serviceRole := &v1alpha1.ServiceRole{
		Rules: rules,
	}

	return configMeta, serviceRole, nil
}

// CreateServiceRole is responsible for creating the service role object in the k8s cluster
func (srMgr *ServiceRoleMgr) CreateServiceRole(namespace, dnsSuffix, role string, policy *zms.Policy) error {
	configMeta, serviceRole, err := srMgr.createServiceRole(namespace, dnsSuffix, role, policy)
	if err != nil {
		return err
	}

	_, err = srMgr.store.Create(model.Config{
		ConfigMeta: configMeta,
		Spec:       serviceRole,
	})
	return err
}

// UpdateServiceRole is responsible for updating the service role object in the k8s cluster
func (srMgr *ServiceRoleMgr) UpdateServiceRole(serviceRole model.Config, dnsSuffix, role string, policy *zms.Policy) (bool, error) {
	currentServiceRole, ok := serviceRole.Spec.(*v1alpha1.ServiceRole)
	if !ok {
		return false, errors.New("Could not cast to ServiceRole")
	}

	configMeta, newServiceRole, err := srMgr.createServiceRole(serviceRole.Namespace, dnsSuffix, role, policy)
	if err != nil {
		return false, err
	}

	if !reflect.DeepEqual(currentServiceRole, newServiceRole) {
		configMeta.ResourceVersion = serviceRole.ResourceVersion
		_, err := srMgr.store.Update(model.Config{
			ConfigMeta: configMeta,
			Spec:       newServiceRole,
		})
		if err != nil {
			return false, err
		}
		return true, err
	}

	return false, nil
}

// DeleteServiceRole is responsible for deleting the service role object in the k8s cluster
func (srMgr *ServiceRoleMgr) DeleteServiceRole(name, namespace string) error {
	return srMgr.store.Delete(model.ServiceRole.Type, name, namespace)
}

func (srMgr *ServiceRoleMgr) EventHandler(config model.Config, e model.Event) {
	// TODO, add to workqueue
	log.Printf("Received %s event for servicerole: %+v", e.String(), config)
}
