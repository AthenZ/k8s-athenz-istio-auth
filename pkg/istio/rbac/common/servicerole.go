// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package common

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"

	"istio.io/api/rbac/v1alpha1"
)

const (
	ConstraintSvcKey = "destination.labels[svc]"
	srLogPrefix      = "[servicerole]"
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
			log.Printf("%s %s", srLogPrefix, err.Error())
			continue
		}

		if assertionRole != roleName {
			log.Printf("%s Assertion: %v does not belong to the role: %s", srLogPrefix, assertion, roleName)
			continue
		}
		_, err = parseAssertionEffect(assertion)
		if err != nil {
			log.Printf("%s %s", srLogPrefix, err.Error())
			continue
		}

		method, err := parseAssertionAction(assertion)
		if err != nil {
			log.Printf("%s %s", srLogPrefix, err.Error())
			continue
		}

		svc, path, err := parseAssertionResource(domainName, assertion)
		if err != nil {
			log.Printf("%s %s", srLogPrefix, err.Error())
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
