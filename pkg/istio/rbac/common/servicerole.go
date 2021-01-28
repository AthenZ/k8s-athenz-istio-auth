// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package common

import (
	"fmt"
	"strings"

	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/common"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"

	"istio.io/api/rbac/v1alpha1"
)

const ConstraintSvcKey = "destination.labels[svc]"

// ConvertAthenzRoleNameToK8sName replaces the '_' in the Athenz role name to a '--' as Kubernetes resource name
// needs to follow a DNS-1123 subdomain format which must consist of lower case alphanumeric characters, '-' or '.',
// and must start and end with an alphanumeric character
func ConvertAthenzRoleNameToK8sName(roleName string) string {
	return strings.ReplaceAll(roleName, "_", "--")
}

// GetServiceRoleSpec returns the ServiceRoleSpec for a given Athenz role and the associated assertions
func GetServiceRoleSpec(domainName zms.DomainName, roleName string, assertions []*zms.Assertion) (*v1alpha1.ServiceRole, error) {

	rules := make([]*v1alpha1.AccessRule, 0)
	for _, assertion := range assertions {
		assertionRole, err := ParseRoleFQDN(domainName, string(assertion.Role))
		if err != nil {
			log.Debug(err.Error())
			continue
		}

		if assertionRole != roleName {
			log.Debugf("Assertion: %v does not belong to the role: %s", assertion, roleName)
			continue
		}

		svc, path, err := common.ParseAssertionResource(domainName, assertion)
		if err != nil {
			log.Debugf(err.Error())
			continue
		}

		_, err = common.ParseAssertionEffect(assertion)
		if err != nil {
			log.Debugf(err.Error())
			continue
		}

		method, err := common.ParseAssertionAction(assertion)
		if err != nil {
			log.Debugf(err.Error())
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
