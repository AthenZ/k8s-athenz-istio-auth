// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package v1

import (
	"log"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"

	"istio.io/istio/pilot/pkg/model"
)

type v1 struct {
	// implements github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/Provider interface
}

func NewProvider() rbac.Provider {
	return &v1{}
}

// ConvertAthenzModelIntoIstioRbac converts the Athenz RBAC model into the list of Istio Authorization V1 specific
// RBAC custom resources (ServiceRoles, ServiceRoleBindings)
// The idea is that with a given input model, the function should always return the same output list of resources
func (p *v1) ConvertAthenzModelIntoIstioRbac(m athenz.Model) []model.Config {

	out := make([]model.Config, 0)

	// Process all the roles in the same order as defined in the Athenz domain
	for _, roleFQDN := range m.Roles {

		// Check if there are any policies/assertions defined for this role
		assertions, exists := m.Rules[roleFQDN]
		if !exists {
			continue
		}

		// Extract only the role name from the <domain>:role.<roleName> format
		roleName, err := common.ParseRoleFQDN(m.Name, string(roleFQDN))
		if err != nil {
			log.Println(err.Error())
			continue
		}

		// Transform the assertions for an Athenz Role into a ServiceRole spec
		srSpec, err := common.GetServiceRoleSpec(m.Name, roleName, assertions)
		if err != nil {
			log.Printf("error converting the assertions for role:%s to a ServiceRole: %s", roleName, err.Error())
			continue
		}

		// Validate the ServiceRole spec
		err = model.ValidateServiceRole(roleName, m.Namespace, srSpec)
		if err != nil {
			log.Printf("error validating the converted ServiceRole spec: %s for role: %s", err.Error(), roleName)
			continue
		}

		sr := common.NewConfig(model.ServiceRole.Type, m.Namespace, roleName, srSpec)
		out = append(out, sr)

		// Transform the members for an Athenz Role into a ServiceRoleBinding spec
		roleMembers, exists := m.Members[roleFQDN]
		if !exists {
			log.Printf("cannot find members for the role:%s while creating a ServiceRoleBinding", roleName)
			continue
		}

		srbSpec, err := common.GetServiceRoleBindingSpec(roleName, roleMembers)
		if err != nil {
			log.Printf("error converting the members for role:%s to a ServiceRoleBinding: %s", roleName, err.Error())
			continue
		}

		// Validate the ServiceRoleBinding spec
		err = model.ValidateServiceRoleBinding(roleName, m.Namespace, srbSpec)
		if err != nil {
			log.Printf("error validating the converted ServiceRoleBinding spec: %s for role: %s", err.Error(), roleName)
			continue
		}

		srb := common.NewConfig(model.ServiceRoleBinding.Type, m.Namespace, roleName, srbSpec)
		out = append(out, srb)
	}

	return out
}
