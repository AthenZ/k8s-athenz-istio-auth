// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package athenz

import (
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/util"
)

// Athenz data structures the way we would want
// list of Athenz Role names for an Athenz domain
type Roles []zms.ResourceName

// map of Athenz Role:Assertions for an Athenz Resource
type RoleAssertions map[zms.ResourceName][]*zms.Assertion

// map of Role:Members for an Athenz domain
type RoleMembers map[zms.ResourceName][]*zms.RoleMember

// RBAC object to hold the policies for an Athenz domain
type Model struct {
	Name      zms.DomainName `json:"name"`
	Namespace string         `json:"namespace"`
	Roles     Roles          `json:"roles,omitempty"`
	Rules     RoleAssertions `json:"rules,omitempty"`
	Members   RoleMembers    `json:"members,omitempty"`
}

// getRolesForDomain returns the role names list in the same order as defined on the Athenz domain
func getRolesForDomain(domain *zms.DomainData) Roles {
	roles := make(Roles, 0)

	if domain == nil || domain.Roles == nil {
		return roles
	}

	rolesObj := domain.Roles
	for _, role := range rolesObj {
		roleName := zms.ResourceName(role.Name)
		roles = append(roles, roleName)
	}

	return roles
}

// getRulesForDomain returns the assertions grouped by role for services(resources) in an Athenz domain
func getRulesForDomain(domain *zms.DomainData) RoleAssertions {
	rules := make(RoleAssertions)

	if domain == nil || domain.Policies == nil || domain.Policies.Contents == nil {
		return rules
	}
	policies := domain.Policies.Contents.Policies

	// Loop through all the policies and the assertions and organize the assertions by role
	// the order of assertions within each role follow the order as they appear
	for _, policy := range policies {

		for _, assertion := range policy.Assertions {

			roleName := zms.ResourceName(assertion.Role)

			// fetch the list of assertions for the role if exists, or create one
			assertionsForRole, exists := rules[roleName]
			if !exists {
				assertionsForRole = []*zms.Assertion{}
				rules[roleName] = assertionsForRole
			}

			rules[roleName] = append(assertionsForRole, assertion)
		}
	}

	return rules
}

// getMembersForRole returns the members for each role in an Athenz domain
func getMembersForRole(domain *zms.DomainData) RoleMembers {
	roleMembers := make(RoleMembers)

	if domain == nil || domain.Roles == nil {
		return roleMembers
	}

	roles := domain.Roles
	for _, role := range roles {
		roleName := zms.ResourceName(role.Name)
		roleMembers[roleName] = role.RoleMembers
	}

	return roleMembers
}

// ConvertAthenzPoliciesIntoRbacModel transforms the given Athenz Domain structure into role-centric policies and members
func ConvertAthenzPoliciesIntoRbacModel(domain *zms.DomainData) Model {
	var domainName zms.DomainName
	if domain != nil {
		domainName = domain.Name
	}
	return Model{
		Name:      domainName,
		Namespace: util.DomainToNamespace(string(domainName)),
		Roles:     getRolesForDomain(domain),
		Rules:     getRulesForDomain(domain),
		Members:   getMembersForRole(domain),
	}
}
