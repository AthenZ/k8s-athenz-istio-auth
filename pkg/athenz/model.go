// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package athenz

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	v1 "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	"k8s.io/client-go/tools/cache"
)

var roleReplacer = strings.NewReplacer("*", ".*", "?", ".", "^", "\\^", "$", "\\$", ".", "\\.", "|", "\\|", "[", "\\[", "+", "\\+", "\\", "\\\\", "(", "\\(", ")", "\\)", "{", "\\{")

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
func getMembersForRole(domain *zms.DomainData, crCache *cache.SharedIndexInformer) RoleMembers {
	roleMembers := make(RoleMembers)

	if domain == nil || domain.Roles == nil {
		return roleMembers
	}

	roles := domain.Roles
	for _, role := range roles {
		// add role members of trust domain
		if role.Trust != "" {
			var err error
			role.RoleMembers, err = processTrustDomain(crCache, role.Trust, string(role.Name))
			if err != nil {
				log.Printf("Error occurred when processing trust domain. Error: %v", err)
				continue
			}
		}
		roleName := zms.ResourceName(role.Name)
		roleMembers[roleName] = role.RoleMembers
	}

	return roleMembers
}

// ConvertAthenzPoliciesIntoRbacModel transforms the given Athenz Domain structure into role-centric policies and members
func ConvertAthenzPoliciesIntoRbacModel(domain *zms.DomainData, crCache *cache.SharedIndexInformer) Model {
	var domainName zms.DomainName
	if domain != nil {
		domainName = domain.Name
	}
	return Model{
		Name:      domainName,
		Namespace: DomainToNamespace(string(domainName)),
		Roles:     getRolesForDomain(domain),
		Rules:     getRulesForDomain(domain),
		Members:   getMembersForRole(domain, crCache),
	}
}

func processTrustDomain(informer *cache.SharedIndexInformer, trust zms.DomainName, roleName string) ([]*zms.RoleMember, error) {
	var res []*zms.RoleMember
	// handle case which crIndexInformer is not initialized at the beginning, return directly.
	if (*informer) == nil {
		return res, nil
	}
	trustDomain := string(trust)
	// initialize a clientset to get information of this trust athenz domain
	// storage := c.crIndexInformer.GetStore()
	crContent, exists, _ := (*informer).GetStore().GetByKey(trustDomain)
	if !exists {
		return res, fmt.Errorf("Error when finding trustDomain %s for this role name %s in the cache: Domain cr is not found in the cache store", trustDomain, roleName)
	}
	// cast it to AthenzDomain object
	obj, ok := crContent.(*v1.AthenzDomain)
	if !ok {
		return res, fmt.Errorf("Error occurred when casting trust domain interface to athen domain object")
	}

	for _, policy := range obj.Spec.SignedDomain.Domain.Policies.Contents.Policies {
		if policy == nil || len(policy.Assertions) == 0 {
			log.Println("policy in Contents.Policies is nil")
			continue
		}
		for _, assertion := range policy.Assertions {
			// check if policy contains action "assume_role", and resource matches with delegated role name
			if assertion.Action == "assume_role" {
				// form correct role name
				matched, err := regexp.MatchString("^"+roleReplacer.Replace(assertion.Resource)+"$", roleName)
				if err != nil {
					log.Println("string matching failed with err: ", err)
					continue
				}
				if matched {
					delegatedRole := assertion.Role
					// check if above policy's corresponding role is delegated role or not
					for _, role := range obj.Spec.SignedDomain.Domain.Roles {
						if string(role.Name) == delegatedRole {
							if role.Trust != "" {
								// return empty array since athenz zms library does not recursively check delegated domain
								// it only checks one level above. Refer to: https://github.com/yahoo/athenz/blob/master/servers/zms/src/main/java/com/yahoo/athenz/zms/DBService.java#L1972
								return res, nil
							}
							for _, member := range role.RoleMembers {
								res = append(res, member)
							}
							return res, nil
						}
					}
				}
			}
		}
	}
	return res, nil
}
