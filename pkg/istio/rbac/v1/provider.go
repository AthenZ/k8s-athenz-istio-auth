// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package v1

import (
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	"istio.io/api/security/v1beta1"
	workloadv1beta1 "istio.io/api/type/v1beta1"
	"istio.io/istio/pkg/config/schema/collections"
	"regexp"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/validation"
)

// implements github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/Provider interface
type v1 struct {
	enableOriginJwtSubject bool
}

func NewProvider(enableOriginJwtSubject bool) rbac.Provider {
	return &v1{
		enableOriginJwtSubject: enableOriginJwtSubject,
	}
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
			log.Debugf("Policies/assertions not defined for role %s", roleFQDN)
			continue
		}

		// Extract only the role name from the <domain>:role.<roleName> format
		roleName, err := common.ParseRoleFQDN(m.Name, string(roleFQDN))
		if err != nil {
			log.Debugln(err.Error())
			continue
		}

		// Transform the assertions for an Athenz Role into a ServiceRole spec
		srSpec, err := common.GetServiceRoleSpec(m.Name, roleName, assertions)
		if err != nil {
			log.Debugf("Error converting the assertions for role: %s to a ServiceRole: %s", roleName, err.Error())
			continue
		}

		// Validate the ServiceRole spec
		err = validation.ValidateServiceRole(roleName, m.Namespace, srSpec)
		if err != nil {
			log.Warningf("Error validating the converted ServiceRole spec: %s for role: %s", err.Error(), roleName)
			continue
		}

		k8sRoleName := common.ConvertAthenzRoleNameToK8sName(roleName)
		sr := common.NewConfig(collections.IstioRbacV1Alpha1Serviceroles, m.Namespace, k8sRoleName, srSpec)
		out = append(out, sr)

		// Transform the members for an Athenz Role into a ServiceRoleBinding spec
		roleMembers, exists := m.Members[roleFQDN]
		if !exists {
			log.Debugf("Cannot find members for the role: %s while creating a ServiceRoleBinding", roleName)
			continue
		}

		srbSpec, err := common.GetServiceRoleBindingSpec(string(m.Name), roleName, k8sRoleName, roleMembers, p.enableOriginJwtSubject)
		if err != nil {
			log.Debugf("Error converting the members for role: %s to a ServiceRoleBinding: %s", roleName, err.Error())
			continue
		}

		// Validate the ServiceRoleBinding spec
		err = validation.ValidateServiceRoleBinding(roleName, m.Namespace, srbSpec)
		if err != nil {
			log.Warningf("Error validating the converted ServiceRoleBinding spec: %s for role: %s", err.Error(), roleName)
			continue
		}

		srb := common.NewConfig(collections.IstioRbacV1Alpha1Servicerolebindings, m.Namespace, k8sRoleName, srbSpec)
		out = append(out, srb)
	}

	return out
}

// GetCurrentIstioRbac returns the ServiceRole and ServiceRoleBinding resources for the specified model's namespace
func (p *v1) GetCurrentIstioRbac(m athenz.Model, csc model.ConfigStoreCache) []model.Config {

	sr, err := csc.List(collections.IstioRbacV1Alpha1Serviceroles.Resource().GroupVersionKind(), m.Namespace)
	if err != nil {
		log.Errorf("Error listing the ServiceRole resources in the namespace: %s", m.Namespace)
	}

	srb, err := csc.List(collections.IstioRbacV1Alpha1Servicerolebindings.Resource().GroupVersionKind(), m.Namespace)
	if err != nil {
		log.Errorf("Error listing the ServiceRoleBinding resources in the namespace: %s", m.Namespace)
	}

	return append(sr, srb...)
}

// ConvertAthenzModelIntoIstioAuthzPolicy converts the Athenz RBAC model into Istio Authorization V1Beta1 specific
// RBAC custom resource (AuthorizationPolicy)
func (p *v1) ConvertAthenzModelIntoIstioAuthzPolicy(athenzModel athenz.Model, namespace string, serviceName string, svcLabel string) model.Config {
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
			svc, path, err := common.ParseAssertionResource(zms.DomainName(athenz.NamespaceToDomain(namespace)), assert)
			if err != nil {
				continue
			}
			// if svc match with current svc, process it and add it to the rules
			// note that svc defined on athenz can be a regex, need to match the pattern
			res, e := regexp.MatchString(svc, svcLabel)
			if e != nil {
				log.Errorln("error matching string: ", e.Error())
				continue
			}
			if !res{
				log.Errorf("athenz svc %s does not match with current svc %s", svc, svcLabel)
				continue
			}
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
					for _, roleMember := range athenzModel.Members[roleName] {
						res, err := common.CheckAthenzMemberExpiry(roleMember)
						if err != nil {
							log.Errorf("error when checking athenz member expiration date, skipping current member: %s, error: %s", roleMember.MemberName, err)
							continue
						}
						if !res {
							log.Infoln("member expired, skip adding member to authz policy resource, member: ", roleMember.MemberName)
							continue
						}
						res, err = common.CheckAthenzSystemDisabled(roleMember)
						if err != nil {
							log.Errorf("error when checking athenz member system disabled, skipping current member: %s, error: %s", roleMember.MemberName, err)
							continue
						}
						if !res {
							log.Infoln("member expired, skip adding member to authz policy resource, member: ", roleMember.MemberName)
							continue
						}

						spiffeName, err := common.MemberToSpiffe(roleMember)
						if err != nil {
							log.Errorln("error converting role name to spiffeName: ", err.Error())
							continue
						}
						from_principal.Source.Principals = append(from_principal.Source.Principals, spiffeName)
						if p.enableOriginJwtSubject {
							originJwtName, err := common.MemberToOriginJwtSubject(roleMember)
							if err != nil {
								log.Errorln(err.Error())
								continue
							}
							from_requestPrincipal.Source.RequestPrincipals = append(from_requestPrincipal.Source.RequestPrincipals, originJwtName)
						}
					}
					//add role spiffee for role certificate
					roleSpiffeName, err := common.RoleToSpiffe(string(athenzModel.Name), string(roleName))
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
			_, err = common.ParseAssertionEffect(assert)
			if err != nil {
				log.Debugf(err.Error())
				continue
			}
			method, err := common.ParseAssertionAction(assert)
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
	spec.Rules = rules
	out.Spec = spec
	return out
}

// GetCurrentIstioRbac returns the authorization policies resources for the specified model's namespace
func (p *v1) GetCurrentIstioAuthzPolicy(m athenz.Model, csc model.ConfigStoreCache) []model.Config {

	ap, err := csc.List(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), m.Namespace)
	if err != nil {
		log.Errorf("Error listing the ServiceRole resources in the namespace: %s", m.Namespace)
	}

	return ap
}
