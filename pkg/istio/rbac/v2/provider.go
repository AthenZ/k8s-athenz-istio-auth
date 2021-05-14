// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package v2

import (
	"regexp"
	"sort"
	"strings"

	"github.com/yahoo/athenz/clients/go/zms"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	"istio.io/api/security/v1beta1"
	workloadv1beta1 "istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/collections"
)

// implements github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/Provider interface
type v2 struct {
	componentEnabledAuthzPolicy *common.ComponentEnabled
	enableOriginJwtSubject      bool
}

func NewProvider(componentEnabledAuthzPolicy *common.ComponentEnabled, enableOriginJwtSubject bool) rbac.Provider {
	return &v2{
		componentEnabledAuthzPolicy: componentEnabledAuthzPolicy,
		enableOriginJwtSubject:      enableOriginJwtSubject,
	}
}

// Regex for finding if the HTTP path contains a query parameter
var queryRegex = regexp.MustCompile(`.*\?.*`)

// ConvertAthenzModelIntoIstioRbac converts the Athenz RBAC model into Istio Authorization V1Beta1 specific
// RBAC custom resource (AuthorizationPolicy)
func (p *v2) ConvertAthenzModelIntoIstioRbac(athenzModel athenz.Model, serviceName string, svcLabel string) []model.Config {
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
		Namespace: athenzModel.Namespace,
		Name:      serviceName,
	}

	// matching label, same with the service label
	spec := &v1beta1.AuthorizationPolicy{}

	spec.Selector = &workloadv1beta1.WorkloadSelector{
		MatchLabels: map[string]string{"svc": svcLabel},
	}

	// sort athenzModel.Rules map based on alphabetical order of key's name (role's name)
	// this is to make sure generated authz policy's rule is in ordered, which will help in spec equality check
	// after v1 provider is deprecated, can update athenzModel.Rules field to list instead of map to improve performance
	roleList := make([]string, 0, len(athenzModel.Rules))
	for role, _ := range athenzModel.Rules {
		roleList = append(roleList, string(role))
	}
	sort.Strings(roleList)

	// generating rules, iterate through assertions, find the one match with desired format.
	var rules []*v1beta1.Rule
	for _, roleKey := range roleList {
		role := zms.ResourceName(roleKey)
		assertions := athenzModel.Rules[role]
		rule := &v1beta1.Rule{}
		for _, assert := range assertions {
			// form rule_to array by appending matching assertions.
			// assert.Resource contains the svc information that needs to parse and match
			svc, path, err := common.ParseAssertionResource(athenzModel.Name, assert)
			if err != nil {
				continue
			}

			if svc == "*" {
				svc = ".*"
			}

			// Drop the query parameters from the HTTP path in the assertions due to the difference
			// in the RBAC Envoy permissions config created by Authorization Policy and ServiceRole/ServiceRoleBindings.
			// Which in case of,
			// Authorization Policy - is created with a url_path object
			// ServiceRole/ServiceRoleBindings - is created with a header object
			if queryRegex.MatchString(path) {
				pathArr := strings.Split(path, "?")
				path = pathArr[0]
			}

			// if svc match with current svc, process it and add it to the rules
			// note that svc defined on athenz can be a regex, need to match the pattern
			res, err := regexp.MatchString(svc, svcLabel)
			if err != nil {
				log.Errorln("error matching string: ", err.Error())
				continue
			}
			if !res {
				log.Debugf("athenz svc %s does not match with current svc %s", svc, svcLabel)
				continue
			}
			// form rules_to
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
			rule.To = append(rule.To, to)
		}

		// group by role, for each role, form rule_from from role members,
		// skip if rule.To is nil, indicating no assertion match with service
		if rule.To == nil {
			continue
		}
		from_principal := &v1beta1.Rule_From{
			Source: &v1beta1.Source{},
		}
		from_requestPrincipal := &v1beta1.Rule_From{
			Source: &v1beta1.Source{},
		}
		from_namespace := &v1beta1.Rule_From{
			Source: &v1beta1.Source{},
		}

		// role name should match zms resource name
		for _, roleMember := range athenzModel.Members[role] {
			var members []interface{}
			roleflag := false

			// Check to see in the roleMember is a group in Athenz
			// - If is a group add all the members of the group to the
			// member array.
			// - If not add only the original roleMember
			if _, ok := athenzModel.GroupMembers[roleMember.MemberName]; ok {
				for _, groupMember := range athenzModel.GroupMembers[roleMember.MemberName] {
					members = append(members, groupMember)
				}
			} else {
				members = append(members, roleMember)
				roleflag = true
			}

			// In both the cases - Role and Groups Members first check the
			// if the role has not yet expired or the role is not system disabled
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

			for _, member := range members {
				// This is only done for Group Members to check the expiry and system disabled
				// at a Group Member level after doing a check for the entire role
				if !roleflag {
					res, err := common.CheckAthenzMemberExpiry(member)
					if err != nil {
						log.Errorf("error when checking athenz member expiration date, skipping current member: %s, error: %s", common.GetMemberName(member), err)
						continue
					}
					if !res {
						log.Infoln("member expired, skip adding member to authz policy resource, member: ", common.GetMemberName(member))
						continue
					}

					res, err = common.CheckAthenzSystemDisabled(member)
					if err != nil {
						log.Errorf("error when checking athenz member system disabled, skipping current member: %s, error: %s", common.GetMemberName(member), err)
						continue
					}
					if !res {
						log.Infoln("member expired, skip adding member to authz policy resource, member: ", common.GetMemberName(member))
						continue
					}
				}

				namespace, err := common.CheckIfMemberIsAllUsersFromDomain(member, athenzModel.Name)
				if err != nil {
					log.Errorln("error checking if role member is all users in an Athenz domain: ", err.Error())
					continue
				}
				if namespace != "" {
					from_namespace.Source.Namespaces = append(from_namespace.Source.Namespaces, namespace)
					continue
				}

				spiffeName, err := common.MemberToSpiffe(member)
				if err != nil {
					log.Errorln("error converting role member to spiffeName: ", err.Error())
					continue
				}

				from_principal.Source.Principals = append(from_principal.Source.Principals, spiffeName)
				if p.enableOriginJwtSubject {
					originJwtName, err := common.MemberToOriginJwtSubject(member)
					if err != nil {
						log.Errorln(err.Error())
						continue
					}
					from_requestPrincipal.Source.RequestPrincipals = append(from_requestPrincipal.Source.RequestPrincipals, originJwtName)
				}
			}
		}
		//add role spiffe for role certificate
		roleSpiffeName, err := common.RoleToSpiffe(string(athenzModel.Name), string(role))
		if err != nil {
			log.Errorln("error when convert role to spiffe name: ", err.Error())
			continue
		}
		from_principal.Source.Principals = append(from_principal.Source.Principals, roleSpiffeName)
		rule.From = append(rule.From, from_principal)
		if len(from_namespace.Source.Namespaces) > 0 {
			rule.From = append(rule.From, from_namespace)
		}
		if p.enableOriginJwtSubject && len(from_requestPrincipal.Source.RequestPrincipals) > 0 {
			rule.From = append(rule.From, from_requestPrincipal)
		}
		rules = append(rules, rule)
	}
	spec.Rules = rules
	out.Spec = spec
	return []model.Config{out}
}

// GetCurrentIstioRbac returns the authorization policies resources for the specified model's namespace
// if serviceName is "", return the all the authorization policies in the given namespace,
// if serviceName is specific, return single authorization policy matching with serviceName.
func (p *v2) GetCurrentIstioRbac(m athenz.Model, csc model.ConfigStoreCache, serviceName string) []model.Config {
	namespace := m.Namespace
	// case when there is athenz domain sync
	if serviceName == "" {
		apList, err := csc.List(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), namespace)
		if err != nil {
			log.Errorf("Error listing the Authorization Policy resources in the namespace: %s", namespace)
		}
		// if namespace is enabled, meaning all services in the namespace are authz enabled, return the list directly
		if p.componentEnabledAuthzPolicy.IsEnabled(serviceName, namespace) {
			return apList
		}
		configList, err := common.ReadDirectoryConvertToModelConfig(namespace, common.DryRunStoredFilesDirectory)
		apList = append(apList, configList...)
		return apList
	}

	// case when there is single service sync
	if !p.componentEnabledAuthzPolicy.IsEnabled(serviceName, namespace) {
		config, err := common.ReadConvertToModelConfig(serviceName, namespace, common.DryRunStoredFilesDirectory)
		if err != nil {
			log.Errorf("unable to convert local yaml file into model config object, error: %s", err)
			return []model.Config{}
		}
		return []model.Config{*config}
	}
	ap := csc.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), serviceName, namespace)
	if ap != nil {
		return []model.Config{*ap}
	}
	log.Infof("authorization policy does not exist in the cache, name: %s, namespace: %s", serviceName, namespace)
	return []model.Config{}
}
