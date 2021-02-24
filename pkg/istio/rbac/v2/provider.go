// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package v2

import (
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	"istio.io/api/security/v1beta1"
	workloadv1beta1 "istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/collections"
	"regexp"
)

// implements github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/Provider interface
type v2 struct {
	dryRun                 bool
	enableOriginJwtSubject bool
}

func NewProvider(dryRun, enableOriginJwtSubject bool) rbac.Provider {
	return &v2{
		dryRun:                 dryRun,
		enableOriginJwtSubject: enableOriginJwtSubject,
	}
}

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

	// generating rules, iterate through assertions, find the one match with desired format.
	var rules []*v1beta1.Rule
	for role, assertions := range athenzModel.Rules {
		rule := &v1beta1.Rule{}
		for _, assert := range assertions {
			// form rule_to array by appending matching assertions.
			// assert.Resource contains the svc information that needs to parse and match
			svc, path, err := common.ParseAssertionResource(athenzModel.Name, assert)
			if err != nil {
				continue
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
		// role name should match zms resource name
		for _, roleMember := range athenzModel.Members[role] {
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
				log.Errorln("error converting role member to spiffeName: ", err.Error())
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
		//add role spiffe for role certificate
		roleSpiffeName, err := common.RoleToSpiffe(string(athenzModel.Name), string(role))
		if err != nil {
			log.Errorln("error when convert role to spiffe name: ", err.Error())
			continue
		}
		from_principal.Source.Principals = append(from_principal.Source.Principals, roleSpiffeName)
		rule.From = append(rule.From, from_principal)
		rule.From = append(rule.From, from_requestPrincipal)
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
	if p.dryRun {
		if serviceName != "" {
			config, err := common.ReadConvertToModelConfig(serviceName, namespace, common.DryRunStoredFilesDirectory)
			if err != nil {
				log.Errorf("unable to convert local yaml file into model config object, error: %s", err)
				return []model.Config{}
			}
			return []model.Config{*config}
		}
		var modelList []model.Config
		serviceList := common.FetchServicesFromDir(namespace, common.DryRunStoredFilesDirectory)
		for _, svc := range serviceList {
			config, err := common.ReadConvertToModelConfig(svc, namespace, common.DryRunStoredFilesDirectory)
			if err != nil {
				log.Errorf("unable to convert local yaml file into model config object, error: %s", err)
				continue
			}
			modelList = append(modelList, *config)
		}
		return modelList
	}

	if serviceName == "" {
		apList, err := csc.List(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), namespace)
		if err != nil {
			log.Errorf("Error listing the Authorization Policy resources in the namespace: %s", namespace)
		}
		return apList
	}
	ap := csc.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), serviceName, namespace)
	if ap != nil {
		log.Infof("authorization policy does not exist in the cache, name: %s, namespace: %s", serviceName, namespace)
		return []model.Config{*ap}
	}
	return []model.Config{}
}
