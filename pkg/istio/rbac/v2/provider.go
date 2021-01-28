package v2

import (
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	m "github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/common"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	"istio.io/api/security/v1beta1"
	workloadv1beta1 "istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/collections"
	"regexp"
)

// implements github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/Provider interface
type v2 struct {enableOriginJwtSubject bool}

func NewProvider(enableOriginJwtSubject bool) rbac.ProviderV2 {
	return &v2{
		enableOriginJwtSubject: enableOriginJwtSubject,
	}
}

func (p *v2) ConvertAthenzModelIntoIstioAuthzPolicy(athenzModel athenz.Model, namespace string, serviceName string, svcLabel string) model.Config {
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
			svc, path, err := common.ParseAssertionResource(zms.DomainName(m.NamespaceToDomain(namespace)), assert)
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
			if res {
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
	}
	spec.Rules = rules
	out.Spec = spec
	return out
}