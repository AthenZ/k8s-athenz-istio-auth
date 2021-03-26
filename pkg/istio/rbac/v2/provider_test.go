// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package v2

import (
	"sort"
	"testing"
	"time"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	fakev1 "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned/fake"
	adInformer "github.com/yahoo/k8s-athenz-syncer/pkg/client/informers/externalversions/athenz/v1"
	"istio.io/api/security/v1beta1"
	workloadv1beta1 "istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/collections"
	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	domainName       = "test.namespace"
	username         = "user.name"
	wildcardUsername = "user.*"
)

var (
	onboardedService = &k8sv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "onboarded-service",
			Namespace: "test-namespace",
			Annotations: map[string]string{
				"authz.istio.io/enabled": "true",
			},
			Labels: map[string]string{
				"app": "productpage",
			},
		},
	}

	undefinedAthenzRulesServiceWithAnnotationTrue = &k8sv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "onboarded-service",
			Namespace: "test-namespace",
			Annotations: map[string]string{
				"authz.istio.io/enabled": "true",
			},
			Labels: map[string]string{
				"app": "productpage",
			},
		},
	}
)

func TestConvertAthenzModelIntoIstioRbac(t *testing.T) {
	tests := []struct {
		name                string
		inputAthenzDomain   zms.SignedDomain
		inputService        *k8sv1.Service
		expectedAuthzPolicy []model.Config
	}{
		{
			name:                "should create empty authz policy spec for service which doesn't have roles and policies defined",
			inputAthenzDomain:   getFakeNotOnboardedDomain(false, false, false, false),
			inputService:        undefinedAthenzRulesServiceWithAnnotationTrue,
			expectedAuthzPolicy: getExpectedEmptyAuthzPolicy(),
		},
		{
			name:                "should create empty authz policy spec for service with empty role and no policies defined",
			inputAthenzDomain:   getFakeNotOnboardedDomain(true, false, false, false),
			inputService:        undefinedAthenzRulesServiceWithAnnotationTrue,
			expectedAuthzPolicy: getExpectedEmptyAuthzPolicy(),
		},
		{
			name:                "should create empty authz policy spec for service with one member in role and no policies defined",
			inputAthenzDomain:   getFakeNotOnboardedDomain(true, true, false, false),
			inputService:        undefinedAthenzRulesServiceWithAnnotationTrue,
			expectedAuthzPolicy: getExpectedEmptyAuthzPolicy(),
		},
		{
			name:                "should create empty authz policy spec for service with no role and empty policy defined",
			inputAthenzDomain:   getFakeNotOnboardedDomain(false, false, true, false),
			inputService:        undefinedAthenzRulesServiceWithAnnotationTrue,
			expectedAuthzPolicy: getExpectedEmptyAuthzPolicy(),
		},
		{
			name:                "should create empty authz policy spec for service with empty role and empty policy defined",
			inputAthenzDomain:   getFakeNotOnboardedDomain(true, false, true, false),
			inputService:        undefinedAthenzRulesServiceWithAnnotationTrue,
			expectedAuthzPolicy: getExpectedEmptyAuthzPolicy(),
		},
		{
			name:                "should create authz policy spec with role for service with no role and policy defined",
			inputAthenzDomain:   getFakeNotOnboardedDomain(false, false, true, true),
			inputService:        undefinedAthenzRulesServiceWithAnnotationTrue,
			expectedAuthzPolicy: getExpectedAuthzPolicyWithRole(),
		},
		{
			name:                "should create authz policy spec with role for service with empty role and policy defined",
			inputAthenzDomain:   getFakeNotOnboardedDomain(true, false, true, true),
			inputService:        undefinedAthenzRulesServiceWithAnnotationTrue,
			expectedAuthzPolicy: getExpectedAuthzPolicyWithRole(),
		},
		{
			name:                "should create expected authz policy spec",
			inputAthenzDomain:   getFakeOnboardedDomain(),
			inputService:        onboardedService,
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			athenzclientset := fakev1.NewSimpleClientset()
			fakeAthenzInformer := adInformer.NewAthenzDomainInformer(athenzclientset, 0, cache.Indexers{})
			labels := onboardedService.GetLabels()
			domainRBAC := athenz.ConvertAthenzPoliciesIntoRbacModel(tt.inputAthenzDomain.Domain, &fakeAthenzInformer)
			componentsEnabledAuthzPolicy, err := common.ParseComponentsEnabledAuthzPolicy("*")
			assert.Equal(t, nil, err, "ParseComponentsEnabledAuthzPolicy func should not return nil")
			p := NewProvider(componentsEnabledAuthzPolicy, true)
			convertedAuthzPolicy := p.ConvertAthenzModelIntoIstioRbac(domainRBAC, tt.inputService.Name, labels["app"])
			configSpec := (convertedAuthzPolicy[0].Spec).(*v1beta1.AuthorizationPolicy)
			sort.Slice(configSpec.Rules, func(i, j int) bool {
				return configSpec.Rules[i].To[0].Operation.Methods[0] < configSpec.Rules[j].To[0].Operation.Methods[0]
			})
			convertedAuthzPolicy[0].Spec = configSpec
			convertedAuthzPolicy[0].CreationTimestamp = tt.expectedAuthzPolicy[0].CreationTimestamp
			assert.Equal(t, tt.expectedAuthzPolicy, convertedAuthzPolicy, "converted authz policy should be equal")
		})
	}
}

func getExpectedEmptyAuthzPolicy() []model.Config {
	var out model.Config
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	createTimestamp, err := time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
	if err != nil {
		panic(err)
	}
	out.ConfigMeta = model.ConfigMeta{
		Type:              schema.Resource().Kind(),
		Group:             schema.Resource().Group(),
		Version:           schema.Resource().Version(),
		Namespace:         "test-namespace",
		Name:              "onboarded-service",
		CreationTimestamp: createTimestamp,
	}
	out.Spec = &v1beta1.AuthorizationPolicy{
		Selector: &workloadv1beta1.WorkloadSelector{
			MatchLabels: map[string]string{"svc": "productpage"},
		},
	}
	return []model.Config{out}
}

func getExpectedAuthzPolicyWithRole() []model.Config {
	ap := getExpectedEmptyAuthzPolicy()

	configSpec := (ap[0].Spec).(*v1beta1.AuthorizationPolicy)
	configSpec.Rules = []*v1beta1.Rule{
		{
			From: []*v1beta1.Rule_From{
				{
					Source: &v1beta1.Source{
						Principals: []string{
							"test.namespace/ra/test.namespace:role.onboarded-service-access",
						},
					},
				},
			},
			To: []*v1beta1.Rule_To{
				{
					Operation: &v1beta1.Operation{
						Methods: []string{
							"POST",
						},
					},
				},
			},
		},
	}

	return ap
}

func getExpectedAuthzPolicy() []model.Config {
	var out model.Config
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	createTimestamp, err := time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
	if err != nil {
		panic(err)
	}
	out.ConfigMeta = model.ConfigMeta{
		Type:              schema.Resource().Kind(),
		Group:             schema.Resource().Group(),
		Version:           schema.Resource().Version(),
		Namespace:         "test-namespace",
		Name:              "onboarded-service",
		CreationTimestamp: createTimestamp,
	}
	out.Spec = &v1beta1.AuthorizationPolicy{
		Selector: &workloadv1beta1.WorkloadSelector{
			MatchLabels: map[string]string{"svc": "productpage"},
		},
		Rules: []*v1beta1.Rule{
			{
				From: []*v1beta1.Rule_From{
					{
						Source: &v1beta1.Source{
							Principals: []string{
								"*",
								"test.namespace/ra/test.namespace:role.productpage-reader",
							},
						},
					},
					{
						Source: &v1beta1.Source{
							RequestPrincipals: []string{
								"*",
							},
						},
					},
				},
				To: []*v1beta1.Rule_To{
					{
						Operation: &v1beta1.Operation{
							Methods: []string{
								"GET",
							},
						},
					},
				},
			},
			{
				From: []*v1beta1.Rule_From{
					{
						Source: &v1beta1.Source{
							Principals: []string{
								"user/sa/name",
								"test.namespace/ra/test.namespace:role.productpage-writer",
							},
						},
					},
					{
						Source: &v1beta1.Source{
							RequestPrincipals: []string{
								"athenz/user.name",
							},
						},
					},
				},
				To: []*v1beta1.Rule_To{
					{
						Operation: &v1beta1.Operation{
							Methods: []string{
								"POST",
							},
						},
					},
					{
						Operation: &v1beta1.Operation{
							Methods: []string{
								"POST",
							},
							Paths: []string{
								"/api/query",
							},
						},
					},
				},
			},
		},
	}
	return []model.Config{out}
}

func getFakeOnboardedDomain() zms.SignedDomain {
	allow := zms.ALLOW
	timestamp, err := rdl.TimestampParse("2012-11-01T22:08:41+00:00")
	if err != nil {
		panic(err)
	}

	return zms.SignedDomain{
		Domain: &zms.DomainData{
			Modified: timestamp,
			Name:     domainName,
			Policies: &zms.SignedPolicies{
				Contents: &zms.DomainPolicies{
					Domain: domainName,
					Policies: []*zms.Policy{
						{
							Assertions: []*zms.Assertion{
								{
									Role:     domainName + ":role.admin",
									Resource: domainName + ":*",
									Action:   "*",
									Effect:   &allow,
								},
								{
									Role:     domainName + ":role.productpage-reader",
									Resource: domainName + ":svc.productpage",
									Action:   "get",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     domainName + ":policy.admin",
						},
						{
							Assertions: []*zms.Assertion{
								{
									Role:     domainName + ":role.productpage-writer",
									Resource: domainName + ":svc.productpage",
									Action:   "post",
									Effect:   &allow,
								},
								{
									Role:     domainName + ":role.productpage-writer",
									Resource: domainName + ":svc.productpage:/api/query?*",
									Action:   "post",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     domainName + ":policy.productpage-writer",
						},
					},
				},
				KeyId:     "col-env-1.1",
				Signature: "signature-policy",
			},
			Roles: []*zms.Role{
				{
					Modified: &timestamp,
					Name:     domainName + ":role.admin",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: username,
						},
					},
				},
				{
					Modified: &timestamp,
					Name:     domainName + ":role.productpage-reader",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: wildcardUsername,
						},
					},
				},
				{
					Modified: &timestamp,
					Name:     domainName + ":role.productpage-writer",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: username,
						},
					},
				},
			},
			Services: []*zms.ServiceIdentity{},
			Entities: []*zms.Entity{},
		},
		KeyId:     "colo-env-1.1",
		Signature: "signature",
	}
}

func getFakeNotOnboardedDomain(addRole, addRoleMember, addPolicy, addAssertion bool) zms.SignedDomain {
	allow := zms.ALLOW
	timestamp, err := rdl.TimestampParse("2012-11-01T22:08:41+00:00")
	if err != nil {
		panic(err)
	}

	domain := zms.SignedDomain{
		Domain: &zms.DomainData{
			Name: domainName,
		},
		KeyId:     "colo-env-1.1",
		Signature: "signature",
	}

	if addRole {
		role := &zms.Role{
			Modified: &timestamp,
			Name:     domainName + ":role.onboarded-service-access",
		}

		if addRoleMember {
			role.RoleMembers = []*zms.RoleMember{
				{
					MemberName: username,
				},
			}
		}

		domain.Domain.Roles = append(domain.Domain.Roles, role)
	}

	if addPolicy {
		policy := &zms.SignedPolicies{
			Contents: &zms.DomainPolicies{
				Domain: domainName,
				Policies: []*zms.Policy{
					{
						Modified: &timestamp,
						Name:     domainName + ":policy.onboarded-service-access",
					},
				},
			},
			KeyId:     "col-env-1.1",
			Signature: "signature-policy",
		}

		if addAssertion {
			assertion := &zms.Assertion{
				Role:     domainName + ":role.onboarded-service-access",
				Resource: domainName + ":svc.productpage",
				Action:   "post",
				Effect:   &allow,
			}
			policy.Contents.Policies[0].Assertions = append(policy.Contents.Policies[0].Assertions, assertion)
		}

		domain.Domain.Policies = policy
	}

	return domain
}
