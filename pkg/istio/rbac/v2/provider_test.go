// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package v2

import (
	"github.com/ardielle/ardielle-go/rdl"
	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	fakev1 "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned/fake"
	adInformer "github.com/yahoo/k8s-athenz-syncer/pkg/client/informers/externalversions/athenz/v1"
	"istio.io/api/security/v1beta1"
	workloadv1beta1 "istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/collections"
	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"testing"
	"time"
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

	notOnboardedServiceWithAnnotationTrue = &k8sv1.Service{
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
			name:                "should create expected authz policy spec",
			inputAthenzDomain:   getFakeOnboardedDomain(),
			inputService:        onboardedService,
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
		},
		{
			name:                "should create empty authz policy spec for service which doesn't have roles / policies defined",
			inputAthenzDomain:   getFakeNotOnboardedDomain(),
			inputService:        notOnboardedServiceWithAnnotationTrue,
			expectedAuthzPolicy: getExpectedEmptyAuthzPolicy(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			athenzclientset := fakev1.NewSimpleClientset()
			fakeAthenzInformer := adInformer.NewAthenzDomainInformer(athenzclientset, 0, cache.Indexers{})
			labels := onboardedService.GetLabels()
			domainRBAC := athenz.ConvertAthenzPoliciesIntoRbacModel(tt.inputAthenzDomain.Domain, &fakeAthenzInformer)
			p := NewProvider(false, true)
			convertedAuthzPolicy := p.ConvertAthenzModelIntoIstioRbac(domainRBAC, tt.inputService.Name, labels["app"])
			assert.Equal(t, tt.expectedAuthzPolicy, convertedAuthzPolicy, "converted authz policy should be equal")
		})
	}
}

func getExpectedEmptyAuthzPolicy() []model.Config {
	var out model.Config
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	createTimestamp, _ := time.Parse("", "12/8/2015 12:00:00")
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

func getExpectedAuthzPolicy() []model.Config {
	var out model.Config
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	createTimestamp, _ := time.Parse("", "12/8/2015 12:00:00")
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
				},
			},
		},
	}
	return []model.Config{out}
}

func getFakeOnboardedDomain() zms.SignedDomain {
	allow := zms.ALLOW
	timestamp, err := rdl.TimestampParse("2019-07-22T20:29:10.305Z")
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
								{
									Role:     domainName + ":role.productpage-writer",
									Resource: domainName + ":svc.productpage",
									Action:   "post",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     domainName + ":policy.admin",
						},
					},
				},
				KeyId:     "col-env-1.1",
				Signature: "signature-policy",
			},
			Roles: []*zms.Role{
				{
					Members:  []zms.MemberName{username},
					Modified: &timestamp,
					Name:     domainName + ":role.admin",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: username,
						},
					},
				},
				{
					Members:  []zms.MemberName{"productpage-reader"},
					Modified: &timestamp,
					Name:     domainName + ":role.productpage-reader",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: wildcardUsername,
						},
					},
				},
				{
					Members:  []zms.MemberName{"productpage-writer"},
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

func getFakeNotOnboardedDomain() zms.SignedDomain {
	return zms.SignedDomain{
		Domain: &zms.DomainData{
			Name: domainName,
		},
		KeyId:     "colo-env-1.1",
		Signature: "signature",
	}
}
