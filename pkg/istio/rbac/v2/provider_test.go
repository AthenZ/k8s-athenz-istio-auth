// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package v2

import (
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
	"sort"
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
)

func TestConvertAthenzModelIntoIstioRbac(t *testing.T) {
	athenzclientset := fakev1.NewSimpleClientset()
	fakeAthenzInformer := adInformer.NewAthenzDomainInformer(athenzclientset, 0, cache.Indexers{})
	signedDomain := getFakeDomain()
	labels := onboardedService.GetLabels()
	domainRBAC := athenz.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &fakeAthenzInformer)
	componentsEnabledAuthzPolicy, err := common.ParseComponentsEnabledAuthzPolicy("*")
	assert.Equal(t, nil, err, "ParseComponentsEnabledAuthzPolicy func should not return nil")
	p := NewProvider(componentsEnabledAuthzPolicy, true)

	convertedCR := p.ConvertAthenzModelIntoIstioRbac(domainRBAC, onboardedService.Name, labels["app"])
	expectedCR := getExpectedCR()
	// when there are multiple assertions matched with svc,
	// base on which assertion will be processed from the athenzModel mapping, order of the authz rule generated
	// may be different each time. Using a workaround here to sort the configSpec in alphabetical order of first
	// method in each rule.
	configSpec := (convertedCR[0].Spec).(*v1beta1.AuthorizationPolicy)
	sort.Slice(configSpec.Rules, func(i, j int) bool {
		return configSpec.Rules[i].To[0].Operation.Methods[0] < configSpec.Rules[j].To[0].Operation.Methods[0]
	})
	convertedCR[0].Spec = configSpec

	assert.EqualValues(t, expectedCR, convertedCR, "converted authz policy should be equal")
}

func getExpectedCR() []model.Config {
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

func getFakeDomain() zms.SignedDomain {
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
