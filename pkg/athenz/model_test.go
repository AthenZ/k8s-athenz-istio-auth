// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package athenz

import (
	"reflect"
	"testing"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	v1 "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	"github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned/fake"
	athenzInformer "github.com/yahoo/k8s-athenz-syncer/pkg/client/informers/externalversions/athenz/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	trustDomainName = "test.trust.domain"
	trustusername   = "trustuser.name"
)

var (
	ad1 = &v1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: trustDomainName,
		},
		Spec: v1.AthenzDomainSpec{
			SignedDomain: getFakeTrustDomain(),
		},
	}
)

func toRDLTimestamp(s string) (rdl.Timestamp, error) {
	return rdl.TimestampParse(s)
}

func TestGetRolesForDomain(t *testing.T) {

	cases := []struct {
		test     string
		domain   *zms.DomainData
		expected Roles
	}{
		{
			test:     "nil athenz domain",
			domain:   nil,
			expected: make(Roles, 0),
		},
		{
			test:     "empty domain roles",
			domain:   &zms.DomainData{},
			expected: make(Roles, 0),
		},
		{
			test: "valid Athenz domain",
			domain: &zms.DomainData{
				Name: "athenz-domain.name",
				Roles: []*zms.Role{
					{
						Name: "athenz-domain.name:role.my-reader-role",
					},
					{
						Name: "athenz-domain.name:role.my-writer-role",
					},
				},
			},
			expected: Roles{
				zms.ResourceName("athenz-domain.name:role.my-reader-role"),
				zms.ResourceName("athenz-domain.name:role.my-writer-role"),
			},
		},
	}

	for _, c := range cases {
		if got := getRolesForDomain(c.domain); !reflect.DeepEqual(got, c.expected) {
			assert.Equal(t, c.expected, got, c.test)
		}
	}
}

func TestGetRulesForDomain(t *testing.T) {

	allow := zms.ALLOW
	modified, err := toRDLTimestamp("2018-03-14T19:36:41.003Z")
	if err != nil {
		t.Errorf(err.Error())
	}
	cases := []struct {
		test     string
		domain   *zms.DomainData
		expected RoleAssertions
	}{
		{
			test:     "nil domain",
			domain:   nil,
			expected: make(RoleAssertions),
		},
		{
			test:     "nil policies",
			domain:   &zms.DomainData{},
			expected: make(RoleAssertions),
		},
		{
			test: "nil policy contents",
			domain: &zms.DomainData{
				Policies: &zms.SignedPolicies{},
			},
			expected: make(RoleAssertions),
		},
		{
			test: "valid Athenz domain",
			domain: &zms.DomainData{
				Policies: &zms.SignedPolicies{
					Contents: &zms.DomainPolicies{
						Domain: zms.DomainName("athenz.domain"),
						Policies: []*zms.Policy{
							{
								Name:     "athenz.domain:policy.my-service-reader",
								Modified: &modified,
								Assertions: []*zms.Assertion{
									{
										Role:     "athenz.domain:role.name",
										Resource: "athenz.domain:svc.my-service-name:*",
										Action:   "get",
										Effect:   &allow,
									},
								},
							},
						},
					},
				},
			},
			expected: RoleAssertions{
				zms.ResourceName("athenz.domain:role.name"): []*zms.Assertion{
					{
						Role:     "athenz.domain:role.name",
						Resource: "athenz.domain:svc.my-service-name:*",
						Action:   "get",
						Effect:   &allow,
					},
				},
			},
		},
		{
			test: "valid Athenz domain with multiple assertions for same role but different service in a policy",
			domain: &zms.DomainData{
				Policies: &zms.SignedPolicies{
					Contents: &zms.DomainPolicies{
						Domain: zms.DomainName("athenz.domain"),
						Policies: []*zms.Policy{
							{
								Name:     "athenz.domain:policy.my-service-reader",
								Modified: &modified,
								Assertions: []*zms.Assertion{
									{
										Role:     "athenz.domain:role.name",
										Resource: "athenz.domain:svc.my-service-name:*",
										Action:   "get",
										Effect:   &allow,
									},
									{
										Role:     "athenz.domain:role.name",
										Resource: "athenz.domain:svc.my-service-name",
										Action:   "post",
										Effect:   &allow,
									},
									{
										Role:     "athenz.domain:role.name",
										Resource: "athenz.domain:svc.my-service-two:*",
										Action:   "put",
										Effect:   &allow,
									},
								},
							},
						},
					},
				},
			},
			expected: RoleAssertions{
				zms.ResourceName("athenz.domain:role.name"): []*zms.Assertion{
					{
						Role:     "athenz.domain:role.name",
						Resource: "athenz.domain:svc.my-service-name:*",
						Action:   "get",
						Effect:   &allow,
					},
					{
						Role:     "athenz.domain:role.name",
						Resource: "athenz.domain:svc.my-service-name",
						Action:   "post",
						Effect:   &allow,
					},
					{
						Role:     "athenz.domain:role.name",
						Resource: "athenz.domain:svc.my-service-two:*",
						Action:   "put",
						Effect:   &allow,
					},
				},
			},
		},
		{
			test: "valid Athenz domain with multiple assertions for same role in different policies",
			domain: &zms.DomainData{
				Policies: &zms.SignedPolicies{
					Contents: &zms.DomainPolicies{
						Domain: zms.DomainName("athenz.domain"),
						Policies: []*zms.Policy{
							{
								Name:     "athenz.domain:policy.my-service-reader",
								Modified: &modified,
								Assertions: []*zms.Assertion{
									{
										Role:     "athenz.domain:role.name",
										Resource: "athenz.domain:svc.my-service-name:*",
										Action:   "get",
										Effect:   &allow,
									},
									{
										Role:     "athenz.domain:role.name",
										Resource: "athenz.domain:svc.my-service-name",
										Action:   "post",
										Effect:   &allow,
									},
								},
							},
							{
								Name:     "athenz.domain:policy.my-service-writer",
								Modified: &modified,
								Assertions: []*zms.Assertion{
									{
										Role:     "athenz.domain:role.name",
										Resource: "athenz.domain:svc.my-service-name:*",
										Action:   "put",
										Effect:   &allow,
									},
									{
										Role:     "athenz.domain:role.name",
										Resource: "athenz.domain:svc.my-service-two",
										Action:   "post",
										Effect:   &allow,
									},
									{
										Role:     "athenz.domain:role.name",
										Resource: "athenz.domain:svc.my-service-three:*",
										Action:   "put",
										Effect:   &allow,
									},
								},
							},
						},
					},
				},
			},
			expected: RoleAssertions{
				zms.ResourceName("athenz.domain:role.name"): []*zms.Assertion{
					{
						Role:     "athenz.domain:role.name",
						Resource: "athenz.domain:svc.my-service-name:*",
						Action:   "get",
						Effect:   &allow,
					},
					{
						Role:     "athenz.domain:role.name",
						Resource: "athenz.domain:svc.my-service-name",
						Action:   "post",
						Effect:   &allow,
					},
					{
						Role:     "athenz.domain:role.name",
						Resource: "athenz.domain:svc.my-service-name:*",
						Action:   "put",
						Effect:   &allow,
					},
					{
						Role:     "athenz.domain:role.name",
						Resource: "athenz.domain:svc.my-service-two",
						Action:   "post",
						Effect:   &allow,
					},
					{
						Role:     "athenz.domain:role.name",
						Resource: "athenz.domain:svc.my-service-three:*",
						Action:   "put",
						Effect:   &allow,
					},
				},
			},
		},
		{
			test: "valid Athenz domain with multiple assertions for multiple roles in different policies",
			domain: &zms.DomainData{
				Policies: &zms.SignedPolicies{
					Contents: &zms.DomainPolicies{
						Domain: zms.DomainName("athenz.domain"),
						Policies: []*zms.Policy{
							{
								Name:     "athenz.domain:policy.my-services-reader",
								Modified: &modified,
								Assertions: []*zms.Assertion{
									{
										Role:     "athenz.domain:role.name",
										Resource: "athenz.domain:svc.my-service-name:*",
										Action:   "get",
										Effect:   &allow,
									},
									{
										Role:     "athenz.domain:role-two.name",
										Resource: "athenz.domain:svc.my-service-name",
										Action:   "post",
										Effect:   &allow,
									},
								},
							},
							{
								Name:     "athenz.domain:policy.my-services-writer",
								Modified: &modified,
								Assertions: []*zms.Assertion{
									{
										Role:     "athenz.domain:role-three.name",
										Resource: "athenz.domain:svc.my-service-name:*",
										Action:   "put",
										Effect:   &allow,
									},
									{
										Role:     "athenz.domain:role.name",
										Resource: "athenz.domain:svc.my-service-two",
										Action:   "post",
										Effect:   &allow,
									},
									{
										Role:     "athenz.domain:role-two.name",
										Resource: "athenz.domain:svc.my-service-three:*",
										Action:   "put",
										Effect:   &allow,
									},
								},
							},
							{
								Name:     "athenz.domain:policy.my-services-admin",
								Modified: &modified,
								Assertions: []*zms.Assertion{
									{
										Role:     "athenz.domain:role-four.name",
										Resource: "athenz.domain:*:*",
										Action:   "*",
										Effect:   &allow,
									},
								},
							},
						},
					},
				},
			},
			expected: RoleAssertions{
				zms.ResourceName("athenz.domain:role.name"): []*zms.Assertion{
					{
						Role:     "athenz.domain:role.name",
						Resource: "athenz.domain:svc.my-service-name:*",
						Action:   "get",
						Effect:   &allow,
					},
					{
						Role:     "athenz.domain:role.name",
						Resource: "athenz.domain:svc.my-service-two",
						Action:   "post",
						Effect:   &allow,
					},
				},
				zms.ResourceName("athenz.domain:role-two.name"): []*zms.Assertion{
					{
						Role:     "athenz.domain:role-two.name",
						Resource: "athenz.domain:svc.my-service-name",
						Action:   "post",
						Effect:   &allow,
					},
					{
						Role:     "athenz.domain:role-two.name",
						Resource: "athenz.domain:svc.my-service-three:*",
						Action:   "put",
						Effect:   &allow,
					},
				},
				zms.ResourceName("athenz.domain:role-three.name"): []*zms.Assertion{
					{
						Role:     "athenz.domain:role-three.name",
						Resource: "athenz.domain:svc.my-service-name:*",
						Action:   "put",
						Effect:   &allow,
					},
				},
				zms.ResourceName("athenz.domain:role-four.name"): []*zms.Assertion{
					{
						Role:     "athenz.domain:role-four.name",
						Resource: "athenz.domain:*:*",
						Action:   "*",
						Effect:   &allow,
					},
				},
			},
		},
	}

	for _, c := range cases {
		if got := getRulesForDomain(c.domain); !reflect.DeepEqual(got, c.expected) {
			assert.Equal(t, c.expected, got, c.test)
		}
	}
}

func TestGetMembersForRole(t *testing.T) {

	modified, err := toRDLTimestamp("2018-03-14T19:36:41.003Z")
	if err != nil {
		t.Errorf(err.Error())
	}
	cases := []struct {
		test     string
		domain   *zms.DomainData
		expected RoleMembers
	}{
		{
			test:     "nil athenz domain",
			domain:   nil,
			expected: make(RoleMembers),
		},
		{
			test:     "empty domain roles",
			domain:   &zms.DomainData{},
			expected: make(RoleMembers),
		},
		{
			test: "valid Athenz domain",
			domain: &zms.DomainData{
				Name: "athenz-domain.name",
				Roles: []*zms.Role{
					{
						Name:     "athenz-domain.name:role.my-reader-role",
						Modified: &modified,
						RoleMembers: []*zms.RoleMember{
							{
								MemberName: "client-domain.serviceA",
							},
							{
								MemberName: "client-domain.serviceB",
							},
							{
								MemberName: "client2-domain.serviceA",
							},
						},
					},
					{
						Name:     "athenz-domain.name:role.my-writer-role",
						Modified: &modified,
						RoleMembers: []*zms.RoleMember{
							{
								MemberName: "client-domain.admin-service",
							},
							{
								MemberName: "client2-domain.serviceA",
							},
						},
					},
				},
			},
			expected: RoleMembers{
				zms.ResourceName("athenz-domain.name:role.my-reader-role"): []*zms.RoleMember{
					{
						MemberName: "client-domain.serviceA",
					},
					{
						MemberName: "client-domain.serviceB",
					},
					{
						MemberName: "client2-domain.serviceA",
					},
				},
				zms.ResourceName("athenz-domain.name:role.my-writer-role"): []*zms.RoleMember{
					{
						MemberName: "client-domain.admin-service",
					},
					{
						MemberName: "client2-domain.serviceA",
					},
				},
			},
		},
	}

	athenzclientset := fake.NewSimpleClientset()
	crIndexInformer := athenzInformer.NewAthenzDomainInformer(athenzclientset, 0, cache.Indexers{})

	for _, c := range cases {
		if got := getMembersForRole(c.domain, &crIndexInformer); !reflect.DeepEqual(got, c.expected) {
			assert.Equal(t, c.expected, got, c.test)
		}
	}
}

func TestConvertAthenzPoliciesIntoRbacModel(t *testing.T) {

	allow := zms.ALLOW
	modified, err := toRDLTimestamp("2018-03-14T19:36:41.003Z")
	if err != nil {
		t.Errorf(err.Error())
	}
	cases := []struct {
		test     string
		domain   *zms.DomainData
		expected Model
	}{
		{
			test:   "nil athenz domain",
			domain: nil,
			expected: Model{
				Members:      RoleMembers{},
				Rules:        RoleAssertions{},
				Roles:        Roles{},
				GroupMembers: GroupMembers{},
			},
		},
		{
			test: "valid Athenz domain with multiple assertions for multiple roles in different policies",
			domain: &zms.DomainData{
				Name: "athenz-domain.name",
				Roles: []*zms.Role{
					{
						Name:     "athenz-domain.name:role.name",
						Modified: &modified,
						RoleMembers: []*zms.RoleMember{
							{
								MemberName: "client-domain.serviceA",
							},
							{
								MemberName: "client-domain.serviceB",
							},
							{
								MemberName: "client2-domain.serviceA",
							},
						},
					},
					{
						Name:     "athenz-domain.name:role-two.name",
						Modified: &modified,
						RoleMembers: []*zms.RoleMember{
							{
								MemberName: "client-domain.writer-service",
							},
							{
								MemberName: "client2-domain.serviceA",
							},
						},
					},
					{
						Name:     "athenz-domain.name:role-three.name",
						Modified: &modified,
						RoleMembers: []*zms.RoleMember{
							{
								MemberName: "client3-domain.manager-service",
							},
							{
								MemberName: "client3-domain.serviceX",
							},
						},
					},
					{
						Name:     "athenz-domain.name:role-four.name",
						Modified: &modified,
						RoleMembers: []*zms.RoleMember{
							{
								MemberName: "client4-domain.admin-service",
							},
						},
					},
				},
				Policies: &zms.SignedPolicies{
					Contents: &zms.DomainPolicies{
						Domain: zms.DomainName("athenz-domain.name"),
						Policies: []*zms.Policy{
							{
								Name:     "athenz-domain.name:policy.my-services-reader",
								Modified: &modified,
								Assertions: []*zms.Assertion{
									{
										Role:     "athenz-domain.name:role.name",
										Resource: "athenz-domain.name:svc.my-service-name:*",
										Action:   "get",
										Effect:   &allow,
									},
									{
										Role:     "athenz-domain.name:role-two.name",
										Resource: "athenz-domain.name:svc.my-service-name",
										Action:   "post",
										Effect:   &allow,
									},
								},
							},
							{
								Name:     "athenz-domain.name:policy.my-services-writer",
								Modified: &modified,
								Assertions: []*zms.Assertion{
									{
										Role:     "athenz-domain.name:role-three.name",
										Resource: "athenz-domain.name:svc.my-service-name:*",
										Action:   "put",
										Effect:   &allow,
									},
									{
										Role:     "athenz-domain.name:role.name",
										Resource: "athenz-domain.name:svc.my-service-two",
										Action:   "post",
										Effect:   &allow,
									},
									{
										Role:     "athenz-domain.name:role-two.name",
										Resource: "athenz-domain.name:svc.my-service-three:*",
										Action:   "put",
										Effect:   &allow,
									},
								},
							},
							{
								Name:     "athenz-domain.name:policy.my-services-admin",
								Modified: &modified,
								Assertions: []*zms.Assertion{
									{
										Role:     "athenz-domain.name:role-four.name",
										Resource: "athenz-domain.name:*:*",
										Action:   "*",
										Effect:   &allow,
									},
								},
							},
						},
					},
				},
			},
			expected: Model{
				Name:      zms.DomainName("athenz-domain.name"),
				Namespace: "athenz--domain-name",
				Roles: Roles{
					zms.ResourceName("athenz-domain.name:role.name"),
					zms.ResourceName("athenz-domain.name:role-two.name"),
					zms.ResourceName("athenz-domain.name:role-three.name"),
					zms.ResourceName("athenz-domain.name:role-four.name"),
				},
				Rules: RoleAssertions{
					zms.ResourceName("athenz-domain.name:role.name"): []*zms.Assertion{
						{
							Role:     "athenz-domain.name:role.name",
							Resource: "athenz-domain.name:svc.my-service-name:*",
							Action:   "get",
							Effect:   &allow,
						},
						{
							Role:     "athenz-domain.name:role.name",
							Resource: "athenz-domain.name:svc.my-service-two",
							Action:   "post",
							Effect:   &allow,
						},
					},
					zms.ResourceName("athenz-domain.name:role-two.name"): []*zms.Assertion{
						{
							Role:     "athenz-domain.name:role-two.name",
							Resource: "athenz-domain.name:svc.my-service-name",
							Action:   "post",
							Effect:   &allow,
						},
						{
							Role:     "athenz-domain.name:role-two.name",
							Resource: "athenz-domain.name:svc.my-service-three:*",
							Action:   "put",
							Effect:   &allow,
						},
					},
					zms.ResourceName("athenz-domain.name:role-three.name"): []*zms.Assertion{
						{
							Role:     "athenz-domain.name:role-three.name",
							Resource: "athenz-domain.name:svc.my-service-name:*",
							Action:   "put",
							Effect:   &allow,
						},
					},
					zms.ResourceName("athenz-domain.name:role-four.name"): []*zms.Assertion{
						{
							Role:     "athenz-domain.name:role-four.name",
							Resource: "athenz-domain.name:*:*",
							Action:   "*",
							Effect:   &allow,
						},
					},
				},
				Members: RoleMembers{
					zms.ResourceName("athenz-domain.name:role.name"): []*zms.RoleMember{
						{
							MemberName: "client-domain.serviceA",
						},
						{
							MemberName: "client-domain.serviceB",
						},
						{
							MemberName: "client2-domain.serviceA",
						},
					},
					zms.ResourceName("athenz-domain.name:role-two.name"): []*zms.RoleMember{
						{
							MemberName: "client-domain.writer-service",
						},
						{
							MemberName: "client2-domain.serviceA",
						},
					},
					zms.ResourceName("athenz-domain.name:role-three.name"): []*zms.RoleMember{
						{
							MemberName: "client3-domain.manager-service",
						},
						{
							MemberName: "client3-domain.serviceX",
						},
					},
					zms.ResourceName("athenz-domain.name:role-four.name"): []*zms.RoleMember{
						{
							MemberName: "client4-domain.admin-service",
						},
					},
				},
				GroupMembers: GroupMembers{},
			},
		},
		{
			test: "valid athenz domain object with delegated role, mutiple roles, multiple policies",
			domain: &zms.DomainData{
				Name: "home.domain",
				Roles: []*zms.Role{
					{
						Name:     "home.domain:role.admin",
						Modified: &modified,
						RoleMembers: []*zms.RoleMember{
							{
								MemberName: zms.MemberName("user.name"),
							},
						},
					},
					{
						Modified: &modified,
						Name:     zms.ResourceName("home.domain:role.delegated"),
						Trust:    trustDomainName,
					},
				},
				Policies: &zms.SignedPolicies{
					Contents: &zms.DomainPolicies{
						Domain: zms.DomainName("home.domain"),
						Policies: []*zms.Policy{
							{
								Assertions: []*zms.Assertion{
									{
										Role:     "home.domain:role.admin",
										Resource: "home.domain:*",
										Action:   "*",
										Effect:   &allow,
									},
								},
								Modified: &modified,
								Name:     zms.ResourceName("home.domain:policy.admin"),
							},
							{
								Assertions: []*zms.Assertion{
									{
										Role:     "home.domain:role.delegated",
										Resource: "home.domain:svc.my-service-name:*",
										Action:   "get",
										Effect:   &allow,
									},
								},
								Modified: &modified,
								Name:     zms.ResourceName("home.domain:policy.delegated"),
							},
						},
					},
				},
			},
			expected: Model{
				Name:      zms.DomainName("home.domain"),
				Namespace: "home-domain",
				Roles: Roles{
					zms.ResourceName("home.domain:role.admin"),
					zms.ResourceName("home.domain:role.delegated"),
				},
				Rules: RoleAssertions{
					zms.ResourceName("home.domain:role.admin"): []*zms.Assertion{
						{
							Role:     "home.domain:role.admin",
							Resource: "home.domain:*",
							Action:   "*",
							Effect:   &allow,
						},
					},
					zms.ResourceName("home.domain:role.delegated"): []*zms.Assertion{
						{
							Role:     "home.domain:role.delegated",
							Resource: "home.domain:svc.my-service-name:*",
							Action:   "get",
							Effect:   &allow,
						},
					},
				},
				Members: RoleMembers{
					zms.ResourceName("home.domain:role.admin"): []*zms.RoleMember{
						{
							MemberName: "user.name",
						},
					},
					zms.ResourceName("home.domain:role.delegated"): []*zms.RoleMember{
						{
							MemberName: trustusername,
						},
					},
				},
				GroupMembers: GroupMembers{},
			},
		},

		{
			test: "valid Athenz domain with multiple assertions for multiple roles with groups in different policies",
			domain: &zms.DomainData{
				Name: "athenz-domain.name",
				Roles: []*zms.Role{
					{
						Name:     "athenz-domain.name:role.name",
						Modified: &modified,
						RoleMembers: []*zms.RoleMember{
							{
								MemberName: "client-domain.serviceA",
							},
							{
								MemberName: "client-domain.serviceB",
							},
							{
								MemberName: "client2-domain.serviceA",
							},
							{
								MemberName: "athenz-domain.name:group.name",
							},
						},
					},
					{
						Name:     "athenz-domain.name:role-two.name",
						Modified: &modified,
						RoleMembers: []*zms.RoleMember{
							{
								MemberName: "client-domain.writer-service",
							},
							{
								MemberName: "client2-domain.serviceA",
							},
							{
								MemberName: "athenz-domain.name:group-two.name",
							},
						},
					},
					{
						Name:     "athenz-domain.name:role-three.name",
						Modified: &modified,
						RoleMembers: []*zms.RoleMember{
							{
								MemberName: "client3-domain.manager-service",
							},
							{
								MemberName: "client3-domain.serviceX",
							},
						},
					},
					{
						Name:     "athenz-domain.name:role-four.name",
						Modified: &modified,
						RoleMembers: []*zms.RoleMember{
							{
								MemberName: "client4-domain.admin-service",
							},
						},
					},
				},
				Groups: []*zms.Group{
					{
						Name:     "athenz-domain.name:group.name",
						Modified: &modified,
						GroupMembers: []*zms.GroupMember{
							{
								MemberName: "client-domain-from-group.serviceA",
							},
							{
								MemberName: "client-domain-from-group.serviceB",
							},
							{
								MemberName: "client2-domain-from-group.serviceA",
							},
						},
					},
					{
						Name:     "athenz-domain.name:group-two.name",
						Modified: &modified,
						GroupMembers: []*zms.GroupMember{
							{
								MemberName: "client-domain-from-group.writer-service",
							},
							{
								MemberName: "client2-domain-from-group.serviceA",
							},
						},
					},
				},
				Policies: &zms.SignedPolicies{
					Contents: &zms.DomainPolicies{
						Domain: zms.DomainName("athenz-domain.name"),
						Policies: []*zms.Policy{
							{
								Name:     "athenz-domain.name:policy.my-services-reader",
								Modified: &modified,
								Assertions: []*zms.Assertion{
									{
										Role:     "athenz-domain.name:role.name",
										Resource: "athenz-domain.name:svc.my-service-name:*",
										Action:   "get",
										Effect:   &allow,
									},
									{
										Role:     "athenz-domain.name:role-two.name",
										Resource: "athenz-domain.name:svc.my-service-name",
										Action:   "post",
										Effect:   &allow,
									},
								},
							},
							{
								Name:     "athenz-domain.name:policy.my-services-writer",
								Modified: &modified,
								Assertions: []*zms.Assertion{
									{
										Role:     "athenz-domain.name:role-three.name",
										Resource: "athenz-domain.name:svc.my-service-name:*",
										Action:   "put",
										Effect:   &allow,
									},
									{
										Role:     "athenz-domain.name:role.name",
										Resource: "athenz-domain.name:svc.my-service-two",
										Action:   "post",
										Effect:   &allow,
									},
									{
										Role:     "athenz-domain.name:role-two.name",
										Resource: "athenz-domain.name:svc.my-service-three:*",
										Action:   "put",
										Effect:   &allow,
									},
								},
							},
							{
								Name:     "athenz-domain.name:policy.my-services-admin",
								Modified: &modified,
								Assertions: []*zms.Assertion{
									{
										Role:     "athenz-domain.name:role-four.name",
										Resource: "athenz-domain.name:*:*",
										Action:   "*",
										Effect:   &allow,
									},
								},
							},
						},
					},
				},
			},
			expected: Model{
				Name:      zms.DomainName("athenz-domain.name"),
				Namespace: "athenz--domain-name",
				Roles: Roles{
					zms.ResourceName("athenz-domain.name:role.name"),
					zms.ResourceName("athenz-domain.name:role-two.name"),
					zms.ResourceName("athenz-domain.name:role-three.name"),
					zms.ResourceName("athenz-domain.name:role-four.name"),
				},
				Rules: RoleAssertions{
					zms.ResourceName("athenz-domain.name:role.name"): []*zms.Assertion{
						{
							Role:     "athenz-domain.name:role.name",
							Resource: "athenz-domain.name:svc.my-service-name:*",
							Action:   "get",
							Effect:   &allow,
						},
						{
							Role:     "athenz-domain.name:role.name",
							Resource: "athenz-domain.name:svc.my-service-two",
							Action:   "post",
							Effect:   &allow,
						},
					},
					zms.ResourceName("athenz-domain.name:role-two.name"): []*zms.Assertion{
						{
							Role:     "athenz-domain.name:role-two.name",
							Resource: "athenz-domain.name:svc.my-service-name",
							Action:   "post",
							Effect:   &allow,
						},
						{
							Role:     "athenz-domain.name:role-two.name",
							Resource: "athenz-domain.name:svc.my-service-three:*",
							Action:   "put",
							Effect:   &allow,
						},
					},
					zms.ResourceName("athenz-domain.name:role-three.name"): []*zms.Assertion{
						{
							Role:     "athenz-domain.name:role-three.name",
							Resource: "athenz-domain.name:svc.my-service-name:*",
							Action:   "put",
							Effect:   &allow,
						},
					},
					zms.ResourceName("athenz-domain.name:role-four.name"): []*zms.Assertion{
						{
							Role:     "athenz-domain.name:role-four.name",
							Resource: "athenz-domain.name:*:*",
							Action:   "*",
							Effect:   &allow,
						},
					},
				},
				Members: RoleMembers{
					zms.ResourceName("athenz-domain.name:role.name"): []*zms.RoleMember{
						{
							MemberName: "client-domain.serviceA",
						},
						{
							MemberName: "client-domain.serviceB",
						},
						{
							MemberName: "client2-domain.serviceA",
						},
						{
							MemberName: "athenz-domain.name:group.name",
						},
					},
					zms.ResourceName("athenz-domain.name:role-two.name"): []*zms.RoleMember{
						{
							MemberName: "client-domain.writer-service",
						},
						{
							MemberName: "client2-domain.serviceA",
						},
						{
							MemberName: "athenz-domain.name:group-two.name",
						},
					},
					zms.ResourceName("athenz-domain.name:role-three.name"): []*zms.RoleMember{
						{
							MemberName: "client3-domain.manager-service",
						},
						{
							MemberName: "client3-domain.serviceX",
						},
					},
					zms.ResourceName("athenz-domain.name:role-four.name"): []*zms.RoleMember{
						{
							MemberName: "client4-domain.admin-service",
						},
					},
				},
				GroupMembers: GroupMembers{
					zms.MemberName("athenz-domain.name:group.name"): []*zms.GroupMember{
						{
							MemberName: "client-domain-from-group.serviceA",
						},
						{
							MemberName: "client-domain-from-group.serviceB",
						},
						{
							MemberName: "client2-domain-from-group.serviceA",
						},
					},
					zms.MemberName("athenz-domain.name:group-two.name"): []*zms.GroupMember{
						{
							MemberName: "client-domain-from-group.writer-service",
						},
						{
							MemberName: "client2-domain-from-group.serviceA",
						},
					},
				},
			},
		},
	}

	athenzclientset := fake.NewSimpleClientset()
	crIndexInformer := athenzInformer.NewAthenzDomainInformer(athenzclientset, 0, cache.Indexers{})
	crIndexInformer.GetStore().Add(ad1.DeepCopy())

	for _, c := range cases {
		if got := ConvertAthenzPoliciesIntoRbacModel(c.domain, &crIndexInformer); !reflect.DeepEqual(got, c.expected) {
			assert.Equal(t, c.expected, got, c.test)
		}
	}
}

func getFakeTrustAthenzDomain() *v1.AthenzDomain {
	spec := v1.AthenzDomainSpec{
		SignedDomain: getFakeTrustDomain(),
	}
	item := &v1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: trustDomainName,
		},
		Spec: spec,
	}
	return item
}

func getFakeTrustDomain() zms.SignedDomain {
	allow := zms.ALLOW
	timestamp, err := rdl.TimestampParse("2019-07-22T20:29:10.305Z")
	if err != nil {
		panic(err)
	}

	return zms.SignedDomain{
		Domain: &zms.DomainData{
			Modified: timestamp,
			Name:     zms.DomainName(trustDomainName),
			Policies: &zms.SignedPolicies{
				Contents: &zms.DomainPolicies{
					Domain: zms.DomainName(trustDomainName),
					Policies: []*zms.Policy{
						{
							Assertions: []*zms.Assertion{
								{
									Role:     trustDomainName + ":role.admin",
									Resource: "*:role.delegated",
									Action:   "assume_role",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     zms.ResourceName(trustDomainName + ":policy.admin"),
						},
					},
				},
				KeyId:     "col-env-1.1",
				Signature: "signature-policy",
			},
			Roles: []*zms.Role{
				{
					Members:  []zms.MemberName{zms.MemberName(trustusername)},
					Modified: &timestamp,
					Name:     zms.ResourceName(trustDomainName + ":role.admin"),
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: zms.MemberName(trustusername),
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
