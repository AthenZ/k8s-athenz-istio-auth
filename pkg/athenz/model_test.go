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
)

func toRDLTimestamp(s string) (rdl.Timestamp, error) {
	return rdl.TimestampParse(s)
}

func TestGetRolesForDomain(t *testing.T) {

	modified, err := toRDLTimestamp("2018-03-14T19:36:41.003Z")
	if err != nil {
		t.Errorf(err.Error())
	}
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

	for _, c := range cases {
		if got := getMembersForRole(c.domain); !reflect.DeepEqual(got, c.expected) {
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
				Members: RoleMembers{},
				Rules:   RoleAssertions{},
				Roles:   Roles{},
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
			},
		},
	}

	for _, c := range cases {
		if got := ConvertAthenzPoliciesIntoRbacModel(c.domain); !reflect.DeepEqual(got, c.expected) {
			//assert.True(t, reflect.DeepEqual(c.expected, got), c.test)
			assert.Equal(t, c.expected, got, c.test)
		}
	}
}
