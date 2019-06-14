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
