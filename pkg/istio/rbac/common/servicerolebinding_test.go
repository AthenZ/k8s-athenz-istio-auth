// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package common

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"

	"istio.io/api/rbac/v1alpha1"
)

func init() {
	log.InitLogger("", "debug")
}

func TestParseMemberName(t *testing.T) {

	cases := []struct {
		test           string
		member         *zms.RoleMember
		expectedMember string
		expectedErr    error
	}{
		{
			test:           "nil member",
			member:         nil,
			expectedMember: "",
			expectedErr:    fmt.Errorf("member is nil"),
		},
		{
			test: "valid service member",
			member: &zms.RoleMember{
				MemberName: zms.MemberName("client.some-domain.dep-svcA"),
			},
			expectedMember: "client.some-domain/sa/dep-svcA",
			expectedErr:    nil,
		},
		{
			test: "valid user member",
			member: &zms.RoleMember{
				MemberName: zms.MemberName("user.somename"),
			},
			expectedMember: "user/sa/somename",
			expectedErr:    nil,
		},
		{
			test: "valid wildcard member",
			member: &zms.RoleMember{
				MemberName: zms.MemberName("user.*"),
			},
			expectedMember: "*",
			expectedErr:    nil,
		},
		{
			test: "invalid member",
			member: &zms.RoleMember{
				MemberName: zms.MemberName("not-a-valid-principal"),
			},
			expectedMember: "",
			expectedErr:    fmt.Errorf("principal:not-a-valid-principal is not of the format <Athenz-domain>.<Athenz-service>"),
		},
	}

	for _, c := range cases {
		gotMember, gotErr := parseMemberName(c.member)
		assert.Equal(t, c.expectedMember, gotMember, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
}

func TestGetServiceRoleBindingSpec(t *testing.T) {

	type input struct {
		roleName    string
		k8sRoleName string
		members     []*zms.RoleMember
	}
	cases := []struct {
		test         string
		input        input
		expectedSpec *v1alpha1.ServiceRoleBinding
		expectedErr  error
	}{
		{
			test: "empty args",
			input: input{
				roleName:    "",
				k8sRoleName: "",
				members:     nil,
			},
			expectedSpec: nil,
			expectedErr:  fmt.Errorf("no subjects found for the ServiceRoleBinding: "),
		},
		{
			test: "valid role member spec",
			input: input{
				roleName:    "client-reader_role",
				k8sRoleName: "client-reader--role",
				members: []*zms.RoleMember{
					{
						MemberName: "athenz.domain.client-serviceA",
					},
					{
						MemberName: "user.athenzuser",
					},
				},
			},
			expectedSpec: &v1alpha1.ServiceRoleBinding{
				RoleRef: &v1alpha1.RoleRef{
					Name: "client-reader--role",
					Kind: ServiceRoleKind,
				},
				Subjects: []*v1alpha1.Subject{
					{
						User: "athenz.domain/sa/client-serviceA",
					},
					{
						User: "user/sa/athenzuser",
					},
				},
			},
			expectedErr: nil,
		},
		{
			test: "invalid role member spec",
			input: input{
				roleName:    "client-reader-role",
				k8sRoleName: "client-reader-role",
				members: []*zms.RoleMember{
					{
						MemberName: "not-a-valid-user",
					},
					{
						MemberName: "another-not-valid-service",
					},
				},
			},
			expectedSpec: nil,
			expectedErr:  fmt.Errorf("no subjects found for the ServiceRoleBinding: client-reader-role"),
		},
	}

	for _, c := range cases {
		gotSpec, gotErr := GetServiceRoleBindingSpec(c.input.roleName, c.input.k8sRoleName, c.input.members)
		assert.Equal(t, c.expectedSpec, gotSpec, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
}
