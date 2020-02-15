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

func TestMemberToSpiffe(t *testing.T) {

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
		gotMember, gotErr := memberToSpiffe(c.member)
		assert.Equal(t, c.expectedMember, gotMember, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
}

func TestMemberToOriginJwtSubject(t *testing.T) {

	cases := []struct {
		test                  string
		member                *zms.RoleMember
		expectedOriginJwtName string
		expectedErr           error
	}{
		{
			test:                  "nil member",
			member:                nil,
			expectedOriginJwtName: "",
			expectedErr:           fmt.Errorf("member is nil"),
		},
		{
			test: "valid service member",
			member: &zms.RoleMember{
				MemberName: zms.MemberName("client.some-domain.dep-svcA"),
			},
			expectedOriginJwtName: AthenzJwtPrefix + "client.some-domain.dep-svcA",
			expectedErr:           nil,
		},
		{
			test: "valid user member",
			member: &zms.RoleMember{
				MemberName: zms.MemberName("user.somename"),
			},
			expectedOriginJwtName: AthenzJwtPrefix + "user.somename",
			expectedErr:           nil,
		},
		{
			test: "valid wildcard member",
			member: &zms.RoleMember{
				MemberName: zms.MemberName("user.*"),
			},
			expectedOriginJwtName: "*",
			expectedErr:           nil,
		},
	}

	for _, c := range cases {
		gotOriginJwtName, gotErr := memberToOriginJwtSubject(c.member)
		assert.Equal(t, c.expectedOriginJwtName, gotOriginJwtName, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
}

func TestGetServiceRoleBindingSpec(t *testing.T) {

	type input struct {
		athenzDomainName       string
		roleName               string
		k8sRoleName            string
		members                []*zms.RoleMember
		enableOriginJwtSubject bool
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
				athenzDomainName:       "",
				roleName:               "",
				k8sRoleName:            "",
				members:                nil,
				enableOriginJwtSubject: true,
			},
			expectedSpec: nil,
			expectedErr:  fmt.Errorf("empty string found in athenzDomainName:  and roleName: "),
		},
		{
			test: "valid role member spec",
			input: input{
				athenzDomainName: "athenz.domain",
				roleName:         "client-reader_role",
				k8sRoleName:      "client-reader--role",
				members: []*zms.RoleMember{
					{
						MemberName: "athenz.domain.client-serviceA",
					},
					{
						MemberName: "user.athenzuser",
					},
				},
				enableOriginJwtSubject: true,
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
						Properties: map[string]string{
							RequestAuthPrincipalProperty: AthenzJwtPrefix + "athenz.domain.client-serviceA",
						},
					},
					{
						User: "user/sa/athenzuser",
					},
					{
						Properties: map[string]string{
							RequestAuthPrincipalProperty: AthenzJwtPrefix + "user.athenzuser",
						},
					},
					{
						User: "athenz.domain/ra/client-reader_role",
					},
				},
			},
			expectedErr: nil,
		},
		{
			test: "invalid role member spec",
			input: input{
				athenzDomainName: "athenz.domain",
				roleName:         "client-reader_role",
				k8sRoleName:      "client-reader--role",
				members: []*zms.RoleMember{
					{
						MemberName: "not-a-valid-user",
					},
					{
						MemberName: "another-not-valid-service",
					},
				},
				enableOriginJwtSubject: true,
			},
			expectedSpec: &v1alpha1.ServiceRoleBinding{
				RoleRef: &v1alpha1.RoleRef{
					Name: "client-reader--role",
					Kind: ServiceRoleKind,
				},
				Subjects: []*v1alpha1.Subject{
					{
						User: "athenz.domain/ra/client-reader_role",
					},
				},
			},
			expectedErr: nil,
		},
		{
			test: "test valid role member spec with enableOriginJwtSubject set to false",
			input: input{
				athenzDomainName: "athenz.domain",
				roleName:         "client-reader_role",
				k8sRoleName:      "client-reader--role",
				members: []*zms.RoleMember{
					{
						MemberName: "athenz.domain.client-serviceA",
					},
					{
						MemberName: "user.athenzuser",
					},
				},
				enableOriginJwtSubject: false,
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
					{
						User: "athenz.domain/ra/client-reader_role",
					},
				},
			},
			expectedErr: nil,
		},
	}

	for _, c := range cases {
		gotSpec, gotErr := GetServiceRoleBindingSpec(c.input.athenzDomainName, c.input.roleName, c.input.k8sRoleName, c.input.members, c.input.enableOriginJwtSubject)
		assert.Equal(t, c.expectedSpec, gotSpec, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
}
