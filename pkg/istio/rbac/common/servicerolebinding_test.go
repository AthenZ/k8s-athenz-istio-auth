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

func TestGetServiceRoleBindingSpec(t *testing.T) {

	type input struct {
		athenzDomainName        string
		roleName                string
		k8sRoleName             string
		members                 []*zms.RoleMember
		enableOriginJwtSubject  bool
		enableSpiffeTrustDomain bool
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
				athenzDomainName:        "",
				roleName:                "",
				k8sRoleName:             "",
				members:                 nil,
				enableOriginJwtSubject:  true,
				enableSpiffeTrustDomain: true,
			},
			expectedSpec: nil,
			expectedErr:  fmt.Errorf("athenzDomainName is empty"),
		},
		{
			test: "empty roleName args",
			input: input{
				athenzDomainName:        "abc",
				roleName:                "",
				k8sRoleName:             "",
				members:                 nil,
				enableOriginJwtSubject:  true,
				enableSpiffeTrustDomain: true,
			},
			expectedSpec: nil,
			expectedErr:  fmt.Errorf("roleName is empty"),
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
				enableOriginJwtSubject:  true,
				enableSpiffeTrustDomain: true,
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
				enableOriginJwtSubject:  true,
				enableSpiffeTrustDomain: true,
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
				enableOriginJwtSubject:  false,
				enableSpiffeTrustDomain: true,
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
