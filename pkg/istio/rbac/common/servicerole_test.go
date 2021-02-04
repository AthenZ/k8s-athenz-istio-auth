// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package common

import (
	"fmt"
	"testing"

	"istio.io/api/rbac/v1alpha1"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
)

func init() {
	log.InitLogger("", "debug")
}

func TestConvertAthenzRoleNameToK8sName(t *testing.T) {
	cases := []struct {
		test     string
		input    string
		expected string
	}{
		{
			test:     "empty",
			input:    "",
			expected: "",
		},
		{
			test:     "role name with underscore",
			input:    "client_reader",
			expected: "client--reader",
		},
		{
			test:     "role name without underscore",
			input:    "client.reader",
			expected: "client.reader",
		},
		{
			test:     "role name with dashes and underscores",
			input:    "client-service_group_reader",
			expected: "client-service--group--reader",
		},
	}
	for _, c := range cases {
		got := ConvertAthenzRoleNameToK8sName(c.input)
		assert.Equal(t, c.expected, got, c.test)
	}
}

func TestGetServiceRoleSpec(t *testing.T) {

	allow := zms.ALLOW
	type input struct {
		domainName zms.DomainName
		roleName   string
		assertions []*zms.Assertion
	}
	cases := []struct {
		test         string
		input        input
		expectedSpec *v1alpha1.ServiceRole
		expectedErr  error
	}{
		{
			test: "empty args",
			input: input{
				domainName: "",
				roleName:   "",
				assertions: nil,
			},
			expectedSpec: nil,
			expectedErr:  fmt.Errorf("no rules found for the ServiceRole: "),
		},
		{
			test: "valid role spec",
			input: input{
				domainName: "athenz.domain",
				roleName:   "client-reader-role",
				assertions: []*zms.Assertion{
					{
						Effect:   &allow,
						Action:   "get",
						Role:     "athenz.domain:role.client-reader-role",
						Resource: "athenz.domain:svc.my-service-name:/protected/path",
					},
				},
			},
			expectedSpec: &v1alpha1.ServiceRole{
				Rules: []*v1alpha1.AccessRule{
					{
						Methods: []string{
							"GET",
						},
						Paths: []string{
							"/protected/path",
						},
						Services: []string{WildCardAll},
						Constraints: []*v1alpha1.AccessRule_Constraint{
							{
								Key: ConstraintSvcKey,
								Values: []string{
									"my-service-name",
								},
							},
						},
					},
				},
			},
			expectedErr: nil,
		},
		{
			test: "valid role spec without path",
			input: input{
				domainName: "athenz.domain",
				roleName:   "client-writer-role",
				assertions: []*zms.Assertion{
					{
						Effect:   &allow,
						Action:   "put",
						Role:     "athenz.domain:role.client-writer-role",
						Resource: "athenz.domain:svc.my-service-name",
					},
				},
			},
			expectedSpec: &v1alpha1.ServiceRole{
				Rules: []*v1alpha1.AccessRule{
					{
						Methods: []string{
							"PUT",
						},
						Services: []string{WildCardAll},
						Constraints: []*v1alpha1.AccessRule_Constraint{
							{
								Key: ConstraintSvcKey,
								Values: []string{
									"my-service-name",
								},
							},
						},
					},
				},
			},
			expectedErr: nil,
		},
	}

	for _, c := range cases {
		gotSpec, gotErr := GetServiceRoleSpec(c.input.domainName, c.input.roleName, c.input.assertions)
		assert.Equal(t, c.expectedSpec, gotSpec, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
}
