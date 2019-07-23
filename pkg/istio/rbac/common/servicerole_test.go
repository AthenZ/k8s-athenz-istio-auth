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

func TestParseAssertionEffect(t *testing.T) {

	allow := zms.ALLOW
	deny := zms.DENY
	cases := []struct {
		test           string
		assertion      *zms.Assertion
		expectedEffect string
		expectedErr    error
	}{
		{
			test:           "empty assertion",
			assertion:      nil,
			expectedEffect: "",
			expectedErr:    fmt.Errorf("assertion is nil"),
		},
		{
			test:           "empty assertion effect",
			assertion:      &zms.Assertion{},
			expectedEffect: "",
			expectedErr:    fmt.Errorf("assertion effect is nil"),
		},
		{
			test: "valid effect",
			assertion: &zms.Assertion{
				Effect: &allow,
			},
			expectedEffect: "ALLOW",
			expectedErr:    nil,
		},
		{
			test: "invalid(unsupported) effect",
			assertion: &zms.Assertion{
				Effect: &deny,
			},
			expectedEffect: "",
			expectedErr:    fmt.Errorf("effect: DENY is not a supported assertion effect"),
		},
	}

	for _, c := range cases {
		gotAssertion, gotErr := parseAssertionEffect(c.assertion)
		assert.Equal(t, c.expectedEffect, gotAssertion, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
}

func TestParseAssertionAction(t *testing.T) {

	cases := []struct {
		test           string
		assertion      *zms.Assertion
		expectedAction string
		expectedErr    error
	}{
		{
			test:           "empty assertion",
			assertion:      nil,
			expectedAction: "",
			expectedErr:    fmt.Errorf("assertion is nil"),
		},
		{
			test: "valid action",
			assertion: &zms.Assertion{
				Action: "get",
			},
			expectedAction: "GET",
			expectedErr:    nil,
		},
		{
			test: "valid action POST",
			assertion: &zms.Assertion{
				Action: "POST",
			},
			expectedAction: "POST",
			expectedErr:    nil,
		},
		{
			test: "valid action wildcard *",
			assertion: &zms.Assertion{
				Action: "*",
			},
			expectedAction: "*",
			expectedErr:    nil,
		},
		{
			test: "invalid action",
			assertion: &zms.Assertion{
				Action: "launch",
			},
			expectedAction: "",
			expectedErr:    fmt.Errorf("method: launch is not a supported HTTP method"),
		},
	}

	for _, c := range cases {
		gotAssertion, gotErr := parseAssertionAction(c.assertion)
		assert.Equal(t, c.expectedAction, gotAssertion, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
}

func TestParseAssertionResource(t *testing.T) {

	cases := []struct {
		test         string
		domainName   zms.DomainName
		assertion    *zms.Assertion
		expectedSvc  string
		expectedPath string
		expectedErr  error
	}{
		{
			test:         "empty assertion",
			domainName:   "athenz.domain",
			assertion:    nil,
			expectedSvc:  "",
			expectedPath: "",
			expectedErr:  fmt.Errorf("assertion is nil"),
		},
		{
			test:       "valid resource spec",
			domainName: "athenz.domain",
			assertion: &zms.Assertion{
				Resource: "athenz.domain:svc.my-backend-service:/protected/endpoint",
			},
			expectedSvc:  "my-backend-service",
			expectedPath: "/protected/endpoint",
			expectedErr:  nil,
		},
		{
			test:       "resource specifying valid service without endpoint",
			domainName: "athenz.domain",
			assertion: &zms.Assertion{
				Resource: "athenz.domain:svc.my-backend-service",
			},
			expectedSvc:  "my-backend-service",
			expectedPath: "",
			expectedErr:  nil,
		},
		{
			test:       "resource specifying service of another domain",
			domainName: "athenz.domain",
			assertion: &zms.Assertion{
				Resource: "some.other.athenz.domain:svc.my-backend-service:/protected/endpoint",
			},
			expectedSvc:  "",
			expectedPath: "",
			expectedErr: fmt.Errorf("resource: some.other.athenz.domain:svc.my-backend-service:/protected/endpoint" +
				" does not belong to the Athenz domain: athenz.domain"),
		},
		{
			test:       "resource not specifying a service in required format",
			domainName: "athenz.domain",
			assertion: &zms.Assertion{
				Resource: "athenz.domain:service.my-backend-service:/protected/endpoint",
			},
			expectedSvc:  "",
			expectedPath: "",
			expectedErr: fmt.Errorf("resource: athenz.domain:service.my-backend-service:/protected/endpoint does " +
				"not specify the service using svc.<service-name> format"),
		},
	}

	for _, c := range cases {
		gotSvc, gotPath, gotErr := parseAssertionResource(c.domainName, c.assertion)
		assert.Equal(t, c.expectedSvc, gotSvc, c.test)
		assert.Equal(t, c.expectedPath, gotPath, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
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
