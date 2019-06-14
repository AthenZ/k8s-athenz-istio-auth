// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package common

import (
	"fmt"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
)

func TestParseRoleFQDN(t *testing.T) {

	cases := []struct {
		test         string
		domainName   zms.DomainName
		roleFQDN     string
		expectedRole string
		expectedErr  error
	}{
		{
			test:         "empty role name",
			domainName:   "athenz.domain",
			roleFQDN:     "",
			expectedRole: "",
			expectedErr:  nil,
		},
		{
			test:         "valid role name",
			domainName:   "athenz.domain",
			roleFQDN:     "athenz.domain:role.reader-role",
			expectedRole: "reader-role",
			expectedErr:  nil,
		},
		{
			test:         "role belonging to another domain",
			domainName:   "athenz.domain",
			roleFQDN:     "another-domain:role.reader-role",
			expectedRole: "",
			expectedErr:  fmt.Errorf("role: another-domain:role.reader-role does not belong to the Athenz domain: athenz.domain"),
		},
	}

	for _, c := range cases {
		gotRole, gotErr := ParseRoleFQDN(c.domainName, c.roleFQDN)
		assert.Equal(t, c.expectedRole, gotRole, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
}

func TestPrincipalToSPIFFE(t *testing.T) {

	cases := []struct {
		test           string
		principal      string
		expectedSpiffe string
		expectedErr    error
	}{
		{
			test:           "empty principal",
			principal:      "",
			expectedSpiffe: "",
			expectedErr:    fmt.Errorf("principal is empty"),
		},
		{
			test:           "valid service principal",
			principal:      "client.some-domain.dep-svcA",
			expectedSpiffe: "client.some-domain/sa/dep-svcA",
			expectedErr:    nil,
		},
		{
			test:           "valid user principal",
			principal:      "user.myname",
			expectedSpiffe: "user/sa/myname",
			expectedErr:    nil,
		},
		{
			test:           "invalid principal",
			principal:      "someuser",
			expectedSpiffe: "",
			expectedErr:    fmt.Errorf("principal:someuser is not of the format <Athenz-domain>.<Athenz-service>"),
		},
	}

	for _, c := range cases {
		gotSpiffe, gotErr := PrincipalToSpiffe(c.principal)
		assert.Equal(t, c.expectedSpiffe, gotSpiffe, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
}

func TestNewConfig(t *testing.T) {

	type input struct {
		configType string
		namespace  string
		name       string
		spec       proto.Message
	}
	cases := []struct {
		test           string
		input          input
		expectedConfig model.Config
	}{
		{
			test: "empty args",
			input: input{
				configType: "",
				namespace:  "",
				name:       "",
				spec:       &v1alpha1.ServiceRoleBinding{},
			},
			expectedConfig: model.Config{},
		},
		{
			test: "valid servicerole",
			input: input{
				configType: model.ServiceRole.Type,
				namespace:  "athenz-ns",
				name:       "my-reader-role",
				spec: &v1alpha1.ServiceRole{
					Rules: []*v1alpha1.AccessRule{
						{
							Constraints: []*v1alpha1.AccessRule_Constraint{
								{
									Key: "destination.labels[svc]",
									Values: []string{
										"my-backend-service",
									},
								},
							},
						},
					},
				},
			},
			expectedConfig: model.Config{
				ConfigMeta: model.ConfigMeta{
					Type:      model.ServiceRole.Type,
					Group:     model.ServiceRole.Group + model.IstioAPIGroupDomain,
					Version:   model.ServiceRole.Version,
					Namespace: "athenz-ns",
					Name:      "my-reader-role",
				},
				Spec: &v1alpha1.ServiceRole{
					Rules: []*v1alpha1.AccessRule{
						{
							Constraints: []*v1alpha1.AccessRule_Constraint{
								{
									Key: "destination.labels[svc]",
									Values: []string{
										"my-backend-service",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			test: "valid servicerolebinding",
			input: input{
				configType: model.ServiceRoleBinding.Type,
				namespace:  "athenz-ns",
				name:       "my-reader-role",
				spec: &v1alpha1.ServiceRoleBinding{
					RoleRef: &v1alpha1.RoleRef{
						Name: "client-reader-role",
						Kind: model.ServiceRole.Type,
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
			},
			expectedConfig: model.Config{
				ConfigMeta: model.ConfigMeta{
					Type:      model.ServiceRoleBinding.Type,
					Group:     model.ServiceRoleBinding.Group + model.IstioAPIGroupDomain,
					Version:   model.ServiceRoleBinding.Version,
					Namespace: "athenz-ns",
					Name:      "my-reader-role",
				},
				Spec: &v1alpha1.ServiceRoleBinding{
					RoleRef: &v1alpha1.RoleRef{
						Name: "client-reader-role",
						Kind: model.ServiceRole.Type,
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
			},
		},
		{
			test: "invalid config type",
			input: input{
				configType: "InvalidCustomResource",
				namespace:  "athenz-ns",
				name:       "my-reader-role",
				spec: &v1alpha1.ServiceRoleBinding{
					RoleRef: &v1alpha1.RoleRef{
						Name: "client-reader-role",
						Kind: model.ServiceRole.Type,
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
			},
			expectedConfig: model.Config{},
		},
	}

	for _, c := range cases {
		gotConfig := NewConfig(c.input.configType, c.input.namespace, c.input.name, c.input.spec)
		assert.Equal(t, c.expectedConfig, gotConfig, c.test)
	}
}
