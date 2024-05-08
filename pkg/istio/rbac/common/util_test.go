// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package common

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	"istio.io/api/rbac/v1alpha1"
	"istio.io/api/security/v1beta1"
	workloadv1beta1 "istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/collection"
	"istio.io/istio/pkg/config/schema/collections"
)

var (
	isNotSystemDisabled, isSystemDisabled int32 = 0, 1
)

func TestPrincipalToSPIFFE(t *testing.T) {
	cases := []struct {
		test                    string
		principal               string
		enableSpiffeTrustDomain bool
		expectedSpiffe          string
		expectedErr             error
	}{
		{
			test:           "empty principal",
			principal:      "",
			expectedSpiffe: "",
			expectedErr:    fmt.Errorf("principal is empty"),
		},
		{
			test:                    "valid service principal",
			principal:               "client.some-domain.dep-svcA",
			enableSpiffeTrustDomain: true,
			expectedSpiffe:          "client.some-domain/sa/dep-svcA",
			expectedErr:             nil,
		},
		{
			test:                    "valid user principal",
			principal:               "user.myname",
			enableSpiffeTrustDomain: true,
			expectedSpiffe:          "user/sa/myname",
			expectedErr:             nil,
		},
		{
			test:                    "invalid principal",
			principal:               "someuser",
			enableSpiffeTrustDomain: true,
			expectedSpiffe:          "",
			expectedErr:             fmt.Errorf("principal:someuser is not of the format <Athenz-domain>.<Athenz-service>"),
		},
	}

	for _, c := range cases {
		actualSpiffee, err := PrincipalToSpiffe(c.principal)

		assert.Equal(t, c.expectedSpiffe, actualSpiffee, c.test)
		assert.Equal(t, c.expectedErr, err, c.test)
	}
}

func TestPrincipalToTrustDomainSPIFFE(t *testing.T) {
	cases := []struct {
		test                    string
		principal               string
		enableSpiffeTrustDomain bool
		expectedSpiffe          []string
		expectedErr             error
		systemNamespaces        []string
		customServiceMap        map[string]string
		adminDomains            []string
	}{
		{
			test:           "empty principal",
			principal:      "",
			expectedSpiffe: nil,
			expectedErr:    fmt.Errorf("principal is empty"),
		},
		{
			test:                    "valid service principal",
			principal:               "client.some-domain.dep-svcA",
			enableSpiffeTrustDomain: true,
			expectedSpiffe: []string{
				"athenz.cloud/ns/client-some--domain/sa/client.some-domain.dep-svcA",
				"athenz.cloud/ns/default/sa/client.some-domain.dep-svcA",
			},
			expectedErr: nil,
		},
		{
			test:                    "valid service principal with system namespace",
			principal:               "client.some-domain.dep-svcA",
			enableSpiffeTrustDomain: true,
			expectedSpiffe: []string{
				"athenz.cloud/ns/some-domain/sa/client.some-domain.dep-svcA",
				"athenz.cloud/ns/default/sa/client.some-domain.dep-svcA",
			},
			expectedErr:      nil,
			systemNamespaces: []string{"some-domain"},
			adminDomains:     []string{"client"},
		},
		{
			test:                    "valid user principal",
			principal:               "k8s.omega.stage1-bf1.istio-system.istio-ingressgateway",
			enableSpiffeTrustDomain: true,
			expectedSpiffe: []string{
				"athenz.cloud/ns/istio-system/sa/k8s.omega.stage1-bf1.istio-system.istio-ingressgateway",
				"athenz.cloud/ns/default/sa/k8s.omega.stage1-bf1.istio-system.istio-ingressgateway",
			},
			expectedErr:      nil,
			systemNamespaces: []string{"istio-system"},
			adminDomains:     []string{"k8s.omega.stage1-bf1"},
		},
		{
			test:                    "valid user principal for cloud",
			principal:               "k8s.omega.stage1-bf1.istio-ingressgateway",
			enableSpiffeTrustDomain: true,
			expectedSpiffe: []string{
				"athenz.cloud/ns/istio-system/sa/k8s.omega.stage1-bf1.istio-ingressgateway",
				"athenz.cloud/ns/default/sa/k8s.omega.stage1-bf1.istio-ingressgateway",
			},
			expectedErr:      nil,
			systemNamespaces: []string{"istio-system"},
			customServiceMap: map[string]string{"istio-ingressgateway": "istio-system"},
			adminDomains:     []string{"k8s.omega.stage1-bf1"},
		},
		{
			test:                    "invalid principal",
			principal:               "someuser",
			enableSpiffeTrustDomain: true,
			expectedSpiffe:          nil,
			expectedErr:             fmt.Errorf("principal:someuser is not of the format <Athenz-domain>.<Athenz-service>"),
		},
	}

	for _, c := range cases {
		adminDomainNamespaceMap := GetAdminDomainNamespaceMap(c.systemNamespaces, c.adminDomains)
		adminPrincipleNamespaceMap := GetAdminPrincipleNamespaceMap(c.customServiceMap, c.adminDomains)
		actualSpiffee, err := PrincipalToTrustDomainSpiffe(c.principal, adminDomainNamespaceMap, adminPrincipleNamespaceMap)

		assert.Equal(t, c.expectedSpiffe, actualSpiffee, c.test)
		assert.Equal(t, c.expectedErr, err, c.test)
	}
}

func TestMemberToSpiffe(t *testing.T) {

	cases := []struct {
		test             string
		member           interface{}
		expectedMember   []string
		expectedErr      error
		systemNamespaces []string
		adminDomains     []string
	}{
		{
			test:           "nil member",
			member:         nil,
			expectedMember: nil,
			expectedErr:    fmt.Errorf("member is nil"),
		},
		{
			test: "valid service member",
			member: &zms.RoleMember{
				MemberName: zms.MemberName("client.some-domain.dep-svcA"),
			},
			expectedMember: []string{
				"client.some-domain/sa/dep-svcA",
				"athenz.cloud/ns/client-some--domain/sa/client.some-domain.dep-svcA",
				"athenz.cloud/ns/default/sa/client.some-domain.dep-svcA",
			},
			expectedErr: nil,
		},
		{
			test: "valid user member",
			member: &zms.RoleMember{
				MemberName: zms.MemberName("user.somename"),
			},
			expectedMember: []string{
				"user/sa/somename",
				"athenz.cloud/ns/user/sa/user.somename",
				"athenz.cloud/ns/default/sa/user.somename",
			},
			expectedErr: nil,
		},
		{
			test: "valid wildcard member",
			member: &zms.RoleMember{
				MemberName: zms.MemberName("user.*"),
			},
			expectedMember: []string{"*"},
			expectedErr:    nil,
		},
		{
			test: "invalid member",
			member: &zms.RoleMember{
				MemberName: zms.MemberName("not-a-valid-principal"),
			},
			expectedMember: nil,
			expectedErr:    fmt.Errorf("principal:not-a-valid-principal is not of the format <Athenz-domain>.<Athenz-service>"),
		},
		{
			test: "valid service member in group",
			member: &zms.GroupMember{
				MemberName: zms.GroupMemberName("client.some-domain.dep-svcA"),
			},
			expectedMember: []string{
				"client.some-domain/sa/dep-svcA",
				"athenz.cloud/ns/client-some--domain/sa/client.some-domain.dep-svcA",
				"athenz.cloud/ns/default/sa/client.some-domain.dep-svcA",
			},
			expectedErr: nil,
		},
		{
			test: "valid user member in group",
			member: &zms.GroupMember{
				MemberName: zms.GroupMemberName("user.somename"),
			},
			expectedMember: []string{
				"user/sa/somename",
				"athenz.cloud/ns/user/sa/user.somename",
				"athenz.cloud/ns/default/sa/user.somename",
			},
			expectedErr: nil,
		},
		{
			test: "valid user member in group with system namespace",
			member: &zms.GroupMember{
				MemberName: zms.GroupMemberName("client.istio-system.dep-svcA"),
			},
			expectedMember: []string{
				"client.istio-system/sa/dep-svcA",
				"athenz.cloud/ns/istio-system/sa/client.istio-system.dep-svcA",
				"athenz.cloud/ns/default/sa/client.istio-system.dep-svcA",
			},
			expectedErr:      nil,
			systemNamespaces: []string{"istio-system"},
			adminDomains:     []string{"client"},
		},
		{
			test: "valid wildcard member in group",
			member: &zms.GroupMember{
				MemberName: zms.GroupMemberName("user.*"),
			},
			expectedMember: []string{"*"},
			expectedErr:    nil,
		},
		{
			test: "invalid member",
			member: &zms.GroupMember{
				MemberName: zms.GroupMemberName("not-a-valid-principal"),
			},
			expectedMember: nil,
			expectedErr:    fmt.Errorf("principal:not-a-valid-principal is not of the format <Athenz-domain>.<Athenz-service>"),
		},
	}

	for _, c := range cases {
		adminDomainNamespaceMap := GetAdminDomainNamespaceMap(c.systemNamespaces, c.adminDomains)
		actualMember, err := MemberToSpiffe(c.member, true, adminDomainNamespaceMap, map[string]string{})
		assert.Equal(t, c.expectedMember, actualMember, c.test)
		assert.Equal(t, c.expectedErr, err, c.test)
	}
}

func TestMemberToOriginJwtSubject(t *testing.T) {

	cases := []struct {
		test                  string
		member                interface{}
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
		{
			test: "valid service member in group",
			member: &zms.GroupMember{
				MemberName: zms.GroupMemberName("client.some-domain.dep-svcA"),
			},
			expectedOriginJwtName: AthenzJwtPrefix + "client.some-domain.dep-svcA",
			expectedErr:           nil,
		},
		{
			test: "valid user member in group",
			member: &zms.GroupMember{
				MemberName: zms.GroupMemberName("user.somename"),
			},
			expectedOriginJwtName: AthenzJwtPrefix + "user.somename",
			expectedErr:           nil,
		},
		{
			test: "valid wildcard member in group",
			member: &zms.GroupMember{
				MemberName: zms.GroupMemberName("user.*"),
			},
			expectedOriginJwtName: "*",
			expectedErr:           nil,
		},
	}

	for _, c := range cases {
		gotOriginJwtName, gotErr := MemberToOriginJwtSubject(c.member)
		assert.Equal(t, c.expectedOriginJwtName, gotOriginJwtName, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
}

func TestGetMemberName(t *testing.T) {

	cases := []struct {
		test         string
		member       interface{}
		expectedName string
	}{
		{
			test: "valid role member",
			member: &zms.RoleMember{
				MemberName: zms.MemberName("client.some-domain.dep-svcA"),
			},
			expectedName: "client.some-domain.dep-svcA",
		},
		{
			test: "valid group member",
			member: &zms.GroupMember{
				MemberName: zms.GroupMemberName("user.somename"),
			},
			expectedName: "user.somename",
		},
		{
			test:         "valid tag value",
			member:       zms.CompoundName("user.somename"),
			expectedName: "user.somename",
		},
		{
			test:         "invalid group member",
			member:       nil,
			expectedName: "",
		},
	}

	for _, c := range cases {
		memberName := GetMemberName(c.member)
		assert.Equal(t, c.expectedName, memberName, c.test)
	}
}

func TestGetMemberExpiry(t *testing.T) {
	timestamp, err := rdl.TimestampParse("2001-01-25T03:32:15.245Z")
	if err != nil {
		panic(err)
	}

	cases := []struct {
		test               string
		member             interface{}
		expectedExpiration *rdl.Timestamp
	}{
		{
			test: "valid role member",
			member: &zms.RoleMember{
				MemberName: zms.MemberName("client.some-domain.dep-svcA"),
				Expiration: &timestamp,
			},
			expectedExpiration: &timestamp,
		},
		{
			test: "valid group member",
			member: &zms.GroupMember{
				MemberName: zms.GroupMemberName("user.somename"),
				Expiration: &timestamp,
			},
			expectedExpiration: &timestamp,
		},
		{
			test:               "invalid group member",
			member:             nil,
			expectedExpiration: nil,
		},
	}

	for _, c := range cases {
		expiry := getMemberExpiry(c.member)
		assert.Equal(t, c.expectedExpiration, expiry, c.test)
	}
}

func TestGetMemberSystemDisabled(t *testing.T) {

	cases := []struct {
		test                   string
		member                 interface{}
		expectedSystemDisabled *int32
	}{
		{
			test: "valid role member",
			member: &zms.RoleMember{
				MemberName:     zms.MemberName("client.some-domain.dep-svcA"),
				SystemDisabled: &isSystemDisabled,
			},
			expectedSystemDisabled: &isSystemDisabled,
		},
		{
			test: "valid group member",
			member: &zms.GroupMember{
				MemberName:     zms.GroupMemberName("user.somename"),
				SystemDisabled: &isNotSystemDisabled,
			},
			expectedSystemDisabled: &isNotSystemDisabled,
		},
		{
			test:                   "invalid group member",
			member:                 nil,
			expectedSystemDisabled: nil,
		},
	}

	for _, c := range cases {
		systemDisabled := getMemberSystemDisabled(c.member)
		assert.Equal(t, c.expectedSystemDisabled, systemDisabled, c.test)
	}
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
		gotAssertion, gotErr := ParseAssertionEffect(c.assertion)
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
		gotAssertion, gotErr := ParseAssertionAction(c.assertion)
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
		gotSvc, gotPath, gotErr := ParseAssertionResource(c.domainName, c.assertion)
		assert.Equal(t, c.expectedSvc, gotSvc, c.test)
		assert.Equal(t, c.expectedPath, gotPath, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
	}
}

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

func TestNewConfig(t *testing.T) {

	type input struct {
		configType collection.Schema
		namespace  string
		name       string
		spec       proto.Message
	}
	cases := []struct {
		test           string
		input          input
		expectedConfig model.Config
	}{
		// deleted empty config test because collections library doesn't have empty schema
		// build empty schema from scratch results in invalid type error
		{
			test: "valid servicerole",
			input: input{
				configType: collections.IstioRbacV1Alpha1Serviceroles,
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
					Type:      collections.IstioRbacV1Alpha1Serviceroles.Resource().Kind(),
					Group:     collections.IstioRbacV1Alpha1Serviceroles.Resource().Group(),
					Version:   collections.IstioRbacV1Alpha1Serviceroles.Resource().Version(),
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
				configType: collections.IstioRbacV1Alpha1Servicerolebindings,
				namespace:  "athenz-ns",
				name:       "my-reader-role",
				spec: &v1alpha1.ServiceRoleBinding{
					RoleRef: &v1alpha1.RoleRef{
						Name: "client-reader-role",
						Kind: collections.IstioRbacV1Alpha1Servicerolebindings.Resource().Kind(),
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
					Type:      collections.IstioRbacV1Alpha1Servicerolebindings.Resource().Kind(),
					Group:     collections.IstioRbacV1Alpha1Servicerolebindings.Resource().Group(),
					Version:   collections.IstioRbacV1Alpha1Servicerolebindings.Resource().Version(),
					Namespace: "athenz-ns",
					Name:      "my-reader-role",
				},
				Spec: &v1alpha1.ServiceRoleBinding{
					RoleRef: &v1alpha1.RoleRef{
						Name: "client-reader-role",
						Kind: collections.IstioRbacV1Alpha1Servicerolebindings.Resource().Kind(),
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
			// istio 1.5.8 library removes support for initializing invalid config type, switch to mock type
			test: "mock config type",
			input: input{
				configType: collections.Mock,
				namespace:  "athenz-ns",
				name:       "my-reader-role",
				spec: &v1alpha1.ServiceRoleBinding{
					RoleRef: &v1alpha1.RoleRef{
						Name: "client-reader-role",
						Kind: collections.IstioRbacV1Alpha1Serviceroles.Resource().Kind(),
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
					Type:      collections.Mock.Resource().Kind(),
					Group:     collections.Mock.Resource().Group(),
					Version:   collections.Mock.Resource().Version(),
					Namespace: "athenz-ns",
					Name:      "my-reader-role",
				},
				Spec: &v1alpha1.ServiceRoleBinding{
					RoleRef: &v1alpha1.RoleRef{
						Name: "client-reader-role",
						Kind: collections.IstioRbacV1Alpha1Serviceroles.Resource().Kind(),
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
	}

	for _, c := range cases {
		gotConfig := NewConfig(c.input.configType, c.input.namespace, c.input.name, c.input.spec)
		assert.Equal(t, c.expectedConfig, gotConfig, c.test)
	}
}

func newSr(ns, role string) model.Config {
	srSpec := &v1alpha1.ServiceRole{
		Rules: []*v1alpha1.AccessRule{
			{
				Services: []string{WildCardAll},
				Methods:  []string{"GET"},
				Constraints: []*v1alpha1.AccessRule_Constraint{
					{
						Key:    ConstraintSvcKey,
						Values: []string{"test-svc"},
					},
				},
			},
		},
	}
	return NewConfig(collections.IstioRbacV1Alpha1Serviceroles, ns, role, srSpec)
}

func newSrb(ns, role string) model.Config {
	srbSpec := &v1alpha1.ServiceRoleBinding{
		RoleRef: &v1alpha1.RoleRef{
			Kind: ServiceRoleKind,
			Name: role,
		},
		Subjects: []*v1alpha1.Subject{
			{
				User: "test-user",
			},
		},
	}
	return NewConfig(collections.IstioRbacV1Alpha1Servicerolebindings, ns, role, srbSpec)
}

func TestConvertSliceToKeyedMap(t *testing.T) {
	tests := []struct {
		name     string
		in       []model.Config
		expected map[string]model.Config
	}{
		{
			name:     "should return empty map for empty slice",
			in:       []model.Config{},
			expected: map[string]model.Config{},
		},
		{
			name: "should return correctly keyed map",
			in: []model.Config{
				newSr("my-ns", "this-role"),
				newSrb("my-ns", "this-role"),
			},
			expected: map[string]model.Config{
				"ServiceRole/my-ns/this-role":        newSr("my-ns", "this-role"),
				"ServiceRoleBinding/my-ns/this-role": newSrb("my-ns", "this-role"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := ConvertSliceToKeyedMap(tt.in)
			assert.Equal(t, tt.expected, actual, "returned map should match the expected map")
		})
	}
}

func TestCheckAthenzMemberExpiry(t *testing.T) {
	tests := []struct {
		athenzMember zms.RoleMember
		expectedRes  bool
		expectedErr  error
	}{
		{
			athenzMember: zms.RoleMember{
				MemberName: "user.expired",
				Expiration: &rdl.Timestamp{
					Time: time.Now().Add(-time.Hour),
				},
			},
			expectedRes: false,
			expectedErr: fmt.Errorf("member user.expired is expired"),
		},
		{
			athenzMember: zms.RoleMember{
				MemberName: "user.valid",
				Expiration: &rdl.Timestamp{
					Time: time.Now().Add(time.Hour),
				},
			},
			expectedRes: true,
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		actual, err := CheckAthenzMemberExpiry(&tt.athenzMember)
		assert.Equal(t, tt.expectedRes, actual, "check member expiry result should be equal to expected result")
		assert.Equal(t, tt.expectedErr, err, "error should be equal")
	}
}

func TestCheckAthenzSystemDisabled(t *testing.T) {
	tests := []struct {
		athenzMember zms.RoleMember
		expectedRes  bool
		expectedErr  error
	}{
		{
			athenzMember: zms.RoleMember{
				MemberName:     "user.expired",
				SystemDisabled: &isSystemDisabled,
			},
			expectedRes: false,
			expectedErr: fmt.Errorf("member user.expired is system disabled"),
		},
		{
			athenzMember: zms.RoleMember{
				MemberName:     "user.valid",
				SystemDisabled: &isNotSystemDisabled,
			},
			expectedRes: true,
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		actual, err := CheckAthenzSystemDisabled(&tt.athenzMember)
		assert.Equal(t, tt.expectedRes, actual, "check member system disabled result should be equal to expected result")
		assert.Equal(t, tt.expectedErr, err, "error should be equal")
	}
}

func TestComputeChangeList(t *testing.T) {

	cbHandler := func(err error, item *Item) error {
		return err
	}

	type input struct {
		current   []model.Config
		desired   []model.Config
		cbHandler OnCompleteFunc
	}
	tests := []struct {
		name           string
		input          input
		expectedOutput []Item
	}{
		{
			name:           "should return empty change list for empty current and desired list",
			input:          input{},
			expectedOutput: make([]Item, 0),
		},
		{
			name: "should add create operations for new items on the desired list",
			input: input{
				current: []model.Config{},
				desired: []model.Config{
					newSr("test-ns", "svc-role"),
					newSrb("test-ns", "svc-role"),
				},
				cbHandler: cbHandler,
			},
			expectedOutput: []Item{
				{
					Operation:       model.EventAdd,
					Resource:        newSr("test-ns", "svc-role"),
					CallbackHandler: cbHandler,
				},
				{
					Operation:       model.EventAdd,
					Resource:        newSrb("test-ns", "svc-role"),
					CallbackHandler: cbHandler,
				},
			},
		},
		{
			name: "should add update operations for changed items on the desired list",
			input: input{
				current: []model.Config{
					newSr("test-ns", "svc-role"),
					newSrb("test-ns", "svc-role"),
					newSr("another-ns", "backend-writer"),
					newSrb("another-ns", "backend-writer"),
				},
				desired: []model.Config{
					updatedSr("test-ns", "svc-role"),
					updatedSrb("test-ns", "svc-role"),
					newSr("another-ns", "backend-writer"),
					newSrb("another-ns", "backend-writer"),
				},
				cbHandler: cbHandler,
			},
			expectedOutput: []Item{
				{
					Operation:       model.EventUpdate,
					Resource:        updatedSr("test-ns", "svc-role"),
					CallbackHandler: cbHandler,
				},
				{
					Operation:       model.EventUpdate,
					Resource:        updatedSrb("test-ns", "svc-role"),
					CallbackHandler: cbHandler,
				},
			},
		},
		{
			name: "should add delete operation for deleted items on the desired list",
			input: input{
				current: []model.Config{
					newSr("test-ns", "svc-role"),
					newSrb("test-ns", "svc-role"),
				},
				desired:   []model.Config{},
				cbHandler: cbHandler,
			},
			expectedOutput: []Item{
				{
					Operation:       model.EventDelete,
					Resource:        newSr("test-ns", "svc-role"),
					CallbackHandler: cbHandler,
				},
				{
					Operation:       model.EventDelete,
					Resource:        newSrb("test-ns", "svc-role"),
					CallbackHandler: cbHandler,
				},
			},
		},
		{
			name: "should add create,update and delete operations based on the desired list",
			input: input{
				current: []model.Config{
					newSr("test-ns", "svc-role"),
					newSrb("test-ns", "svc-role"),
					newSr("some-ns", "frontend-reader"),
					newSrb("some-ns", "frontend-reader"),
				},
				desired: []model.Config{
					updatedSr("test-ns", "svc-role"),
					updatedSrb("test-ns", "svc-role"),
					newSr("another-ns", "backend-writer"),
					newSrb("another-ns", "backend-writer"),
				},
				cbHandler: cbHandler,
			},
			expectedOutput: []Item{
				{
					Operation:       model.EventUpdate,
					Resource:        updatedSr("test-ns", "svc-role"),
					CallbackHandler: cbHandler,
				},
				{
					Operation:       model.EventUpdate,
					Resource:        updatedSrb("test-ns", "svc-role"),
					CallbackHandler: cbHandler,
				},
				{
					Operation:       model.EventAdd,
					Resource:        updatedSr("another-ns", "backend-writer"),
					CallbackHandler: cbHandler,
				},
				{
					Operation:       model.EventAdd,
					Resource:        updatedSrb("another-ns", "backend-writer"),
					CallbackHandler: cbHandler,
				},
				{
					Operation:       model.EventDelete,
					Resource:        newSr("some-ns", "frontend-reader"),
					CallbackHandler: cbHandler,
				},
				{
					Operation:       model.EventDelete,
					Resource:        newSrb("some-ns", "frontend-reader"),
					CallbackHandler: cbHandler,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualChangeList := ComputeChangeList(tt.input.current, tt.input.desired, tt.input.cbHandler, nil)
			assert.Equal(t, len(tt.expectedOutput), len(actualChangeList), "len(expectedChangeList) and len(actualChangeList) should match")
			for i, expectedItem := range tt.expectedOutput {
				assert.Equal(t, expectedItem.Operation, actualChangeList[i].Operation, fmt.Sprintf("operation on changelist[%d] does not match with expected", i))
				assert.Equal(t, expectedItem.Operation, actualChangeList[i].Operation, fmt.Sprintf("operation on changelist[%d] does not match with expected", i))
			}
		})
	}
}

func updatedSr(ns, role string) model.Config {
	srSpec := &v1alpha1.ServiceRole{
		Rules: []*v1alpha1.AccessRule{
			{
				Services: []string{WildCardAll},
				Methods:  []string{"GET"},
				Constraints: []*v1alpha1.AccessRule_Constraint{
					{
						Key:    ConstraintSvcKey,
						Values: []string{"test-svc"},
					},
				},
			},
			{
				Services: []string{WildCardAll},
				Methods:  []string{"POST"},
				Constraints: []*v1alpha1.AccessRule_Constraint{
					{
						Key:    ConstraintSvcKey,
						Values: []string{"test-svc"},
					},
				},
			},
		},
	}
	return NewConfig(collections.IstioRbacV1Alpha1Serviceroles, ns, role, srSpec)
}

func updatedSrb(ns, role string) model.Config {
	srbSpec := &v1alpha1.ServiceRoleBinding{
		RoleRef: &v1alpha1.RoleRef{
			Kind: ServiceRoleKind,
			Name: role,
		},
		Subjects: []*v1alpha1.Subject{
			{
				User: "test-user",
			},
			{
				User: "another.client.user",
			},
		},
	}
	return NewConfig(collections.IstioRbacV1Alpha1Servicerolebindings, ns, role, srbSpec)
}

func TestEqual(t *testing.T) {
	tests := []struct {
		name     string
		in1      model.Config
		in2      model.Config
		expected bool
	}{
		{
			name:     "should return true for empty model.Config items",
			in1:      model.Config{},
			in2:      model.Config{},
			expected: true,
		},
		{
			name:     "should return false for different model.Config item names but same spec",
			in1:      newSr("test-ns", "my-role"),
			in2:      newSr("test-ns", "another-role"),
			expected: false,
		},
		{
			name:     "should return false for different model.Config item names and different spec",
			in1:      newSr("test-ns", "my-role"),
			in2:      updatedSr("test-ns", "another-role"),
			expected: false,
		},
		{
			name:     "should return false for same model.Config item names but different spec",
			in1:      newSr("test-ns", "my-role"),
			in2:      updatedSr("test-ns", "my-role"),
			expected: false,
		},
		{
			name:     "should return false for different model.Config item types but same names",
			in1:      newSr("test-ns", "my-role"),
			in2:      newSrb("test-ns", "my-role"),
			expected: false,
		},
		{
			name:     "should return true for same model.Config item names and spec",
			in1:      newSr("test-ns", "my-role"),
			in2:      newSr("test-ns", "my-role"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Equal(tt.in1, tt.in2)
			assert.Equal(t, tt.expected, actual, "comparison result should be equal to expected")
		})
	}
}

func TestDryrunResource(t *testing.T) {
	eHandler := DryRunHandler{}
	tests := []struct {
		item     Item
		fileName string
		expErr   error
	}{
		{
			item:     getAuthzPolicyItem(model.EventAdd),
			fileName: "test-namespace/onboarded-service.yaml",
			expErr:   nil,
		},
	}

	for _, tt := range tests {
		// test the flow of creating dry run resource, checking created content, and deleting dry run resource
		err := eHandler.createDryrunResource(&tt.item, os.TempDir()+"/")
		assert.Equal(t, tt.expErr, err, "error should be nil for creating resource")
		if _, err := os.Stat(os.TempDir() + "/" + tt.fileName); err != nil {
			assert.Equal(t, false, os.IsNotExist(err), "file should exist after calling createDryrunResource")
			assert.Equal(t, tt.expErr, err, "os stat generated file should not return err")
		}

		// convert the created yaml back to config model format, compare the model spec
		covertedConfig, err := ReadConvertToModelConfig(tt.item.Resource.Name, tt.item.Resource.Namespace, os.TempDir()+"/")
		assert.Equal(t, tt.expErr, err, "error should be nil when converting config")
		assert.Equal(t, *covertedConfig, tt.item.Resource, "model config should be the same")

		// delete the created resource
		err = eHandler.findDeleteDryrunResource(&tt.item, os.TempDir()+"/")
		assert.Equal(t, tt.expErr, err, "error should not be nil when deleting the yaml file")

		// stat the file, file should not exist anymore
		_, err = os.Stat(os.TempDir() + "/" + tt.fileName)
		assert.Equal(t, true, os.IsNotExist(err), "err should be file not exists error")
	}
}

func getAuthzPolicyItem(action model.Event) Item {
	var item Item
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
		},
	}

	item.Operation = action
	item.Resource = out
	return item
}

func TestParseComponentsEnabledAuthzPolicy(t *testing.T) {
	type inputData struct {
		description string
		objectList  string
	}
	type outputData struct {
		result *ComponentEnabled
		err    string
	}
	type testData struct {
		input  inputData
		output outputData
	}
	tests := []testData{
		{
			input: inputData{
				description: "Parse services-enabled-authzpolicy list",
				objectList:  "namespace1/service1,namespace2/service2",
			},
			output: outputData{
				result: &ComponentEnabled{
					serviceMap:   map[string]bool{"namespace1/service1": true, "namespace2/service2": true},
					namespaceMap: map[string]bool{},
					cluster:      false,
				},
				err: "",
			},
		}, {
			input: inputData{
				description: "Services-enabled-authzpolicy list item has invalid format",
				objectList:  "service1-namespace1,service2-namespace2",
			},
			output: outputData{
				result: nil,
				err:    "service item service1-namespace1 from command line arg components-enabled-authzpolicy is in incorrect format",
			},
		}, {
			input: inputData{
				description: "Parse namespaces-enabled-authzpolicy list",
				objectList:  "ns1/*,ns2/*,ns3/*",
			},
			output: outputData{
				result: &ComponentEnabled{
					serviceMap:   map[string]bool{},
					namespaceMap: map[string]bool{"ns1": true, "ns2": true, "ns3": true},
					cluster:      false,
				},
				err: "",
			},
		}, {
			input: inputData{
				description: "Parse clusters-enabled-authzpolicy argument",
				objectList:  "*",
			},
			output: outputData{
				result: &ComponentEnabled{
					serviceMap:   nil,
					namespaceMap: nil,
					cluster:      true,
				},
				err: "",
			},
		},
	}
	for _, testcase := range tests {
		components, err := ParseComponentsEnabledAuthzPolicy(testcase.input.objectList)
		if err != nil {
			if err.Error() != testcase.output.err {
				t.Errorf("Wrong error message. Expected: %s, Actual: %s", testcase.output.err, err.Error())
			} else {
				continue
			}
		}

		assert.EqualValues(t, components.serviceMap, testcase.output.result.serviceMap, "Object serviceMap spec mismatch")
		assert.EqualValues(t, components.namespaceMap, testcase.output.result.namespaceMap, "Object namespaceMap spec mismatch")

		if components.cluster != testcase.output.result.cluster {
			t.Error("Object cluster value mismatch")
		}
	}

}

func TestIsEnabled(t *testing.T) {
	type inputData struct {
		obj       ComponentEnabled
		service   string
		namespace string
	}
	type testData struct {
		input  inputData
		output bool
	}
	tests := []testData{
		{
			input: inputData{
				obj: ComponentEnabled{
					serviceMap:   map[string]bool{"namespace1/service1": true, "namespace2/service2": true},
					namespaceMap: map[string]bool{},
					cluster:      false,
				},
				service:   "service1",
				namespace: "namespace1",
			},
			output: true,
		},
		{
			input: inputData{
				obj: ComponentEnabled{
					serviceMap:   map[string]bool{},
					namespaceMap: map[string]bool{"ns1": true, "ns2": true, "ns3": true},
					cluster:      false,
				},
				service:   "service1",
				namespace: "ns1",
			},
			output: true,
		},
		{
			input: inputData{
				obj: ComponentEnabled{
					serviceMap:   map[string]bool{},
					namespaceMap: map[string]bool{},
					cluster:      true,
				},
				service:   "test",
				namespace: "test",
			},
			output: true,
		},
		{
			input: inputData{
				obj: ComponentEnabled{
					serviceMap:   map[string]bool{},
					namespaceMap: map[string]bool{},
					cluster:      false,
				},
				service:   "service1",
				namespace: "namespace1",
			},
			output: false,
		},
	}
	for index, testcase := range tests {
		if testcase.input.obj.IsEnabled(testcase.input.service, testcase.input.namespace) != testcase.output {
			t.Errorf("Test %d failed, does not match expected output", index)
		}
	}
}
