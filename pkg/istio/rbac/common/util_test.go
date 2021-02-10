package common

import (
	"fmt"
	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/collection"
	"istio.io/istio/pkg/config/schema/collections"
	"testing"
)

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
		gotMember, gotErr := MemberToSpiffe(c.member)
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
		gotOriginJwtName, gotErr := MemberToOriginJwtSubject(c.member)
		assert.Equal(t, c.expectedOriginJwtName, gotOriginJwtName, c.test)
		assert.Equal(t, c.expectedErr, gotErr, c.test)
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
