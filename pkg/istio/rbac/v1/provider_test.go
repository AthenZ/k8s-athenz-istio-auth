// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
)

func TestConvertAthenzModelIntoIstioRbac(t *testing.T) {

	allow := zms.ALLOW
	cases := []struct {
		test            string
		model           athenz.Model
		expectedConfigs []model.Config
	}{
		{
			test:            "empty model",
			model:           athenz.Model{},
			expectedConfigs: []model.Config{},
		},
		{
			test: "valid model with policies and members",
			model: athenz.Model{
				Name:      "athenz.domain",
				Namespace: "athenz-domain",
				Roles: []zms.ResourceName{
					zms.ResourceName("athenz.domain:role.client-reader-role"),
					zms.ResourceName("different-domain:role.trust-role"),
					zms.ResourceName("athenz.domain:role.client-writer-role"),
					zms.ResourceName("athenz.domain:role.identity-provider-role"),
					zms.ResourceName("athenz.domain:role.client-no-policies-role"),
					zms.ResourceName("athenz.domain:role.no-members-role"),
				},
				Rules: map[zms.ResourceName][]*zms.Assertion{
					zms.ResourceName("different-domain:role.trust-role"): {
						{
							Effect:   &allow,
							Action:   "PUT",
							Role:     "different-domain:role.trust-role",
							Resource: "athenz.domain:svc.my-service-name:/another/sub/path",
						},
						{
							Effect:   &allow,
							Action:   "post",
							Role:     "different-domain:role.trust-role",
							Resource: "athenz.domain:svc.some-other-service-name:*",
						},
					},
					zms.ResourceName("athenz.domain:role.client-writer-role"): {
						{
							Effect:   &allow,
							Action:   "PUT",
							Role:     "athenz.domain:role.client-writer-role",
							Resource: "athenz.domain:svc.my-service-name:/another/sub/path",
						},
						{
							Effect:   &allow,
							Action:   "post",
							Role:     "athenz.domain:role.client-writer-role",
							Resource: "athenz.domain:svc.some-other-service-name:*",
						},
					},
					zms.ResourceName("athenz.domain:role.identity-provider-role"): {
						{
							Effect:   &allow,
							Action:   "LAUNCH",
							Role:     "athenz.domain:role.identity-provider-role",
							Resource: "athenz.domain:svc.my-service-name",
						},
					},
					zms.ResourceName("athenz.domain:role.client-reader-role"): {
						{
							Effect:   &allow,
							Action:   "get",
							Role:     "athenz.domain:role.client-reader-role",
							Resource: "athenz.domain:svc.my-service-name:/protected/path",
						},
						{
							Effect:   &allow,
							Action:   "HEAD",
							Role:     "athenz.domain:role.client-reader-role",
							Resource: "athenz.domain:svc.my-another-service-name",
						},
					},
				},
				Members: map[zms.ResourceName][]*zms.RoleMember{
					zms.ResourceName("athenz.domain:role.client-reader-role"): {
						{
							MemberName: "some-client.domain.client-serviceA",
						},
						{
							MemberName: "user.athenzuser",
						},
					},
					zms.ResourceName("different-domain:trust-role"): {
						{
							MemberName: "user.trusted",
						},
					},
					zms.ResourceName("athenz.domain:role.client-writer-role"): {
						{
							MemberName: "writer-domain.client-power-service",
						},
						{
							MemberName: "user.developer",
						},
					},
					zms.ResourceName("athenz.domain:role.identity-provider-role"): {
						{
							MemberName: "k8s.cluster.prod",
						},
						{
							MemberName: "k8s.cluster.canary",
						},
					},
					zms.ResourceName("athenz.domain:role.client-no-policies-role"): {
						{
							MemberName: "another-domain.client-service",
						},
						{
							MemberName: "user.engineer",
						},
					},
				},
			},
			expectedConfigs: []model.Config{
				{
					ConfigMeta: model.ConfigMeta{
						Type:      model.ServiceRole.Type,
						Group:     model.ServiceRole.Group + model.IstioAPIGroupDomain,
						Version:   model.ServiceRole.Version,
						Namespace: "athenz-domain",
						Name:      "client-reader-role",
					},
					Spec: &v1alpha1.ServiceRole{
						Rules: []*v1alpha1.AccessRule{
							{
								Methods: []string{
									"GET",
								},
								Paths: []string{
									"/protected/path",
								},
								Services: []string{common.WildCardAll},
								Constraints: []*v1alpha1.AccessRule_Constraint{
									{
										Key: common.ConstraintSvcKey,
										Values: []string{
											"my-service-name",
										},
									},
								},
							},
							{
								Methods: []string{
									"HEAD",
								},
								Services: []string{common.WildCardAll},
								Constraints: []*v1alpha1.AccessRule_Constraint{
									{
										Key: common.ConstraintSvcKey,
										Values: []string{
											"my-another-service-name",
										},
									},
								},
							},
						},
					},
				},
				{
					ConfigMeta: model.ConfigMeta{
						Type:      model.ServiceRoleBinding.Type,
						Group:     model.ServiceRoleBinding.Group + model.IstioAPIGroupDomain,
						Version:   model.ServiceRoleBinding.Version,
						Namespace: "athenz-domain",
						Name:      "client-reader-role",
					},
					Spec: &v1alpha1.ServiceRoleBinding{
						RoleRef: &v1alpha1.RoleRef{
							Name: "client-reader-role",
							Kind: common.ServiceRoleKind,
						},
						Subjects: []*v1alpha1.Subject{
							{
								User: "some-client.domain/sa/client-serviceA",
							},
							{
								User: "user/sa/athenzuser",
							},
						},
					},
				},
				{
					ConfigMeta: model.ConfigMeta{
						Type:      model.ServiceRole.Type,
						Group:     model.ServiceRole.Group + model.IstioAPIGroupDomain,
						Version:   model.ServiceRole.Version,
						Namespace: "athenz-domain",
						Name:      "client-writer-role",
					},
					Spec: &v1alpha1.ServiceRole{
						Rules: []*v1alpha1.AccessRule{
							{
								Methods: []string{
									"PUT",
								},
								Paths: []string{
									"/another/sub/path",
								},
								Services: []string{common.WildCardAll},
								Constraints: []*v1alpha1.AccessRule_Constraint{
									{
										Key: common.ConstraintSvcKey,
										Values: []string{
											"my-service-name",
										},
									},
								},
							},
							{
								Methods: []string{
									"POST",
								},
								Paths: []string{
									"*",
								},
								Services: []string{common.WildCardAll},
								Constraints: []*v1alpha1.AccessRule_Constraint{
									{
										Key: common.ConstraintSvcKey,
										Values: []string{
											"some-other-service-name",
										},
									},
								},
							},
						},
					},
				},
				{
					ConfigMeta: model.ConfigMeta{
						Type:      model.ServiceRoleBinding.Type,
						Group:     model.ServiceRoleBinding.Group + model.IstioAPIGroupDomain,
						Version:   model.ServiceRoleBinding.Version,
						Namespace: "athenz-domain",
						Name:      "client-writer-role",
					},
					Spec: &v1alpha1.ServiceRoleBinding{
						RoleRef: &v1alpha1.RoleRef{
							Name: "client-writer-role",
							Kind: common.ServiceRoleKind,
						},
						Subjects: []*v1alpha1.Subject{
							{
								User: "writer-domain/sa/client-power-service",
							},
							{
								User: "user/sa/developer",
							},
						},
					},
				},
			},
		},
		{
			test: "model with invalid members that results in empty ServiceRoleBindingSpec",
			model: athenz.Model{
				Name:      "athenz.domain",
				Namespace: "athenz-domain",
				Roles: []zms.ResourceName{
					zms.ResourceName("athenz.domain:role.client-reader-role"),
					zms.ResourceName("athenz.domain:role.client-writer-role"),
				},
				Rules: map[zms.ResourceName][]*zms.Assertion{
					zms.ResourceName("athenz.domain:role.client-reader-role"): {
						{
							Effect:   &allow,
							Action:   "get",
							Role:     "athenz.domain:role.client-reader-role",
							Resource: "athenz.domain:svc.my-service-name:/protected/path",
						},
						{
							Effect:   &allow,
							Action:   "HEAD",
							Role:     "athenz.domain:role.client-reader-role",
							Resource: "athenz.domain:svc.my-another-service-name",
						},
					},
				},
				Members: map[zms.ResourceName][]*zms.RoleMember{
					zms.ResourceName("athenz.domain:role.client-reader-role"): {
						{
							MemberName: "invalid-principal",
						},
					},
				},
			},
			expectedConfigs: []model.Config{
				{
					ConfigMeta: model.ConfigMeta{
						Type:      model.ServiceRole.Type,
						Group:     model.ServiceRole.Group + model.IstioAPIGroupDomain,
						Version:   model.ServiceRole.Version,
						Namespace: "athenz-domain",
						Name:      "client-reader-role",
					},
					Spec: &v1alpha1.ServiceRole{
						Rules: []*v1alpha1.AccessRule{
							{
								Methods: []string{
									"GET",
								},
								Paths: []string{
									"/protected/path",
								},
								Services: []string{common.WildCardAll},
								Constraints: []*v1alpha1.AccessRule_Constraint{
									{
										Key: common.ConstraintSvcKey,
										Values: []string{
											"my-service-name",
										},
									},
								},
							},
							{
								Methods: []string{
									"HEAD",
								},
								Services: []string{common.WildCardAll},
								Constraints: []*v1alpha1.AccessRule_Constraint{
									{
										Key: common.ConstraintSvcKey,
										Values: []string{
											"my-another-service-name",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			test: "model with invalid members that results in unable to create ServiceRoleBindingSpec",
			model: athenz.Model{
				Name:      "athenz.domain",
				Namespace: "athenz-domain",
				Roles: []zms.ResourceName{
					zms.ResourceName("athenz.domain:role.client-reader-role"),
				},
				Rules: map[zms.ResourceName][]*zms.Assertion{
					zms.ResourceName("athenz.domain:role.client-reader-role"): {
						{
							Effect:   &allow,
							Action:   "get",
							Role:     "athenz.domain:role.client-reader-role",
							Resource: "athenz.domain:svc.my-service-name:/protected/path",
						},
						{
							Effect:   &allow,
							Action:   "HEAD",
							Role:     "athenz.domain:role.client-reader-role",
							Resource: "athenz.domain:svc.my-another-service-name",
						},
					},
				},
				Members: map[zms.ResourceName][]*zms.RoleMember{},
			},
			expectedConfigs: []model.Config{
				{
					ConfigMeta: model.ConfigMeta{
						Type:      model.ServiceRole.Type,
						Group:     model.ServiceRole.Group + model.IstioAPIGroupDomain,
						Version:   model.ServiceRole.Version,
						Namespace: "athenz-domain",
						Name:      "client-reader-role",
					},
					Spec: &v1alpha1.ServiceRole{
						Rules: []*v1alpha1.AccessRule{
							{
								Methods: []string{
									"GET",
								},
								Paths: []string{
									"/protected/path",
								},
								Services: []string{common.WildCardAll},
								Constraints: []*v1alpha1.AccessRule_Constraint{
									{
										Key: common.ConstraintSvcKey,
										Values: []string{
											"my-service-name",
										},
									},
								},
							},
							{
								Methods: []string{
									"HEAD",
								},
								Services: []string{common.WildCardAll},
								Constraints: []*v1alpha1.AccessRule_Constraint{
									{
										Key: common.ConstraintSvcKey,
										Values: []string{
											"my-another-service-name",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			test: "model with invalid assertions that results in no rules for ServiceRole",
			model: athenz.Model{
				Name:      "athenz.domain",
				Namespace: "athenz-domain",
				Roles: []zms.ResourceName{
					zms.ResourceName("athenz.domain:role.client-reader-role"),
					zms.ResourceName("athenz.domain:role.client-writer-role"),
				},
				Rules: map[zms.ResourceName][]*zms.Assertion{
					zms.ResourceName("athenz.domain:role.client-reader-role"): {
						{
							Effect:   &allow,
							Action:   "assume_role",
							Role:     "athenz.domain:role.client-reader-role",
							Resource: "athenz.domain:svc.my-service-name:/protected/path",
						},
						{
							Effect:   &allow,
							Action:   "HEAD",
							Role:     "athenz.domain:role.client-reader-role",
							Resource: "my-another-service-name:*",
						},
					},
				},
				Members: map[zms.ResourceName][]*zms.RoleMember{
					zms.ResourceName("athenz.domain:role.client-reader-role"): {
						{
							MemberName: "some-client.domain.client-serviceA",
						},
						{
							MemberName: "user.athenzuser",
						},
					},
				},
			},
			expectedConfigs: []model.Config{},
		},
	}

	for _, c := range cases {
		p := NewProvider()
		gotConfigs := p.ConvertAthenzModelIntoIstioRbac(c.model)
		assert.EqualValues(t, c.expectedConfigs, gotConfigs, c.test)
	}
}
