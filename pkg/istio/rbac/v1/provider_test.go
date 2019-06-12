// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
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
					zms.ResourceName("athenz.domain:role.client-writer-role"): {
						{
							MemberName: "writer-domain.client-power-service",
						},
						{
							MemberName: "user.developer",
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
	}

	for _, c := range cases {
		p := NewProvider()
		gotConfigs := p.ConvertAthenzModelIntoIstioRbac(c.model)
		assert.EqualValues(t, c.expectedConfigs, gotConfigs, c.test)
	}
}
