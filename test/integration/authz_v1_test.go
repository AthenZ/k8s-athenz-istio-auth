package integration

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

type action int

const (
	create action = iota
	update
	delete
	noop
)

// rolloutAndValidateRbac will create / update / delete / noop the athenz domain resource and wait for the
// associated service role / service role bindings to be created. Once these are rolled out,
// they are validated against the expected output.
func rolloutAndValidateRbac(t *testing.T, r *fixtures.ExpectedRbac, a action) {
	switch a {
	case create:
		_, err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Create(r.AD, v1.CreateOptions{})
		assert.Nil(t, err, "athenz domain create error should be nil")
	case update:
		currentAD, err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Get(r.AD.Name, v1.GetOptions{})
		assert.Nil(t, err, "athenz domain get error should be nil")
		r.AD.ResourceVersion = currentAD.ResourceVersion
		_, err = framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Update(r.AD, v1.UpdateOptions{})
		assert.Nil(t, err, "athenz domain update error should be nil")
	case delete:
		err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Delete(r.AD.Name, v1.DeleteOptions{})
		assert.Nil(t, err, "athenz domain delete error should be nil")
	}

	err := wait.PollImmediate(time.Second, time.Second*5, func() (bool, error) {
		for _, curr := range r.ModelConfigs {
			got := framework.Global.IstioClientset.Get(curr.GroupVersionKind(), curr.Name, curr.Namespace)
			if got == nil {
				return false, nil
			}

			if !reflect.DeepEqual(curr.Spec, got.Spec) {
				return false, nil
			}
		}

		return true, nil
	})

	assert.Nil(t, err, "time out waiting for rollout for ad "+r.AD.Name+" with error")

	namespace := athenz.DomainToNamespace(r.AD.Name)
	modelConfigTypes := make(map[string]bool)
	modelConfigs := make([]model.Config, 0)
	for _, modelConfig := range r.ModelConfigs {
		_, exists := modelConfigTypes[modelConfig.Type]
		if !exists {
			list, err := framework.Global.IstioClientset.List(modelConfig.GroupVersionKind(), namespace)
			assert.Nil(t, err, "istio custom resource list error should be nil")
			modelConfigTypes[modelConfig.Type] = true
			for _, curr := range list {
				curr.ResourceVersion = ""
				curr.CreationTimestamp = time.Time{}
				modelConfigs = append(modelConfigs, curr)
			}
		}
	}

	assert.ElementsMatch(t, modelConfigs, r.ModelConfigs, "expected list must match the configs on the cluster")
}

// cleanupRbac will clean up the athenz domain and service role / service role binding objects on the cluster
func cleanupRbac(t *testing.T, r *fixtures.ExpectedRbac) {
	err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Delete(r.AD.Name, v1.DeleteOptions{})
	assert.Nil(t, err, "athenz domain delete error should be nil")

	modelConfigTypes := make(map[string]bool)
	for _, modelConfig := range r.ModelConfigs {
		modelConfigTypes[modelConfig.Type] = true
		err := framework.Global.IstioClientset.Delete(modelConfig.GroupVersionKind(), modelConfig.Name, modelConfig.Namespace)
		assert.Nil(t, err, "istio custom resource delete error should be nil")
	}

	namespace := athenz.DomainToNamespace(r.AD.Name)
	for _, modelConfigType := range r.ModelConfigs {
		list, err := framework.Global.IstioClientset.List(modelConfigType.GroupVersionKind(), namespace)
		assert.Nil(t, err, "istio custom resource list error should be nil")
		assert.Empty(t, list, "all configs must be deleted, list not empty")
	}
}

// 1.0 Create SR / SRB with valid AD
func TestCreateServiceRoleAndBinding(t *testing.T) {
	r := fixtures.GetExpectedRbac(nil)
	rolloutAndValidateRbac(t, r, create)
	cleanupRbac(t, r)
}

// 1.1 Create SR and SRB with role cert spiffe only if there are no role members
func TestCreateServiceRoleAndBindingsWhenNoMembersInRole(t *testing.T) {
	o := &fixtures.OverrideRbac{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.Domain.Roles[0].RoleMembers = []*zms.RoleMember{}
			signedDomain.Domain.Roles[0].Members = []zms.MemberName{}
		},
	}
	r := fixtures.GetExpectedRbac(o)
	rolloutAndValidateRbac(t, r, create)
	cleanupRbac(t, r)
}

// 2.0 Update existing domain with new role / policy
func TestUpdateRoleAndPolicy(t *testing.T) {
	r := fixtures.GetExpectedRbac(nil)
	rolloutAndValidateRbac(t, r, create)

	o := &fixtures.OverrideRbac{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			allow := zms.ALLOW
			domainName := "athenz.domain"
			policy := &zms.Policy{
				Assertions: []*zms.Assertion{
					{
						Effect:   &allow,
						Action:   "GET",
						Role:     domainName + ":role.client-reader-role",
						Resource: domainName + ":svc.my-service-name",
					},
				},
				Name: zms.ResourceName(domainName + ":policy.admin"),
			}
			signedDomain.Domain.Policies.Contents.Policies = append(signedDomain.Domain.Policies.Contents.Policies, policy)
			role := &zms.Role{
				Members: []zms.MemberName{zms.MemberName("user.bar")},
				Name:    zms.ResourceName(domainName + ":role.client-reader-role"),
				RoleMembers: []*zms.RoleMember{
					{
						MemberName: zms.MemberName("user.bar"),
					},
				},
			}
			signedDomain.Domain.Roles = append(signedDomain.Domain.Roles, role)
		},
		ModifySRAndSRBPair: []func(sr *v1alpha1.ServiceRole, srb *v1alpha1.ServiceRoleBinding){
			func(sr *v1alpha1.ServiceRole, srb *v1alpha1.ServiceRoleBinding) {
			},
			func(sr *v1alpha1.ServiceRole, srb *v1alpha1.ServiceRoleBinding) {
				sr.Rules = []*v1alpha1.AccessRule{
					{
						Methods: []string{
							"GET",
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
				}
				srb.Subjects = []*v1alpha1.Subject{
					{
						User: "user/sa/bar",
					},
					{
						Properties: map[string]string{
							common.RequestAuthPrincipalProperty: common.AthenzJwtPrefix + "user.bar",
						},
					},
				}
			},
		},
	}

	r = fixtures.GetExpectedRbac(o)
	rolloutAndValidateRbac(t, r, update)
	cleanupRbac(t, r)
}

// 2.1 Update existing assertion / role member / action
func TestUpdateAssertionActionAndRoleMember(t *testing.T) {
	r := fixtures.GetExpectedRbac(nil)
	rolloutAndValidateRbac(t, r, create)

	o := &fixtures.OverrideRbac{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			allow := zms.ALLOW
			domainName := "athenz.domain"
			policy := &zms.Policy{
				Assertions: []*zms.Assertion{
					{
						Effect:   &allow,
						Action:   "POST",
						Role:     domainName + ":role.client-writer-role",
						Resource: domainName + ":svc.my-service-name-two",
					},
				},
				Name: zms.ResourceName(domainName + ":policy.admin"),
			}
			signedDomain.Domain.Policies.Contents.Policies = []*zms.Policy{policy}

			roleMember := &zms.RoleMember{
				MemberName: zms.MemberName("user.bar"),
			}
			signedDomain.Domain.Roles[0].RoleMembers = []*zms.RoleMember{roleMember}
			signedDomain.Domain.Roles[0].Members = []zms.MemberName{zms.MemberName("user.bar")}
		},
		ModifySRAndSRBPair: []func(sr *v1alpha1.ServiceRole, srb *v1alpha1.ServiceRoleBinding){
			func(sr *v1alpha1.ServiceRole, srb *v1alpha1.ServiceRoleBinding) {
				sr.Rules = []*v1alpha1.AccessRule{
					{
						Methods: []string{
							"POST",
						},
						Services: []string{common.WildCardAll},
						Constraints: []*v1alpha1.AccessRule_Constraint{
							{
								Key: common.ConstraintSvcKey,
								Values: []string{
									"my-service-name-two",
								},
							},
						},
					},
				}
				srb.Subjects = []*v1alpha1.Subject{
					{
						User: "user/sa/bar",
					},
					{
						Properties: map[string]string{
							common.RequestAuthPrincipalProperty: common.AthenzJwtPrefix + "user.bar",
						},
					},
				}
			},
		},
	}

	r = fixtures.GetExpectedRbac(o)
	rolloutAndValidateRbac(t, r, update)
	cleanupRbac(t, r)
}

// 2.2 Delete existing roleMember / assertion
func TestUpdateDeleteRoleMemberAndAssertion(t *testing.T) {
	o := &fixtures.OverrideRbac{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			allow := zms.ALLOW
			domainName := "athenz.domain"
			policy := &zms.Policy{
				Assertions: []*zms.Assertion{
					{
						Effect:   &allow,
						Action:   "GET",
						Role:     domainName + ":role.client-writer-role",
						Resource: domainName + ":svc.my-service-name",
					},
				},
				Name: zms.ResourceName(domainName + ":policy.admin"),
			}
			signedDomain.Domain.Policies.Contents.Policies = append(signedDomain.Domain.Policies.Contents.Policies, policy)

			roleMember := &zms.RoleMember{
				MemberName: zms.MemberName("user.bar"),
			}
			signedDomain.Domain.Roles[0].RoleMembers = append(signedDomain.Domain.Roles[0].RoleMembers, roleMember)
		},
		ModifySRAndSRBPair: []func(sr *v1alpha1.ServiceRole, srb *v1alpha1.ServiceRoleBinding){
			func(sr *v1alpha1.ServiceRole, srb *v1alpha1.ServiceRoleBinding) {
				sr.Rules = append(sr.Rules, &v1alpha1.AccessRule{
					Methods: []string{
						"GET",
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
				})
				srb.Subjects = append(srb.Subjects, &v1alpha1.Subject{
					User: "user/sa/bar",
				}, &v1alpha1.Subject{
					Properties: map[string]string{
						common.RequestAuthPrincipalProperty: common.AthenzJwtPrefix + "user.bar",
					},
				})
			},
		},
	}

	r := fixtures.GetExpectedRbac(o)
	rolloutAndValidateRbac(t, r, create)

	r = fixtures.GetExpectedRbac(nil)
	rolloutAndValidateRbac(t, r, update)
	cleanupRbac(t, r)
}

// 2.3 Add unrelated AD changes (not conformant to RBAC)
func TestUpdateUnrelatedAthenzDomainField(t *testing.T) {
	r := fixtures.GetExpectedRbac(nil)
	rolloutAndValidateRbac(t, r, create)

	o := &fixtures.OverrideRbac{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.Domain.Policies.KeyId = "col-env-1.2"
			signedDomain.KeyId = "col-env-1.2"
		},
	}

	updatedR := fixtures.GetExpectedRbac(o)
	rolloutAndValidateRbac(t, updatedR, update)
	cleanupRbac(t, r)
}

// 2.4 Update role name and expect the old SR/SRB to be deleted
func TestUpdateRoleName(t *testing.T) {
	r := fixtures.GetExpectedRbac(nil)
	rolloutAndValidateRbac(t, r, create)

	o := &fixtures.OverrideRbac{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Role = "athenz.domain:role.client-reader-role"
			signedDomain.Domain.Roles[0].Name = "athenz.domain:role.client-reader-role"
		},
	}

	updatedR := fixtures.GetExpectedRbac(o)
	rolloutAndValidateRbac(t, updatedR, update)
	for _, config := range r.ModelConfigs {
		c := framework.Global.IstioClientset.Get(config.GroupVersionKind(), config.Name, config.Namespace)
		assert.Nil(t, c, "istio custom resource get should return nil")
	}
	cleanupRbac(t, updatedR)
}

// 2.5 Test updates with multiple namespaces / AD
func TestMultipleAthenzDomain(t *testing.T) {
	rOne := fixtures.GetExpectedRbac(nil)
	rolloutAndValidateRbac(t, rOne, create)

	oTwo := &fixtures.OverrideRbac{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.Domain.Name = "athenz.domain.one"
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Role = "athenz.domain.one:role.client-reader-role"
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Resource = "athenz.domain.one:svc.my-service-name"
			signedDomain.Domain.Roles[0].Name = "athenz.domain.one:role.client-reader-role"
		},
	}

	rTwo := fixtures.GetExpectedRbac(oTwo)
	rolloutAndValidateRbac(t, rTwo, create)

	oThree := &fixtures.OverrideRbac{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.Domain.Name = "athenz.domain.two"
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Role = "athenz.domain.two:role.client-reader-role"
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Resource = "athenz.domain.two:svc.my-service-name"
			signedDomain.Domain.Roles[0].Name = "athenz.domain.two:role.client-reader-role"
		},
	}

	rThree := fixtures.GetExpectedRbac(oThree)
	rolloutAndValidateRbac(t, rThree, create)

	oOne := &fixtures.OverrideRbac{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			allow := zms.ALLOW
			domainName := "athenz.domain"
			policy := &zms.Policy{
				Assertions: []*zms.Assertion{
					{
						Effect:   &allow,
						Action:   "GET",
						Role:     domainName + ":role.client-writer-role",
						Resource: domainName + ":svc.my-service-name",
					},
				},
				Name: zms.ResourceName(domainName + ":policy.admin"),
			}
			signedDomain.Domain.Policies.Contents.Policies = append(signedDomain.Domain.Policies.Contents.Policies, policy)

			roleMember := &zms.RoleMember{
				MemberName: zms.MemberName("user.bar"),
			}
			signedDomain.Domain.Roles[0].RoleMembers = append(signedDomain.Domain.Roles[0].RoleMembers, roleMember)
		},
		ModifySRAndSRBPair: []func(sr *v1alpha1.ServiceRole, srb *v1alpha1.ServiceRoleBinding){
			func(sr *v1alpha1.ServiceRole, srb *v1alpha1.ServiceRoleBinding) {
				sr.Rules = append(sr.Rules, &v1alpha1.AccessRule{
					Methods: []string{
						"GET",
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
				})
				srb.Subjects = append(srb.Subjects, &v1alpha1.Subject{
					User: "user/sa/bar",
				}, &v1alpha1.Subject{
					Properties: map[string]string{
						common.RequestAuthPrincipalProperty: common.AthenzJwtPrefix + "user.bar",
					},
				})
			},
		},
	}

	rOne = fixtures.GetExpectedRbac(oOne)
	rolloutAndValidateRbac(t, rOne, update)

	cleanupRbac(t, rOne)
	cleanupRbac(t, rTwo)
	cleanupRbac(t, rThree)
}

// 3.0 Delete athenz domain
// TODO: currently the controller does not delete the service role / binding
// due to checking for the existence of the athenz domain. This test assumes
// these still exist. Update this test once the controller core logic changes.
func TestAthenzDomainDelete(t *testing.T) {
	r := fixtures.GetExpectedRbac(nil)
	rolloutAndValidateRbac(t, r, create)
	rolloutAndValidateRbac(t, r, delete)
}

// 3.1 Delete SR / SRB if AD still exists, expect the controller to sync it back
func TestDeleteSRAndSRB(t *testing.T) {
	r := fixtures.GetExpectedRbac(nil)
	rolloutAndValidateRbac(t, r, create)

	for _, curr := range r.ModelConfigs {
		err := framework.Global.IstioClientset.Delete(curr.GroupVersionKind(), curr.Name, curr.Namespace)
		assert.Nil(t, err, "istio custom resource delete error should be nil")
	}

	rolloutAndValidateRbac(t, r, noop)
	cleanupRbac(t, r)
}
