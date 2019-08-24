package integration

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"

	"istio.io/api/rbac/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TODO, figure out why the warnings disappeared
// TODO, make the integration go.mod point to the local authz controller as opposed to the version
// TODO, add informer / indexer for get?
// TODO, go through document
// TODO, go through each test and make sure it's working correctly
type action int

const (
	create action = iota
	update
	noop
)

// rolloutAndValidate will create / update / noop the athenz domain resource and wait for the
// associated service role / service role bindings to be created. Once these are rolled out,
// they are validated against the expected output.
func rolloutAndValidate(t *testing.T, r *fixtures.ExpectedResources, a action) {
	if a == update {
		currentAD, err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Get(r.AD.Name, v1.GetOptions{})
		assert.Nil(t, err, "error should be nil")
		r.AD.ResourceVersion = currentAD.ResourceVersion
		_, err = framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Update(r.AD)
		assert.Nil(t, err, "error should be nil")
	} else if a == create {
		_, err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Create(r.AD)
		assert.Nil(t, err, "should be nil")
	}

	rolloutCount := 0
	for {
		rolloutCount++
		if rolloutCount > 5 {
			t.Error("time out waiting for rollout for ad", r.AD.Name)
		}

		index := 0
		for _, curr := range r.ModelConfigs {
			got := framework.Global.IstioClientset.Get(curr.Type, curr.Name, curr.Namespace)
			if got != nil && reflect.DeepEqual(got.Spec, curr.Spec) {
				index++
			}
		}

		if index == len(r.ModelConfigs) {
			break
		}
		time.Sleep(time.Second)
	}

	validateConfigs(t, r)
}

// validateConfigs will validate the service role / service role bindings on the
// cluster against the expected output
func validateConfigs(t *testing.T, r *fixtures.ExpectedResources) {
	for _, curr := range r.ModelConfigs {
		got := framework.Global.IstioClientset.Get(curr.Type, curr.Name, curr.Namespace)
		assert.NotNil(t, got, "istio custom resource should exist on the cluster")
		curr.ResourceVersion = got.ResourceVersion
		curr.CreationTimestamp = got.CreationTimestamp
		assert.Equal(t, curr, *got, "istio resource should be equal to expected")
	}
}

// cleanup will clean up the athenz domain and service role / service role binding objects on the cluster
func cleanup(t *testing.T, r *fixtures.ExpectedResources) {
	err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Delete(r.AD.Name, &v1.DeleteOptions{})
	assert.Nil(t, err, "athenz domain delete error should be nil")

	for _, curr := range r.ModelConfigs {
		err := framework.Global.IstioClientset.Delete(curr.Type, curr.Name, curr.Namespace)
		assert.Nil(t, err, "istio custom resource delete error should be nil")
	}
}

// 1. Create: Create SR / SRB with valid AD
// Initial: No AD, SR, SRB existing
// Input actions: Create AD with roles and policies
// Output: SR / SRB created with matching rules and bindings
func TestServiceRoleAndBindingCreation(t *testing.T) {
	r := fixtures.CreateAthenzDomain(&fixtures.OverrideResources{})
	rolloutAndValidate(t, r, create)
	cleanup(t, r)
}

// TODO, make sure srb is not there
// 1.1 Create: Create SR only if there are no role members for SRB creation
// Initial: No AD, SR, SRB existing
// Input actions: Created AD with policies
// Output: SR created with matching rules
func TestServiceRoleOnlyCreation(t *testing.T) {
	o := &fixtures.OverrideResources{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.Domain.Roles[0].RoleMembers = []*zms.RoleMember{}
		},
	}
	r := fixtures.CreateAthenzDomain(o)
	rolloutAndValidate(t, r, create)
	cleanup(t, r)
}

// 2. Update: Update existing roles / policy
// Initial: Existing AD, SR, SRB
// Input Actions: Update AD with additional roles, policies
// Output: SR / SRB updated with matching rules and bindings
func TestUpdateRoleAssertion(t *testing.T) {
	r := fixtures.CreateAthenzDomain(&fixtures.OverrideResources{})
	rolloutAndValidate(t, r, create)

	o := &fixtures.OverrideResources{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			allow := zms.ALLOW
			domainName := "athenz.domain"
			policy := &zms.Policy{
				Assertions: []*zms.Assertion{
					{
						Effect:   &allow,
						Action:   "GET",
						Role:     "athenz.domain:role.client-reader-role",
						Resource: "athenz.domain:svc.my-service-name",
					},
				},
				Name: zms.ResourceName(domainName + ":policy.admin"),
			}
			signedDomain.Domain.Policies.Contents.Policies = append(signedDomain.Domain.Policies.Contents.Policies, policy)
			role := &zms.Role{
				Members: []zms.MemberName{zms.MemberName("user.bar")},
				Name:    zms.ResourceName("athenz.domain:role.client-reader-role"),
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
				}
			},
		},
	}

	r = fixtures.CreateAthenzDomain(o)
	rolloutAndValidate(t, r, update)
	cleanup(t, r)
}

// 2.1 Update: Update existing assertion / role member / action
func TestUpdateAssertionRoleMemberAction(t *testing.T) {
	r := fixtures.CreateAthenzDomain(&fixtures.OverrideResources{})
	rolloutAndValidate(t, r, create)

	o := &fixtures.OverrideResources{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			allow := zms.ALLOW
			domainName := "athenz.domain"
			policy := &zms.Policy{
				Assertions: []*zms.Assertion{
					{
						Effect:   &allow,
						Action:   "POST",
						Role:     "athenz.domain:role.client-writer-role",
						Resource: "athenz.domain:svc.my-service-name-two",
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
				}
			},
		},
	}

	r = fixtures.CreateAthenzDomain(o)
	rolloutAndValidate(t, r, update)
	cleanup(t, r)
}

// 2.2 Update: Delete existing roleMember / assertion
func TestUpdateDeleteRoleMemberAssertion(t *testing.T) {
	o := &fixtures.OverrideResources{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			allow := zms.ALLOW
			domainName := "athenz.domain"
			policy := &zms.Policy{
				Assertions: []*zms.Assertion{
					{
						Effect:   &allow,
						Action:   "GET",
						Role:     "athenz.domain:role.client-writer-role",
						Resource: "athenz.domain:svc.my-service-name",
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
				})
			},
		},
	}

	r := fixtures.CreateAthenzDomain(o)
	rolloutAndValidate(t, r, create)

	r = fixtures.CreateAthenzDomain(&fixtures.OverrideResources{})
	rolloutAndValidate(t, r, update)
	cleanup(t, r)
}

// 2.3 Update: Add unrelated AD changes (not conformant to RBAC)
func TestUpdateUnrelatedADField(t *testing.T) {
	r := fixtures.CreateAthenzDomain(&fixtures.OverrideResources{})
	rolloutAndValidate(t, r, create)

	o := &fixtures.OverrideResources{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.KeyId = "col-env-1.2"
		},
	}

	newR := fixtures.CreateAthenzDomain(o)
	r.AD = newR.AD

	rolloutAndValidate(t, r, update)
	cleanup(t, r)
}

// STATUS: DONE
// 2.4 Update: Update role name and expect the old SR/SRB to be deleted
func TestUpdateRoleName(t *testing.T) {
	r := fixtures.CreateAthenzDomain(&fixtures.OverrideResources{})
	rolloutAndValidate(t, r, create)

	o := &fixtures.OverrideResources{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Role = "athenz.domain:role.client-reader-role"
			signedDomain.Domain.Roles[0].Name = "athenz.domain:role.client-reader-role"
		},
	}

	newR := fixtures.CreateAthenzDomain(o)
	r.AD = newR.AD
	rolloutAndValidate(t, r, update)
	for _, config := range r.ModelConfigs {
		c := framework.Global.IstioClientset.Get(config.Type, config.Name, config.Namespace)
		assert.Nil(t, c, "istio custom resource get should return nil")
	}
	cleanup(t, newR)
}

// 2.5 Update: Test updates with multiple namespaces / AD
func TestMultipleAD(t *testing.T) {
	r := fixtures.CreateAthenzDomain(&fixtures.OverrideResources{})
	rolloutAndValidate(t, r, create)

	o := &fixtures.OverrideResources{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.Domain.Name = "athenz.domain.one"
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Role = "athenz.domain.one:role.client-reader-role"
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Resource = "athenz.domain.one:svc.my-service-name"
			signedDomain.Domain.Roles[0].Name = "athenz.domain.one:role.client-reader-role"
		},
	}

	rTwo := fixtures.CreateAthenzDomain(o)
	rolloutAndValidate(t, rTwo, create)

	o = &fixtures.OverrideResources{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.Domain.Name = "athenz.domain.two"
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Role = "athenz.domain.two:role.client-reader-role"
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Resource = "athenz.domain.two:svc.my-service-name"
			signedDomain.Domain.Roles[0].Name = "athenz.domain.two:role.client-reader-role"
		},
	}

	rThree := fixtures.CreateAthenzDomain(o)
	rolloutAndValidate(t, rThree, create)

	cleanup(t, r)
	cleanup(t, rTwo)
	cleanup(t, rThree)
}

// 3 Delete
//Initial: Existing AD, SR, SRB
//Input Actions: Delete entire AD
//Output: SR / SRB deleted in namespace
func TestAthenzDomainDelete(t *testing.T) {
	r := fixtures.CreateAthenzDomain(&fixtures.OverrideResources{})
	rolloutAndValidate(t, r, create)

	err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Delete(r.AD.Name, &v1.DeleteOptions{})
	assert.Nil(t, err, "athenz domain delete error should be nil")

	validateConfigs(t, r)
}

// 3.1 Delete: Delete SR / SRB if AD still exists, expect the controller to sync it back
func TestDeleteSRAndSRB(t *testing.T) {
	r := fixtures.CreateAthenzDomain(&fixtures.OverrideResources{})
	rolloutAndValidate(t, r, create)

	for _, curr := range r.ModelConfigs {
		err := framework.Global.IstioClientset.Delete(curr.Type, curr.Name, curr.Namespace)
		assert.Nil(t, err, "istio custom resource delete error should be nil")
	}

	rolloutAndValidate(t, r, noop)
}
