package integration

import (
	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	"istio.io/api/rbac/v1alpha1"
	"time"
)

// TODO, figure out why the warnings disappeared
// TODO, make the integration go.mod point to the local authz controller as opposed to the version
// TODO, add informer / indexer for get?
// TODO, see if we need more test cases like both role and policy changes
// TODO, go through document
// TODO, go through each test and make sure it's working correctly
type action int

const (
	create action = iota
	update
	noop
)

func rolloutAndValidate(t *testing.T, adPair *fixtures.AthenzDomainPair, a action) {
	if a == update {
		currentAD, err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Get(adPair.AD.Name, v1.GetOptions{})
		assert.Nil(t, err, "error should be nil")

		adPair.AD.ResourceVersion = currentAD.ResourceVersion

		_, err = framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Update(adPair.AD)
		assert.Nil(t, err, "error should be nil")
	} else if a == create {
		_, err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Create(adPair.AD)
		assert.Nil(t, err, "should be nil")
	}

	rolloutCount := 0
	// TODO, might need deep equal check here for rollout
	for {
		rolloutCount++
		if rolloutCount > 5 {
			t.Error("time out waiting for rollout for ad", adPair.AD.Name)
		}

		index := 0
		for _, curr := range adPair.ModelConfigs {
			got := framework.Global.IstioClientset.Get(curr.Type, curr.Name, curr.Namespace)
			if got != nil {
				index++
			}
		}

		if index == len(adPair.ModelConfigs) {
			break
		}
		time.Sleep(time.Second)
	}

	configs, err := framework.Global.IstioClientset.List(model.ServiceRole.Type, "athenz-domain")
	assert.Nil(t, err)
	log.Println("service roles:")
	spew.Dump(configs)
	configs, err = framework.Global.IstioClientset.List(model.ServiceRoleBinding.Type, "athenz-domain")
	log.Println("service role bindings:")
	spew.Dump(configs)
	time.Sleep(time.Second * 5)
	validateConfigs(t, adPair)
}

func validateConfigs(t *testing.T, adPair *fixtures.AthenzDomainPair) {
	log.Println("model configs array:")
	spew.Dump(adPair.ModelConfigs)
	for _, curr := range adPair.ModelConfigs {
		got := framework.Global.IstioClientset.Get(curr.Type, curr.Name, curr.Namespace)
		assert.NotNil(t, got, "not nil")
		curr.ResourceVersion = got.ResourceVersion
		curr.CreationTimestamp = got.CreationTimestamp
		assert.Equal(t, curr, *got, "should be equal")
	}
}

func cleanup(t *testing.T, adPair *fixtures.AthenzDomainPair) {
	err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Delete(adPair.AD.Name, &v1.DeleteOptions{})
	assert.Nil(t, err, "nil")

	for _, curr := range adPair.ModelConfigs {
		err := framework.Global.IstioClientset.Delete(curr.Type, curr.Name, curr.Namespace)
		assert.Nil(t, err, "nil")
	}
}

// STATUS: DONE
// 1. Create: Create SR / SRB with valid AD
// Initial: No AD, SR, SRB existing
// Input actions: Create AD with roles and policies
// Output: SR / SRB created with matching rules and bindings
func TestServiceRoleAndBindingCreation(t *testing.T) {
	adPair := fixtures.CreateAthenzDomain(&fixtures.Override{})
	rolloutAndValidate(t, adPair, create)
	cleanup(t, adPair)
}

// STATUS: IN PROGRESS
// TODO, make sure srb is not there
// 1.1 Create: Create SR only if there are no role members for SRB creation
// Initial: No AD, SR, SRB existing
// Input actions: Created AD with policies
// Output: SR created with matching rules
func TestServiceRoleOnlyCreation(t *testing.T) {
	o := &fixtures.Override{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.Domain.Roles[0].RoleMembers = []*zms.RoleMember{}
		},
	}
	adPair := fixtures.CreateAthenzDomain(o)
	rolloutAndValidate(t, adPair, create)
	cleanup(t, adPair)
}

// STATUS: DONE
// 2. Update: Update existing roles / policy
// Initial: Existing AD, SR, SRB
// Input Actions: Update AD with additional roles, policies
// Output: SR / SRB updated with matching rules and bindings
func TestUpdateRoleAssertion(t *testing.T) {
	adPair := fixtures.CreateAthenzDomain(&fixtures.Override{})
	rolloutAndValidate(t, adPair, create)

	o := &fixtures.Override{
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

	adPair = fixtures.CreateAthenzDomain(o)

	spew.Dump(adPair)
	rolloutAndValidate(t, adPair, update)
	cleanup(t, adPair)
}

// STATUS: IN PROGRESS
// 2.1 Update: Update existing assertion / role member / action
func TestUpdateAssertionRoleMemberAction(t *testing.T) {
	adPair := fixtures.CreateAthenzDomain(&fixtures.Override{})
	rolloutAndValidate(t, adPair, create)

	o := &fixtures.Override{
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

	adPair = fixtures.CreateAthenzDomain(o)
	rolloutAndValidate(t, adPair, update)
	cleanup(t, adPair)
}

// 2.2 Update: Delete existing roleMember / assertion
func TestUpdateDeleteRoleMember(t *testing.T) {

	o := &fixtures.Override{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			roleMember := &zms.RoleMember{
				MemberName: zms.MemberName("user.bar"),
			}
			signedDomain.Domain.Roles[0].RoleMembers = append(signedDomain.Domain.Roles[0].RoleMembers, roleMember)
		},
		ModifySRAndSRBPair: []func(sr *v1alpha1.ServiceRole, srb *v1alpha1.ServiceRoleBinding){
			func(sr *v1alpha1.ServiceRole, srb *v1alpha1.ServiceRoleBinding) {
				srb.Subjects = append(srb.Subjects, &v1alpha1.Subject{
					User: "user/sa/bar",
				})
			},
		},
	}

	adPair := fixtures.CreateAthenzDomain(o)
	rolloutAndValidate(t, adPair, create)

	adPair = fixtures.CreateAthenzDomain(&fixtures.Override{})
	rolloutAndValidate(t, adPair, update)
	cleanup(t, adPair)
}

// 2.3 Update: Add unrelated AD changes (not conformant to RBAC)
func TestUpdateUnrelatedADField(t *testing.T) {
	ogPair := fixtures.CreateAthenzDomain(&fixtures.Override{})
	rolloutAndValidate(t, ogPair, create)

	o := &fixtures.Override{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.KeyId = "col-env-1.2"
		},
	}

	// TODO, hacky?
	adPair := fixtures.CreateAthenzDomain(o)
	ogPair.AD = adPair.AD

	rolloutAndValidate(t, ogPair, update)
	cleanup(t, ogPair)
}

func checkDeletion(t *testing.T, configs []model.Config) {
	for _, config := range configs {
		c := framework.Global.IstioClientset.Get(config.Type, config.Name, config.Namespace)
		assert.Nil(t, c, "should be nil")
	}
}

// 2.4 Update: Update role name and expect the old SR/SRB to be deleted
func TestUpdateRoleName(t *testing.T) {
	ogPair := fixtures.CreateAthenzDomain(&fixtures.Override{})
	rolloutAndValidate(t, ogPair, create)

	o := &fixtures.Override{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Role = "athenz.domain:role.client-reader-role"
			signedDomain.Domain.Roles[0].Name = "athenz.domain:role.client-reader-role"
		},
	}

	adPair := fixtures.CreateAthenzDomain(o)
	ogPair.AD = adPair.AD
	rolloutAndValidate(t, ogPair, update)
	checkDeletion(t, ogPair.ModelConfigs)
	cleanup(t, adPair)
}

// 2.5 Update: Test updates with multiple namespaces / AD
func TestMultipleAD(t *testing.T) {
	ogPair := fixtures.CreateAthenzDomain(&fixtures.Override{})
	rolloutAndValidate(t, ogPair, create)

	o := &fixtures.Override{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.Domain.Name = "athenz.domain.one"
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Role = "athenz.domain.one:role.client-reader-role"
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Resource = "athenz.domain.one:svc.my-service-name"
			signedDomain.Domain.Roles[0].Name = "athenz.domain.one:role.client-reader-role"
		},
	}

	adPairTwo := fixtures.CreateAthenzDomain(o)
	rolloutAndValidate(t, adPairTwo, create)

	o = &fixtures.Override{
		ModifyAD: func(signedDomain *zms.SignedDomain) {
			signedDomain.Domain.Name = "athenz.domain.two"
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Role = "athenz.domain.two:role.client-reader-role"
			signedDomain.Domain.Policies.Contents.Policies[0].Assertions[0].Resource = "athenz.domain.two:svc.my-service-name"
			signedDomain.Domain.Roles[0].Name = "athenz.domain.two:role.client-reader-role"
		},
	}

	adPairThree := fixtures.CreateAthenzDomain(o)
	rolloutAndValidate(t, adPairThree, create)

	cleanup(t, ogPair)
	cleanup(t, adPairTwo)
	cleanup(t, adPairThree)
}

// 3.1 Delete
//Initial: Existing AD, SR, SRB
//Input Actions: Delete entire AD
//Output: SR / SRB deleted in namespace
func TestAthenzDomainDelete(t *testing.T) {
	adPair := fixtures.CreateAthenzDomain(&fixtures.Override{})
	rolloutAndValidate(t, adPair, create)

	err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Delete(adPair.AD.Name, &v1.DeleteOptions{})
	assert.Nil(t, err, "not nil")

	// TODO, once we fix the logic this should no longer exist
	validateConfigs(t, adPair)
}

// 3.1 Delete: Delete SR / SRB if AD still exists, expect the controller to sync it back
func TestDeleteSRAndSRB(t *testing.T) {
	adPair := fixtures.CreateAthenzDomain(&fixtures.Override{})
	rolloutAndValidate(t, adPair, create)

	for _, curr := range adPair.ModelConfigs {
		err := framework.Global.IstioClientset.Delete(curr.Type, curr.Name, curr.Namespace)
		assert.Nil(t, err, "nil")
	}

	rolloutAndValidate(t, adPair, noop)
}
