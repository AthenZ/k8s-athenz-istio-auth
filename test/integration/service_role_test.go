package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"
	athenzdomain "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	"time"
)

// TODO, logging for callback weird [controller.(*Controller).getCallbackHandler/controller.go] [func1]
// TODO, look into logrus function logging
// TODO, should we sync if athenz domain is not found but namespace is there and delete sr / srb? https://github.com/yahoo/k8s-athenz-istio-auth/blob/master/pkg/controller/controller.go#L163-L167
// TODO, figure out why the warnings disappeared
// TODO, make the integration go.mod point to the local authz controller as opposed to the version
// TODO, add for loop to wait for athenz domain created
// TODO, validate if role actually exists from policy / assertion

func expectedModelConfigs(t *testing.T, input []model.Config) {
	for _, curr := range input {
		got := framework.Global.IstioClientset.Get(curr.Type, curr.Name, curr.Namespace)
		assert.NotNil(t, got, "not nil")
		curr.ResourceVersion = got.ResourceVersion
		curr.CreationTimestamp = got.CreationTimestamp
		assert.Equal(t, curr, *got, "should be equal")
	}
}

func deleteResources(t *testing.T, input []model.Config) {
	err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Delete("athenz.domain", &v1.DeleteOptions{})
	assert.Nil(t, err, "nil")

	for _, curr := range input {
		err := framework.Global.IstioClientset.Delete(curr.Type, curr.Name, "athenz-domain")
		assert.Nil(t, err, "nil")
	}
}

func updateAD(t *testing.T, ad *athenzdomain.AthenzDomain, modify func(ad *athenzdomain.AthenzDomain)) {
	ad, err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Get(ad.Name, v1.GetOptions{})
	assert.Nil(t, err, "error should be nil")

	modify(ad)

	_, err = framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Update(ad)
	assert.Nil(t, err, "error should be nil")
	time.Sleep(time.Second * 5)
}

// 1. Test case:
// Initial: No AD, SR, SRB existing
// Input Actions: Create AD with roles and policies
// Output: SR / SRB created with matching rules and bindings
func TestServiceRoleAndBindingCreation(t *testing.T) {
	_, configs, err := fixtures.CreateAthenzDomain(framework.Global.AthenzDomainClientset)
	assert.Nil(t, err, "should be nil")
	time.Sleep(time.Second * 5)
	expectedModelConfigs(t, configs)
	deleteResources(t, configs)
}

// 1.1 Create SR only if there are no role members for SRB creation
// TODO, make sure srb is not there
func TestServiceRoleOnlyCreation(t *testing.T) {
	_, configs, err := fixtures.CreateAthenzDomainSROnly(framework.Global.AthenzDomainClientset, func(signedDomain *zms.SignedDomain) {
		signedDomain.Domain.Roles[0].RoleMembers = []*zms.RoleMember{}
	})
	assert.Nil(t, err, "should be nil")
	time.Sleep(time.Second * 10)
	expectedModelConfigs(t, configs)
	deleteResources(t, configs)
}

// 2. Test case:
// Initial: Existing AD, SR, SRB
// Input Actions: Update AD with additional roles, policies
// Output: SR / SRB updated with matching rules and bindings
func TestUpdateRoleAssertion(t *testing.T) {
	ad, configs, err := fixtures.CreateAthenzDomain(framework.Global.AthenzDomainClientset)
	assert.Nil(t, err, "should be nil")
	time.Sleep(time.Second * 5)
	expectedModelConfigs(t, configs)

	updateAD(t, ad, func(ad *athenzdomain.AthenzDomain) {
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
		ad.Spec.Domain.Policies.Contents.Policies = append(ad.Spec.Domain.Policies.Contents.Policies, policy)
	})

	configs[0], err = fixtures.GetExpectedSR(configs[0], func(sr *v1alpha1.ServiceRole) {
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
	})
	assert.Nil(t, err, "should be nil")

	expectedModelConfigs(t, configs)
	deleteResources(t, configs)
}

// 2.1 Update existing assertion / roleMember / action
func TestUpdateRoleMember(t *testing.T) {
	ad, configs, err := fixtures.CreateAthenzDomain(framework.Global.AthenzDomainClientset)
	assert.Nil(t, err, "should be nil")
	time.Sleep(time.Second * 5)
	expectedModelConfigs(t, configs)

	updateAD(t, ad, func(ad *athenzdomain.AthenzDomain) {
		roleMember := &zms.RoleMember{
			MemberName: zms.MemberName("user.bar"),
		}
		ad.Spec.Domain.Roles[0].RoleMembers = append(ad.Spec.Domain.Roles[0].RoleMembers, roleMember)
	})

	configs[1], err = fixtures.GetExpectedSRB(configs[1], func(srb *v1alpha1.ServiceRoleBinding) {
		srb.Subjects = append(srb.Subjects, &v1alpha1.Subject{
			User: "user/sa/bar",
		})
	})
	assert.Nil(t, err, "should be nil")

	expectedModelConfigs(t, configs)
	deleteResources(t, configs)
}

// 2.2 Delete existing roleMember / assertion
func TestUpdateDeleteRoleMember(t *testing.T) {
	ad, configs, err := fixtures.CreateAthenzDomain(framework.Global.AthenzDomainClientset)
	assert.Nil(t, err, "should be nil")
	time.Sleep(time.Second * 5)
	expectedModelConfigs(t, configs)
	original := configs[1]

	updateAD(t, ad, func(ad *athenzdomain.AthenzDomain) {
		roleMember := &zms.RoleMember{
			MemberName: zms.MemberName("user.bar"),
		}
		ad.Spec.Domain.Roles[0].RoleMembers = append(ad.Spec.Domain.Roles[0].RoleMembers, roleMember)
	})

	configs[1], err = fixtures.GetExpectedSRB(configs[1], func(srb *v1alpha1.ServiceRoleBinding) {
		srb.Subjects = append(srb.Subjects, &v1alpha1.Subject{
			User: "user/sa/bar",
		})
	})
	assert.Nil(t, err, "should be nil")

	expectedModelConfigs(t, configs)

	updateAD(t, ad, func(ad *athenzdomain.AthenzDomain) {
		ad.Spec.Domain.Roles[0].RoleMembers = ad.Spec.Domain.Roles[0].RoleMembers[0:1]
	})

	// TODO, fix expected check
	configs[1] = original
	//expectedModelConfigs(t, configs)
	deleteResources(t, configs)
}
