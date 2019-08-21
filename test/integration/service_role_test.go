package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"time"
)

// TODO, logging for callback weird [controller.(*Controller).getCallbackHandler/controller.go] [func1]
// TODO, look into logrus function logging
// TODO, should we sync if athenz domain is not found but namespace is there?

func expectedModelConfigs(t *testing.T, input []model.Config) {
	for _, curr := range input {
		got := framework.Global.IstioClientset.Get(curr.Type, curr.Name, "athenz-domain")
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

// Test case:
// Initial: No AD, SR, SRB existing
// Input Actions: Create AD with roles and policies
// Output: SR / SRB created with matching rules and bindings
func TestServiceRoleAndBindingCreation(t *testing.T) {
	_, configs, err := fixtures.CreateAthenzDomain(framework.Global.AthenzDomainClientset)
	if err != nil {
		t.Error(err)
	}
	time.Sleep(time.Second * 5)
	expectedModelConfigs(t, configs)
	deleteResources(t, configs)
}

func TestServiceRoleOnlyCreation(t *testing.T) {
	_, configs, err := fixtures.CreateAthenzDomainSROnly(framework.Global.AthenzDomainClientset)
	if err != nil {
		t.Error(err)
	}
	time.Sleep(time.Second * 5)
	expectedModelConfigs(t, configs)
	deleteResources(t, configs)
}

func TestUpdateRoleAssertion(t *testing.T) {
	ad, configs, err := fixtures.CreateAthenzDomain(framework.Global.AthenzDomainClientset)
	if err != nil {
		t.Error(err)
	}
	time.Sleep(time.Second * 5)
	expectedModelConfigs(t, configs)

	ad, err = framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Get(ad.Name, v1.GetOptions{})
	assert.Nil(t, err, "error should be nil")

	policy := fixtures.GetNewPolicy()
	ad.Spec.Domain.Policies.Contents.Policies = append(ad.Spec.Domain.Policies.Contents.Policies, policy)

	_, err = framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Update(ad)
	assert.Nil(t, err, "error should be nil")
	time.Sleep(time.Second * 5)

	configs[0] = fixtures.GetExpectedSR()
	expectedModelConfigs(t, configs)
	deleteResources(t, configs)
}
