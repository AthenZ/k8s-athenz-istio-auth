package integration

import (
	"log"
	"testing"

	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	"istio.io/istio/pilot/pkg/model"
)

// Test case:
// Initial: No AD, SR, SRB existing
// Input Actions: Create AD with roles and policies
// Output: SR / SRB created with matching rules and bindings
func TestServiceRoleAndBindingCreation(t *testing.T) {
	serviceRole := fixtures.GetServiceRole()
	// TODO, make this consistent with the common library
	srConfig := common.NewConfig(model.ServiceRole.Type, "default", "default", serviceRole)

	_, err := framework.F.IstioClientset.Create(srConfig)
	if err != nil {
		t.Error()
	}

	got := framework.F.IstioClientset.Get(model.ServiceRole.Type, "default", "default")
	log.Println("got:", got)
}
