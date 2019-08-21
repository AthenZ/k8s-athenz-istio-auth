package integration

import (
	"log"
	"testing"

	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"
			"istio.io/istio/pilot/pkg/model"
)

// Test case:
// Initial: No AD, SR, SRB existing
// Input Actions: Create AD with roles and policies
// Output: SR / SRB created with matching rules and bindings
func TestServiceRoleAndBindingCreation(t *testing.T) {
	//serviceRole := fixtures.GetServiceRole()
	//// TODO, make this consistent with the common library
	//srConfig := common.NewConfig(model.ServiceRole.Type, "default", "athenz.domain", serviceRole)
	//
	//_, err := framework.Global.IstioClientset.Create(srConfig)
	//if err != nil {
	//	t.Error()
	//}

	got := framework.Global.IstioClientset.Get(model.ServiceRole.Type, "default", "default")
	log.Println("got:", got)
}
