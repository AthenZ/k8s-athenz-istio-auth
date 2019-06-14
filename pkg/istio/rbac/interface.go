package rbac

import (
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"

	"istio.io/istio/pilot/pkg/model"
)

type Provider interface {

	// ConvertAthenzModelIntoIstioRbac converts the given Athenz model into a list of Istio type RBAC resources
	// Any implementation should return exactly the same list of output resources for a given Athenz model
	ConvertAthenzModelIntoIstioRbac(model athenz.Model) []model.Config
}
