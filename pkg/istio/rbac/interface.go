// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package rbac

import (
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"

	"istio.io/istio/pilot/pkg/model"
)

type Provider interface {

	// ConvertAthenzModelIntoIstioRbac converts the given Athenz model into a list of Istio type RBAC resources
	// Any implementation should return exactly the same list of output resources for a given Athenz model
	ConvertAthenzModelIntoIstioRbac(model athenz.Model) []model.Config

	// GetCurrentIstioRbac returns the Istio RBAC custom resources associated with the given model
	GetCurrentIstioRbac(model athenz.Model, csc model.ConfigStoreCache) []model.Config
}
