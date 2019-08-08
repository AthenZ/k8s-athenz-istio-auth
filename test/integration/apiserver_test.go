// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.

// +build integration

package integration

import (
	"testing"

	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"
)

func TestApiServer(t *testing.T) {
	f, err := framework.RunApiServer()
	if err != nil {
		t.Error(err)
	}
	defer framework.ShutdownApiServer()
	fixtures.CreateAthenzDomain(f.AthenzDomainClientset)
}
