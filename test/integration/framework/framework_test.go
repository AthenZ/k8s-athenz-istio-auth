// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.

package framework

import (
	"testing"

	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
)

func TestApiServer(t *testing.T) {
	f, err := Setup()
	if err != nil {
		t.Error(err)
	}
	defer f.Teardown()
	fixtures.CreateAthenzDomain(f.AthenzDomainClientset)
}
