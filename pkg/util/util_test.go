// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDomainNamespaceMap(t *testing.T) {
	a := assert.New(t)

	a.Equal("foo-bar-baz", DomainToNamespace("foo.bar.baz"))
	a.Equal("foo-bar--baz", DomainToNamespace("foo.bar-baz"))
	a.Equal("foo.bar.baz", NamespaceToDomain("foo-bar-baz"))
	a.Equal("foo.bar-baz", NamespaceToDomain("foo-bar--baz"))
}
