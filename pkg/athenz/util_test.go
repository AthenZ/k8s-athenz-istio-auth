// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package athenz

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDomainNamespaceMap(t *testing.T) {
	assert.Equal(t, "foo-bar-baz", DomainToNamespace("foo.bar.baz"))
	assert.Equal(t, "foo-bar--baz", DomainToNamespace("foo.bar-baz"))
	assert.Equal(t, "foo.bar.baz", NamespaceToDomain("foo-bar-baz"))
	assert.Equal(t, "foo.bar-baz", NamespaceToDomain("foo-bar--baz"))
}

func TestDomainNamespaceMapForCloud(t *testing.T) {
	assert.Equal(t, "bar-baz", DomainToNamespaceForSystemComponents("foo.bar-baz"))
	assert.Equal(t, "bar--baz", DomainToNamespaceForSystemComponents("foo.bar--baz"))
	assert.Equal(t, "bar", DomainToNamespaceForSystemComponents("foo.bar"))
	assert.Equal(t, "bar", DomainToNamespaceForSystemComponents("bar"))
}
