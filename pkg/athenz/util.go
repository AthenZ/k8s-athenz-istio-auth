// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package athenz

import "strings"

// DomainToNamespace will convert an athenz domain to a kubernetes namespace. Dots are converted to dashes
// and dashes are converted to double dashes.
// ex: k8s.athenz-istio-auth -> k8s-athenz--istio--auth
func DomainToNamespace(domain string) (namespace string) {
	dubdash := strings.Replace(domain, "-", "--", -1)
	return strings.Replace(dubdash, ".", "-", -1)
}

// NamespaceToDomain will convert the kubernetes namespace to an athenz domain. Dashes are converted to dots and
// double dashes are converted to single dashes.
// ex: k8s-athenz--istio--auth -> k8s.athenz-istio-auth
func NamespaceToDomain(ns string) (domain string) {
	dotted := strings.Replace(ns, "-", ".", -1)
	return strings.Replace(dotted, "..", "-", -1)
}

func DomainToNamespaceForSystemComponents(domain string) (namespace string) {
	substring := strings.Split(domain, ".")
	namespace = substring[len(substring)-1]
	return
}
