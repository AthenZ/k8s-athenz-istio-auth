// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package common

import (
	"fmt"
	"strings"

	"github.com/gogo/protobuf/proto"
	"github.com/yahoo/athenz/clients/go/zms"

	"istio.io/istio/pilot/pkg/model"
)

// ParseRoleFQDN parses the Athenz role full name in the format <domainName>:role.<roleName> to roleName
// e.g. app-domain:role.reader -> reader
func ParseRoleFQDN(domainName zms.DomainName, roleFQDN string) (string, error) {
	roleName := strings.TrimPrefix(roleFQDN, fmt.Sprintf("%s:role.", domainName))
	if strings.Contains(roleName, ":") {
		return "", fmt.Errorf("role: %s does not belong to the Athenz domain: %s", roleFQDN, domainName)
	}
	return roleName, nil
}

// PrincipalToSpiffe converts the Athenz principal into a SPIFFE compliant format
// e.g. client-domain.frontend.some-app -> client-domain.frontend/sa/some-app
func PrincipalToSpiffe(principal string) (string, error) {
	if len(principal) == 0 {
		return "", fmt.Errorf("principal is empty")
	}
	i := strings.LastIndex(principal, ".")
	if i < 0 {
		return "", fmt.Errorf("principal:%s is not of the format <Athenz-domain>.<Athenz-service>", principal)
	}
	memberDomain, memberService := principal[:i], principal[i+1:]
	spiffeName := fmt.Sprintf("%s/sa/%s", memberDomain, memberService)
	return spiffeName, nil
}

// NewConfig returns a new model.Config resource for the passed-in type with the given namespace/name and spec
func NewConfig(configType string, namespace string, name string, spec proto.Message) model.Config {

	schema, exists := model.IstioConfigTypes.GetByType(configType)
	if !exists {
		return model.Config{}
	}
	meta := model.ConfigMeta{
		Type:      schema.Type,
		Group:     schema.Group + model.IstioAPIGroupDomain,
		Version:   schema.Version,
		Namespace: namespace,
		Name:      name,
	}
	return model.Config{
		ConfigMeta: meta,
		Spec:       spec,
	}
}
