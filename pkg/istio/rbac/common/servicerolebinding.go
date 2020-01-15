// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package common

import (
	"fmt"

	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"

	"istio.io/api/rbac/v1alpha1"
)

const (
	allUsers                     = "user.*"
	WildCardAll                  = "*"
	ServiceRoleKind              = "ServiceRole"
	AthenzJwtPrefix              = "athenz/"
	RequestAuthPrincipalProperty = "request.auth.principal"
)

// parseMemberName parses the Athenz role member into a SPIFFE compliant name
func parseMemberName(member *zms.RoleMember) (string, string, error) {

	if member == nil {
		return "", "", fmt.Errorf("member is nil")
	}

	memberStr := string(member.MemberName)

	// special condition: if member == 'user.*', return '*'
	if memberStr == allUsers {
		return WildCardAll, WildCardAll, nil
	}

	spiffeName, err := PrincipalToSpiffe(memberStr)
	if err != nil {
		return "", "", err
	}

	requestAuthPrincipal := AthenzJwtPrefix + memberStr
	return spiffeName, requestAuthPrincipal, nil
}

// GetServiceRoleBindingSpec returns the ServiceRoleBindingSpec for a given Athenz role and its members
func GetServiceRoleBindingSpec(k8sRoleName string, members []*zms.RoleMember) (*v1alpha1.ServiceRoleBinding, error) {

	subjects := make([]*v1alpha1.Subject, 0)
	for _, member := range members {

		//TODO: handle member.Expiration for expired members, for now ignore expiration

		spiffeName, requestAuthPrincipal, err := parseMemberName(member)
		if err != nil {
			log.Warningln(err.Error())
			continue
		}

		// Spiffe and request auth principal subjects MUST be separate or else
		// the user needs to provide both the certificate and the jwt token. If
		// one subject is used, the source.principal and request.auth.principal
		// in the envoy rbac is grouped together into one id principal array as
		// opposed to being separated to allow either to go through.
		spiffeSubject := &v1alpha1.Subject{
			User: spiffeName,
		}

		requestAuthPrincipalSubject := &v1alpha1.Subject{
			Properties: map[string]string{
				RequestAuthPrincipalProperty: requestAuthPrincipal,
			},
		}

		subjects = append(subjects, spiffeSubject, requestAuthPrincipalSubject)
	}

	if len(subjects) == 0 {
		return nil, fmt.Errorf("no subjects found for the ServiceRoleBinding: %s", k8sRoleName)
	}

	roleRef := &v1alpha1.RoleRef{
		Kind: ServiceRoleKind,
		Name: k8sRoleName,
	}
	spec := &v1alpha1.ServiceRoleBinding{
		RoleRef:  roleRef,
		Subjects: subjects,
	}
	return spec, nil
}
