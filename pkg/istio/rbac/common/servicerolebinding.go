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

// memberToSpiffe parses the Athenz role member into a SPIFFE compliant name.
// Example: example.domain/sa/service
func memberToSpiffe(member *zms.RoleMember) (string, error) {

	if member == nil {
		return "", fmt.Errorf("member is nil")
	}

	memberStr := string(member.MemberName)

	// special condition: if member == 'user.*', return '*'
	if memberStr == allUsers {
		return WildCardAll, nil
	}

	return PrincipalToSpiffe(memberStr)
}

// memberToOriginSubject parses the Athenz role member into the request.auth.principal
// jwt format. Example: athenz/example.domain.service
func memberToOriginJwtSubject(member *zms.RoleMember) (string, error) {

	if member == nil {
		return "", fmt.Errorf("member is nil")
	}

	memberStr := string(member.MemberName)

	// special condition: if member == 'user.*', return '*'
	if memberStr == allUsers {
		return WildCardAll, nil
	}

	requestAuthPrincipal := AthenzJwtPrefix + memberStr
	return requestAuthPrincipal, nil
}

// GetServiceRoleBindingSpec returns the ServiceRoleBindingSpec for a given Athenz role and its members
func GetServiceRoleBindingSpec(k8sRoleName string, members []*zms.RoleMember, enableOriginJwtSubject bool) (*v1alpha1.ServiceRoleBinding, error) {

	subjects := make([]*v1alpha1.Subject, 0)
	for _, member := range members {

		//TODO: handle member.Expiration for expired members, for now ignore expiration

		spiffeName, err := memberToSpiffe(member)
		if err != nil {
			log.Warningln(err.Error())
			continue
		}

		spiffeSubject := &v1alpha1.Subject{
			User: spiffeName,
		}
		subjects = append(subjects, spiffeSubject)

		if enableOriginJwtSubject {
			originJwtName, err := memberToOriginJwtSubject(member)
			if err != nil {
				log.Warningln(err.Error())
				continue
			}

			originJwtSubject := &v1alpha1.Subject{
				Properties: map[string]string{
					RequestAuthPrincipalProperty: originJwtName,
				},
			}

			// Spiffe and request auth principal subjects MUST be separate or else
			// the user needs to provide both the certificate and the jwt token. If
			// one subject is used, the source.principal and request.auth.principal
			// in the envoy rbac is grouped together into one id principal array as
			// opposed to being separated to allow either to go through.
			subjects = append(subjects, originJwtSubject)
		}
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
