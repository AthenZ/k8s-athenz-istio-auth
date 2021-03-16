// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package common

import (
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"

	"istio.io/api/rbac/v1alpha1"
)

// GetServiceRoleBindingSpec returns the ServiceRoleBindingSpec for a given Athenz role and its members
func GetServiceRoleBindingSpec(athenzDomainName string, roleName string, k8sRoleName string, members []*zms.RoleMember, enableOriginJwtSubject bool) (*v1alpha1.ServiceRoleBinding, error) {

	subjects := make([]*v1alpha1.Subject, 0)
	for _, member := range members {

		//TODO: handle member.Expiration for expired members, for now ignore expiration

		spiffeName, err := MemberToSpiffe(member)
		if err != nil {
			log.Warningln(err.Error())
			continue
		}

		spiffeSubject := &v1alpha1.Subject{
			User: spiffeName,
		}
		subjects = append(subjects, spiffeSubject)

		if enableOriginJwtSubject {
			originJwtName, err := MemberToOriginJwtSubject(member)
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
		log.Warningln("no subjects found for the ServiceRoleBinding: %s", k8sRoleName)
	}

	//add role spiffee for role certificate
	roleSpiffeName, err := RoleToSpiffe(athenzDomainName, roleName)
	if err != nil {
		return nil, err
	}

	spiffeSubject := &v1alpha1.Subject{
		User: roleSpiffeName,
	}
	subjects = append(subjects, spiffeSubject)

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
