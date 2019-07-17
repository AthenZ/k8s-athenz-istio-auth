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
	allUsers        = "user.*"
	WildCardAll     = "*"
	ServiceRoleKind = "ServiceRole"
)

// parseMemberName parses the Athenz role member into a SPIFFE compliant name
func parseMemberName(member *zms.RoleMember) (string, error) {

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

// GetServiceRoleBindingSpec returns the ServiceRoleBindingSpec for a given Athenz role and its members
func GetServiceRoleBindingSpec(roleName string, members []*zms.RoleMember) (*v1alpha1.ServiceRoleBinding, error) {

	subjects := make([]*v1alpha1.Subject, 0)
	for _, member := range members {

		//TODO: handle member.Expiration for expired members, for now ignore expiration

		memberName, err := parseMemberName(member)
		if err != nil {
			log.Warningln(err.Error())
			continue
		}

		subject := &v1alpha1.Subject{
			User: memberName,
		}

		subjects = append(subjects, subject)
	}

	if len(subjects) == 0 {
		return nil, fmt.Errorf("no subjects found for the ServiceRoleBinding: %s", roleName)
	}

	roleRef := &v1alpha1.RoleRef{
		Kind: ServiceRoleKind,
		Name: roleName,
	}
	spec := &v1alpha1.ServiceRoleBinding{
		RoleRef:  roleRef,
		Subjects: subjects,
	}
	return spec, nil
}
