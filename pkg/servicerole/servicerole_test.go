// Copyright 2018, Oath Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package servicerole

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
)

func TestCreateServiceRole(t *testing.T) {
	allow := zms.ALLOW
	policy := &zms.Policy{
		Name: "my.domain:policy.service.role.my.domain.details",
		Assertions: []*zms.Assertion{
			{
				Role:     "my.domain.details:role.",
				Resource: "my.domain.details:/details",
				Action:   "get",
				Effect:   &allow,
			},
			{
				Role:     "my.domain.details:role.",
				Resource: "my.domain.details:/details",
				Action:   "post",
				Effect:   &allow,
			},
		},
	}

	configMeta, serviceRole, err := createServiceRole("my-domain", "svc.cluster.local", "my.domain.details", policy)

	a := assert.New(t)
	a.Equal("my.domain.details", configMeta.Name)
	a.Equal("my-domain", configMeta.Namespace)
	a.Equal(serviceRole.Rules[0].Services, []string{"details.my-domain.svc.cluster.local"})
	a.Equal(serviceRole.Rules[0].Methods, []string{"GET", "POST"})
	a.Equal(serviceRole.Rules[0].Paths, []string{"/details"})
	a.Equal(nil, err)

	_, _, err = createServiceRole("my-domain", "svc.cluster.local", "", policy)
	a.Equal(errors.New("Error splitting on . character"), err)

	_, _, err = createServiceRole("my-domain", "svc.cluster.local", "foobar.", policy)
	a.Equal(errors.New("Could not get sa from role: foobar."), err)
}
