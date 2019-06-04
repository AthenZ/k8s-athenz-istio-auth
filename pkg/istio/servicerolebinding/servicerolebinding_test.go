// Copyright 2018, Oath Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package servicerolebinding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
)

var srbMgr = NewServiceRoleBindingMgr(nil)

func TestGetSubjects(t *testing.T) {
	subjects := srbMgr.getSubjects([]zms.MemberName{"domain.one.application1", "domain.two.application2"})

	a := assert.New(t)
	a.Equal("domain.one/sa/application1", subjects[0].User)
	a.Equal("domain.two/sa/application2", subjects[1].User)

	subjects = srbMgr.getSubjects([]zms.MemberName{"user.*"})
	a.Equal("*", subjects[0].User)

	subjects = srbMgr.getSubjects([]zms.MemberName{"domain"})
	a.Equal(0, len(subjects))

	subjects = srbMgr.getSubjects([]zms.MemberName{"domain."})
	a.Equal(0, len(subjects))
}

func TestCreateServiceRoleBinding(t *testing.T) {
	configMeta, serviceRoleBinding := srbMgr.createServiceRoleBinding("my-domain", "my.domain.details",
		[]zms.MemberName{"domain.one.application1", "domain.two.application2"})

	a := assert.New(t)
	a.Equal("my.domain.details", configMeta.Name)
	a.Equal("my-domain", configMeta.Namespace)
	a.Equal("my.domain.details", serviceRoleBinding.RoleRef.Name)
	a.Equal("domain.one/sa/application1", serviceRoleBinding.Subjects[0].User)
	a.Equal("domain.two/sa/application2", serviceRoleBinding.Subjects[1].User)
}
