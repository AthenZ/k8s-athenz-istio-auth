// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.

package framework

import (
	"log"
	"testing"

	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
)

func TestApiServer(t *testing.T) {
	f, err := Setup()
	if err != nil {
		t.Error(err)
	}
	//defer f.Teardown()
	fixtures.CreateAthenzDomain(f.AthenzDomainClientset)

	configDescriptor := model.ConfigDescriptor{
		model.ServiceRole,
		model.ServiceRoleBinding,
		model.ClusterRbacConfig,
	}

	istioClient, err := crd.NewClient("/Users/mcieplak/.kube/config", "default-context", configDescriptor, "svc.cluster.local")
	if err != nil {
		log.Printf("Error creating istio crd client: %s", err.Error())
	}

	schema, _ := model.IstioConfigTypes.GetByType(model.ServiceRole.Type)

	meta := model.ConfigMeta{
		Type:    schema.Type,
		Group:   schema.Group + model.IstioAPIGroupDomain,
		Version: schema.Version,
		Name:    "test",
	}
	foo := model.Config{
		ConfigMeta: meta,
		Spec: &v1alpha1.ServiceRole{
			Rules: []*v1alpha1.AccessRule{
				{
					Methods: []string{
						"PUT",
					},
					Services: []string{"*"},
					Constraints: []*v1alpha1.AccessRule_Constraint{
						{
							Key: "foo",
							Values: []string{
								"my-service-name",
							},
						},
					},
				},
			},
		},
	}

	_, err = istioClient.Create(foo)
	if err != nil {
		log.Println("err creating service role:", err)
		return
	}

	modelConfig := istioClient.Get(model.ServiceRole.Type, "test", "default")
	log.Println("modelConfig:", modelConfig)
}
