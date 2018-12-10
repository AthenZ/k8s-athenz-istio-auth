// Copyright 2018, Oath Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package servicerole

import (
	"errors"
	"log"
	"reflect"
	"strings"

	"k8s.io/api/core/v1"

	"github.com/yahoo/athenz/clients/go/zms"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
)

var client *crd.Client

func init() {
	var err error
	client, err = crd.NewClient("", "", model.IstioConfigTypes, "svc.cluster.local")
	if err != nil {
		log.Panicln(err)
	}
}

type ServiceRoleInfo struct {
	ServiceRole model.Config
	Processed   bool
}

// GetServiceRoleMap creates a map of the form servicerolename-namespace:servicerole for quick lookup
func GetServiceRoleMap() (map[string]*ServiceRoleInfo, error) {
	serviceRoleMap := make(map[string]*ServiceRoleInfo)

	serviceRoleList, err := client.List(model.ServiceRole.Type, v1.NamespaceAll)
	if err != nil {
		return serviceRoleMap, err
	}

	for _, serviceRole := range serviceRoleList {
		serviceRoleInfo := &ServiceRoleInfo{
			ServiceRole: serviceRole,
		}
		serviceRoleMap[serviceRole.Name+"-"+serviceRole.Namespace] = serviceRoleInfo
	}
	return serviceRoleMap, nil
}

// createServiceRole will construct the config meta and service role objects
func createServiceRole(namespace, role string, policy *zms.Policy) (model.ConfigMeta, *v1alpha1.ServiceRole, error) {
	configMeta := model.ConfigMeta{
		Type:      model.ServiceRole.Type,
		Name:      role,
		Group:     model.ServiceRole.Group + model.IstioAPIGroupDomain,
		Version:   model.ServiceRole.Version,
		Namespace: namespace,
	}

	methods := make([]string, 0)
	for _, assertion := range policy.Assertions {
		methods = append(methods, strings.ToUpper(assertion.Action))
	}

	// ex: sa.namespace.svc.cluster.local
	splitArray := strings.Split(role, ".")
	if len(splitArray) == 1 {
		return configMeta, nil, errors.New("Error splitting on . character")
	}

	sa := splitArray[len(splitArray)-1]
	if sa == "" {
		return configMeta, nil, errors.New("Could not get sa from role: " + role)
	}

	service := sa + "." + namespace + ".svc.cluster.local"
	serviceRole := &v1alpha1.ServiceRole{
		Rules: []*v1alpha1.AccessRule{{Services: []string{service}, Methods: methods}},
	}

	return configMeta, serviceRole, nil
}

// CreateServiceRole is responsible for creating the service role object in the k8s cluster
func CreateServiceRole(namespace, role string, policy *zms.Policy) error {
	configMeta, serviceRole, err := createServiceRole(namespace, role, policy)
	if err != nil {
		return err
	}

	_, err = client.Create(model.Config{
		ConfigMeta: configMeta,
		Spec:       serviceRole,
	})
	return err
}

// UpdateServiceRole is responsible for updating the service role object in the k8s cluster
func UpdateServiceRole(serviceRole model.Config, role string, policy *zms.Policy) (bool, error) {
	currentServiceRole, ok := serviceRole.Spec.(*v1alpha1.ServiceRole)
	if !ok {
		return false, errors.New("Could not cast to ServiceRole")
	}

	configMeta, newServiceRole, err := createServiceRole(serviceRole.Namespace, role, policy)
	if err != nil {
		return false, err
	}

	if !reflect.DeepEqual(currentServiceRole, newServiceRole) {
		configMeta.ResourceVersion = serviceRole.ResourceVersion
		_, err := client.Update(model.Config{
			ConfigMeta: configMeta,
			Spec:       newServiceRole,
		})
		if err != nil {
			return false, err
		}
		return true, err
	}

	return false, nil
}

// DeleteServiceRole is responsible for deleting the service role object in the k8s cluster
func DeleteServiceRole(name, namespace string) error {
	return client.Delete(model.ServiceRole.Type, name, namespace)
}
