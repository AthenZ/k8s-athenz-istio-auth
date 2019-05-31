// Copyright 2018, Oath Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package servicerolebinding

import (
	"errors"
	"log"
	"reflect"
	"strings"

	"k8s.io/api/core/v1"

	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/util"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
)

const (
	allUsers = "user.*"
)

type ServiceRoleBindingMgr struct {
	client *crd.Client
	store  model.ConfigStoreCache
}

type ServiceRoleBindingInfo struct {
	ServiceRoleBinding model.Config
	Processed          bool
}

// NewServiceRoleBindingMgr initializes the ServiceRoleBindingMgr object
func NewServiceRoleBindingMgr(client *crd.Client, store model.ConfigStoreCache) *ServiceRoleBindingMgr {
	return &ServiceRoleBindingMgr{
		client: client,
		store:  store,
	}
}

// GetServiceRoleBindingMap creates a map of the form servicerolebindingname-namespace:servicerolebinding for
// quick lookup
func (srbMgr *ServiceRoleBindingMgr) GetServiceRoleBindingMap() (map[string]*ServiceRoleBindingInfo, error) {
	serviceRoleBindingMap := make(map[string]*ServiceRoleBindingInfo)
	// TODO, use the store
	serviceRoleBindingList, err := srbMgr.store.List(model.ServiceRoleBinding.Type, v1.NamespaceAll)
	if err != nil {
		return serviceRoleBindingMap, err
	}

	for _, serviceRoleBinding := range serviceRoleBindingList {
		serviceRoleBindingInfo := &ServiceRoleBindingInfo{
			ServiceRoleBinding: serviceRoleBinding,
		}
		serviceRoleBindingMap[serviceRoleBinding.Name+"-"+serviceRoleBinding.Namespace] = serviceRoleBindingInfo
	}
	return serviceRoleBindingMap, nil
}

// getSubjects processes the members of a role and creates the corresponding subject object which will be used in the
// service role binding
func (srbMgr *ServiceRoleBindingMgr) getSubjects(members []zms.MemberName) []*v1alpha1.Subject {
	subjects := make([]*v1alpha1.Subject, 0)

	// return * subject if one of the members is user.*
	for _, member := range members {
		if string(member) == allUsers {
			return []*v1alpha1.Subject{
				{
					User: "*",
				},
			}
		}
	}

	// ex: cluster.local/ns/namespace/sa/serviceaccountname
	for _, member := range members {
		splitArray := strings.Split(string(member), ".")
		if len(splitArray) == 0 {
			log.Println("Error splitting on . character for member:", string(member))
			continue
		}

		sa := splitArray[len(splitArray)-1]
		if sa == "" {
			log.Println("Could not get sa from member:", string(member))
			continue
		}

		tempNamespace := splitArray[:len(splitArray)-1]
		namespace := strings.Join(tempNamespace, "-")
		if namespace == "" {
			log.Println("Could not get namespace from member:", string(member))
			continue
		}

		// user := "cluster.local/ns/" + namespace + "/sa/" + sa
		domain := util.NamespaceToDomain(namespace)
		user := domain + "/sa/" + sa
		subject := &v1alpha1.Subject{
			User: user,
		}
		subjects = append(subjects, subject)
	}
	return subjects
}

// createServiceRoleBinding will construct the config meta and service role binding objects
func (srbMgr *ServiceRoleBindingMgr) createServiceRoleBinding(namespace, role string, members []zms.MemberName) (model.ConfigMeta, *v1alpha1.ServiceRoleBinding) {
	configMeta := model.ConfigMeta{
		Type:      model.ServiceRoleBinding.Type,
		Name:      role,
		Group:     model.ServiceRoleBinding.Group + model.IstioAPIGroupDomain,
		Version:   model.ServiceRoleBinding.Version,
		Namespace: namespace,
	}

	subjects := srbMgr.getSubjects(members)

	// cluster.local/ns/namespace/sa/serviceaccountname
	serviceRoleBinding := &v1alpha1.ServiceRoleBinding{
		Subjects: subjects,
		RoleRef: &v1alpha1.RoleRef{
			Kind: "ServiceRole",
			Name: role,
		},
	}

	return configMeta, serviceRoleBinding
}

// CreateServiceRoleBinding is responsible for creating the service role binding object in the k8s cluster
func (srbMgr *ServiceRoleBindingMgr) CreateServiceRoleBinding(namespace, role string, members []zms.MemberName) error {
	configMeta, serviceRoleBinding := srbMgr.createServiceRoleBinding(namespace, role, members)
	_, err := srbMgr.client.Create(model.Config{
		ConfigMeta: configMeta,
		Spec:       serviceRoleBinding,
	})
	return err
}

// UpdateServiceRoleBinding is responsible for updating the service role binding object in the k8s cluster
func (srbMgr *ServiceRoleBindingMgr) UpdateServiceRoleBinding(serviceRoleBinding model.Config, namespace, role string, members []zms.MemberName) (bool, error) {
	needsUpdate := false
	currentServiceRoleBinding, ok := serviceRoleBinding.Spec.(*v1alpha1.ServiceRoleBinding)
	if !ok {
		return needsUpdate, errors.New("Could not cast to ServiceRoleBinding")
	}

	configMeta, newServiceRoleBinding := srbMgr.createServiceRoleBinding(namespace, role, members)
	if !reflect.DeepEqual(currentServiceRoleBinding, newServiceRoleBinding) {
		configMeta.ResourceVersion = serviceRoleBinding.ResourceVersion
		_, err := srbMgr.client.Update(model.Config{
			ConfigMeta: configMeta,
			Spec:       newServiceRoleBinding,
		})
		if err != nil {
			return false, err
		}
		return true, nil
	}

	return false, nil
}

// DeleteServiceRoleBinding is responsible for deleting the service role binding object in the k8s cluster
func (srbMgr *ServiceRoleBindingMgr) DeleteServiceRoleBinding(name, namespace string) error {
	return srbMgr.client.Delete(model.ServiceRoleBinding.Type, name, namespace)
}

func (srbMgr *ServiceRoleBindingMgr) EventHandler(config model.Config, e model.Event) {
	// TODO, add to workqueue
	log.Printf("Received %s update for servicerolebinding: %+v", e.String(), config)
}
