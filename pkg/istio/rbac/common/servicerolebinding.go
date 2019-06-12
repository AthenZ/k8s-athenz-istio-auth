// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package common

import (
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"

	"k8s.io/api/core/v1"

	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/util"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
)

const (
	allUsers        = "user.*"
	WildCardAll     = "*"
	ServiceRoleKind = "ServiceRole"
)

type ServiceRoleBindingMgr struct {
	store model.ConfigStoreCache
}

type ServiceRoleBindingInfo struct {
	ServiceRoleBinding model.Config
	Processed          bool
}

// NewServiceRoleBindingMgr initializes the ServiceRoleBindingMgr object
func NewServiceRoleBindingMgr(store model.ConfigStoreCache) *ServiceRoleBindingMgr {
	return &ServiceRoleBindingMgr{
		store: store,
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
			log.Println(err.Error())
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
	_, err := srbMgr.store.Create(model.Config{
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
		_, err := srbMgr.store.Update(model.Config{
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
	return srbMgr.store.Delete(model.ServiceRoleBinding.Type, name, namespace)
}

func (srbMgr *ServiceRoleBindingMgr) EventHandler(config model.Config, e model.Event) {
	// TODO, add to workqueue
	log.Printf("Received %s update for servicerolebinding: %+v", e.String(), config)
}
