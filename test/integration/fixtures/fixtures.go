// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.

package fixtures

import (
	"log"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/yahoo/athenz/clients/go/zms"
	athenzdomain "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"fmt"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"strings"
)

// getAthenzDomainCrd returns the athenz domain custom resource definition
func getAthenzDomainCrd() *v1beta1.CustomResourceDefinition {
	return &v1beta1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "athenzdomains.athenz.io",
		},
		Spec: v1beta1.CustomResourceDefinitionSpec{
			Group: "athenz.io",
			Scope: v1beta1.ClusterScoped,
			Versions: []v1beta1.CustomResourceDefinitionVersion{
				{
					Name:    "v1",
					Served:  true,
					Storage: true,
				},
			},
			Names: v1beta1.CustomResourceDefinitionNames{
				Plural:     "athenzdomains",
				Singular:   "athenzdomain",
				Kind:       "AthenzDomain",
				ShortNames: []string{"domain"},
				ListKind:   "AthenzDomainList",
			},
		},
	}
}

// getServiceRoleCrd returns the service role custom resource definition
func getServiceRoleCrd() *v1beta1.CustomResourceDefinition {
	return &v1beta1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "serviceroles.rbac.istio.io",
		},
		Spec: v1beta1.CustomResourceDefinitionSpec{
			Group: "rbac.istio.io",
			Names: v1beta1.CustomResourceDefinitionNames{
				Plural:   "serviceroles",
				Singular: "servicerole",
				Kind:     "ServiceRole",
				Categories: []string{
					"istio-io",
					"rbac-istio-io",
				},
			},
			Scope: v1beta1.NamespaceScoped,
			Versions: []v1beta1.CustomResourceDefinitionVersion{
				{
					Name:    "v1alpha1",
					Served:  true,
					Storage: true,
				},
			},
		},
	}
}

// getServiceRoleBindingCrd returns the service role binding custom resource definition
func getServiceRoleBindingCrd() *v1beta1.CustomResourceDefinition {
	return &v1beta1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "servicerolebindings.rbac.istio.io",
		},
		Spec: v1beta1.CustomResourceDefinitionSpec{
			Group: "rbac.istio.io",
			Names: v1beta1.CustomResourceDefinitionNames{
				Plural:   "servicerolebindings",
				Singular: "servicerolebinding",
				Kind:     "ServiceRoleBinding",
				Categories: []string{
					"istio-io",
					"rbac-istio-io",
				},
			},
			Scope: v1beta1.NamespaceScoped,
			Versions: []v1beta1.CustomResourceDefinitionVersion{
				{
					Name:    "v1alpha1",
					Served:  true,
					Storage: true,
				},
			},
		},
	}
}

// getClusterRbacConfigCrd returns the cluster rbac config custom resource definition
func getClusterRbacConfigCrd() *v1beta1.CustomResourceDefinition {
	return &v1beta1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "clusterrbacconfigs.rbac.istio.io",
		},
		Spec: v1beta1.CustomResourceDefinitionSpec{
			Group: "rbac.istio.io",
			Names: v1beta1.CustomResourceDefinitionNames{
				Plural:   "clusterrbacconfigs",
				Singular: "clusterrbacconfig",
				Kind:     "ClusterRbacConfig",
				Categories: []string{
					"istio-io",
					"rbac-istio-io",
				},
			},
			Scope: v1beta1.ClusterScoped,
			Versions: []v1beta1.CustomResourceDefinitionVersion{
				{
					Name:    "v1alpha1",
					Served:  true,
					Storage: true,
				},
			},
		},
	}
}

// CreateCrds creates the athenz domain, service role, service role binding, and
// cluster rbac config custom resource definitions
func CreateCrds(clientset *apiextensionsclient.Clientset) error {
	athenzDomainCrd := getAthenzDomainCrd()
	serviceRoleCrd := getServiceRoleCrd()
	serviceRoleBindingCrd := getServiceRoleBindingCrd()
	clusterRbacConfigCrd := getClusterRbacConfigCrd()
	crds := []*v1beta1.CustomResourceDefinition{athenzDomainCrd, serviceRoleCrd, serviceRoleBindingCrd, clusterRbacConfigCrd}

	for _, crd := range crds {
		_, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Create(crd)
		if err != nil {
			return err
		}
	}
	return nil
}

func getExpectedSR() *v1alpha1.ServiceRole {
	return &v1alpha1.ServiceRole{
		Rules: []*v1alpha1.AccessRule{
			{
				Methods: []string{
					"PUT",
				},
				Services: []string{common.WildCardAll},
				Constraints: []*v1alpha1.AccessRule_Constraint{
					{
						Key: common.ConstraintSvcKey,
						Values: []string{
							"my-service-name",
						},
					},
				},
			},
		},
	}
}

func getExpectedSRB() *v1alpha1.ServiceRoleBinding {
	return &v1alpha1.ServiceRoleBinding{
		RoleRef: &v1alpha1.RoleRef{
			Name: "client-writer-role",
			Kind: common.ServiceRoleKind,
		},
		Subjects: []*v1alpha1.Subject{
			{
				User: "user/sa/foo",
			},
		},
	}
}

type AthenzDomainPair struct {
	AD           *athenzdomain.AthenzDomain
	ModelConfigs []model.Config
}

type Override struct {
	ModifyAD  func(signedDomain *zms.SignedDomain)
	ModifySR  func(sr *v1alpha1.ServiceRole)
	ModifySRB func(srb *v1alpha1.ServiceRoleBinding)
}

// CreateAthenzDomain creates an athenz domain custom resource
func CreateAthenzDomain(o *Override) *AthenzDomainPair {
	signedDomain := getFakeDomain()
	domainName := string(signedDomain.Domain.Name)

	if o.ModifyAD != nil {
		o.ModifyAD(&signedDomain)
	}

	ad := &athenzdomain.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: domainName,
		},
		Spec: athenzdomain.AthenzDomainSpec{
			SignedDomain: signedDomain,
		},
	}

	sr := getExpectedSR()
	if o.ModifySR != nil {
		o.ModifySR(sr)
	}

	ns := athenz.DomainToNamespace(domainName)
	roleFQDN := string(signedDomain.Domain.Roles[0].Name)
	roleName := strings.TrimPrefix(roleFQDN, fmt.Sprintf("%s:role.", domainName))
	modelSR := common.NewConfig(model.ServiceRole.Type, ns, roleName, sr)
	modelConfig := []model.Config{modelSR}

	// TODO, make more dynamic
	if len(signedDomain.Domain.Roles[0].RoleMembers) > 0 {
		srb := getExpectedSRB()
		if o.ModifySRB != nil {
			o.ModifySRB(srb)
		}
		srb.RoleRef.Name = modelSR.Name
		modelSRB := common.NewConfig(model.ServiceRoleBinding.Type, ns, roleName, srb)
		modelConfig = append(modelConfig, modelSRB)
	}

	return &AthenzDomainPair{
		AD:           ad,
		ModelConfigs: modelConfig,
	}
}

// getFakeDomain provides a populated fake domain object
func getFakeDomain() zms.SignedDomain {
	allow := zms.ALLOW
	timestamp, err := rdl.TimestampParse("2019-06-21T19:28:09.305Z")
	if err != nil {
		panic(err)
	}

	domainName := "athenz.domain"
	username := "user.foo"
	return zms.SignedDomain{
		Domain: &zms.DomainData{
			Modified: timestamp,
			Name:     zms.DomainName(domainName),
			Policies: &zms.SignedPolicies{
				Contents: &zms.DomainPolicies{
					Domain: zms.DomainName(domainName),
					Policies: []*zms.Policy{
						{
							Assertions: []*zms.Assertion{
								{
									Effect:   &allow,
									Action:   "put",
									Role:     "athenz.domain:role.client-writer-role",
									Resource: "athenz.domain:svc.my-service-name",
								},
							},
							Name: zms.ResourceName(domainName + ":policy.admin"),
						},
					},
				},
				KeyId:     "col-env-1.1",
				Signature: "signature-policy",
			},
			Roles: []*zms.Role{
				{
					Members: []zms.MemberName{zms.MemberName(username)},
					Name:    zms.ResourceName("athenz.domain:role.client-writer-role"),
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: zms.MemberName(username),
						},
					},
				},
			},
			Services: []*zms.ServiceIdentity{},
			Entities: []*zms.Entity{},
		},
		KeyId:     "colo-env-1.1",
		Signature: "signature",
	}
}

func CreateNamespace(clientset kubernetes.Interface) {
	for _, nsName := range []string{"athenz-domain", "athenz-domain-one", "athenz-domain-two"} {
		ns := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: nsName}}
		_, err := clientset.CoreV1().Namespaces().Create(ns)
		if err != nil {
			log.Println(err)
			return
		}
	}
}
