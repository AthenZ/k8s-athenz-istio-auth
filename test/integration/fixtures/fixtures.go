// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.

package fixtures

import (
	"github.com/ardielle/ardielle-go/rdl"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	securityV1beta1 "istio.io/api/security/v1beta1"
	istioTypeV1beta1 "istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/collections"
	v1 "k8s.io/api/core/v1"

	athenzdomain "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
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

// getAuthorizationPolicyCrd returns the Authorization policy custom resource definition
func getAuthorizationPolicyCrd() *v1beta1.CustomResourceDefinition {
	return &v1beta1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "authorizationpolicies.security.istio.io",
		},
		Spec: v1beta1.CustomResourceDefinitionSpec{
			Group: "security.istio.io",
			Names: v1beta1.CustomResourceDefinitionNames{
				Plural:   "authorizationpolicies",
				Singular: "authorizationpolicy",
				Kind:     "AuthorizationPolicy",
				Categories: []string{
					"istio-io",
					"security-istio-io",
				},
			},
			Scope: v1beta1.NamespaceScoped,
			Versions: []v1beta1.CustomResourceDefinitionVersion{
				{
					Name:    "v1beta1",
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
	authorizationPolicyCrd := getAuthorizationPolicyCrd()
	crds := []*v1beta1.CustomResourceDefinition{athenzDomainCrd, serviceRoleCrd, serviceRoleBindingCrd, clusterRbacConfigCrd, authorizationPolicyCrd}

	for _, crd := range crds {
		_, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Create(crd)
		if err != nil {
			return err
		}
	}
	return nil
}

// CreateNamespaces creates testing namespaces
func CreateNamespaces(clientset kubernetes.Interface) error {
	for _, nsName := range []string{"athenz-domain", "athenz-domain-one", "athenz-domain-two"} {
		ns := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: nsName,
			},
		}
		_, err := clientset.CoreV1().Namespaces().Create(ns)
		if err != nil {
			return err
		}
	}
	return nil
}

// getDefaultSignedDomain returns a default testing spec for a signed domain object
func getDefaultSignedDomain() zms.SignedDomain {
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
									Role:     domainName + ":role.client-writer-role",
									Resource: domainName + ":svc.my-service-name",
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
					Name:    zms.ResourceName(domainName + ":role.client-writer-role"),
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

type ExpectedServices struct {
	Services   []*v1.Service
	ServiceDNS []string
}

// GetExpectedServices returns an expected resources object which contains the
// services along with a list of their full DNS names
func GetExpectedServices(o []func(*v1.Service)) *ExpectedServices {
	var services []*v1.Service
	var serviceDNS []string

	if o == nil {
		o = []func(*v1.Service){
			func(s *v1.Service) {
			},
		}
	}

	for _, fn := range o {
		s := getDefaultService()
		fn(s)
		services = append(services, s)

		enabled := s.Annotations["authz.istio.io/enabled"]
		if enabled == "true" {
			serviceDNS = append(serviceDNS, s.Name+"."+s.Namespace+".svc.cluster.local")
		}
	}

	return &ExpectedServices{
		Services:   services,
		ServiceDNS: serviceDNS,
	}
}

// getDefaultService returns a default onboarded service object
func getDefaultService() *v1.Service {
	targetPort := intstr.IntOrString{
		Type:   intstr.Int,
		IntVal: 80,
	}

	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-service",
			Namespace: "athenz-domain",
			Annotations: map[string]string{
				"authz.istio.io/enabled": "true",
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: targetPort,
				},
			},
		},
	}
}

type ExpectedV2Rbac struct {
	AD                    *athenzdomain.AthenzDomain
	Services              []*v1.Service
	AuthorizationPolicies []*model.Config
}

type RbacV2Modifications struct {
	ModifyAthenzDomain          []func(signedDomain *zms.SignedDomain)
	ModifyServices              [][]func(service *v1.Service)
	ModifyAuthorizationPolicies [][]func(policy *securityV1beta1.AuthorizationPolicy)
}

func getExpectedAuthorizationPolicy(serviceName string, modifications []func(*securityV1beta1.AuthorizationPolicy)) *securityV1beta1.AuthorizationPolicy {
	authPolicy := &securityV1beta1.AuthorizationPolicy{
		Selector: &istioTypeV1beta1.WorkloadSelector{
			MatchLabels: map[string]string{
				"app": serviceName,
			},
		},
		Rules: []*securityV1beta1.Rule{
			&securityV1beta1.Rule{
				From: []*securityV1beta1.Rule_From{
					&securityV1beta1.Rule_From{
						Source: &securityV1beta1.Source{
							Principals: []string{
								"user/sa/foo",
								"athenz.cloud/ns/user/sa/user.foo",
								"athenz.cloud/ns/default/sa/user.foo",
								"*/sa/user.foo",
								"athenz.domain/ra/client-writer-role",
								"athenz.cloud/ns/athenz.domain/ra/client-writer-role",
							},
						},
					},
					&securityV1beta1.Rule_From{
						Source: &securityV1beta1.Source{
							RequestPrincipals: []string{
								"athenz/user.foo",
							},
						},
					},
				},
				To: []*securityV1beta1.Rule_To{
					&securityV1beta1.Rule_To{
						Operation: &securityV1beta1.Operation{
							Methods: []string{
								"PUT",
							},
						},
					},
				},
			},
		},
	}

	if modifications == nil {
		modifications = []func(policy *securityV1beta1.AuthorizationPolicy){}
	}

	for _, modify := range modifications {
		modify(authPolicy)
	}

	return authPolicy
}

func GetDefaultService(serviceName string, modifications []func(service *v1.Service)) *v1.Service {
	defaultService := getDefaultService()
	defaultService.Name = serviceName
	if defaultService.Labels == nil {
		defaultService.Labels = make(map[string]string)
	}
	defaultService.Labels["app"] = defaultService.Name
	defaultService.Labels["svc"] = defaultService.Name
	if modifications == nil {
		modifications = []func(service *v1.Service){}
	}
	for _, modify := range modifications {
		modify(defaultService)
	}
	return defaultService
}

func GetDefaultAthenzDomainForAuthorizationPolicies(athenzDomainModifications []func(signedDomain *zms.SignedDomain)) *athenzdomain.AthenzDomain {
	signedDomain := getDefaultSignedDomain()
	if athenzDomainModifications != nil {
		for _, f := range athenzDomainModifications {
			f(&signedDomain)
		}
	}
	domainName := string(signedDomain.Domain.Name)
	return &athenzdomain.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: domainName,
		},
		Spec: athenzdomain.AthenzDomainSpec{
			SignedDomain: signedDomain,
		},
	}
}

func GetAuthorizationPolicyModelConfig(namespace, name string, apSpec *securityV1beta1.AuthorizationPolicy) *model.Config {
	response := common.NewConfig(collections.IstioSecurityV1Beta1Authorizationpolicies, namespace, name, apSpec)
	return &response
}

func GetBasicRbacV2Case(modifications *RbacV2Modifications) *ExpectedV2Rbac {
	serviceName := "my-service-name"
	namespace := "athenz-domain"

	defaultModifyServices := [][]func(service *v1.Service){
		[]func(service *v1.Service){
			func(service *v1.Service) {},
		},
	}

	defaultModifyAuthorizationPolicies := [][]func(policy *securityV1beta1.AuthorizationPolicy){
		[]func(policy *securityV1beta1.AuthorizationPolicy){
			func(policy *securityV1beta1.AuthorizationPolicy) {},
		},
	}

	if modifications == nil {
		modifications = &RbacV2Modifications{
			ModifyAthenzDomain:          []func(signedDomain *zms.SignedDomain){},
			ModifyServices:              defaultModifyServices,
			ModifyAuthorizationPolicies: defaultModifyAuthorizationPolicies,
		}
	}

	// Create Athenz Domain
	ad := GetDefaultAthenzDomainForAuthorizationPolicies(modifications.ModifyAthenzDomain)

	// Create Kubernetes Services
	services := []*v1.Service{}
	if modifications.ModifyServices == nil {
		modifications.ModifyServices = defaultModifyServices
	}

	for _, serviceModifications := range modifications.ModifyServices {
		services = append(services, GetDefaultService(serviceName, serviceModifications))
	}

	// Create Authorization Policies
	policies := []*model.Config{}
	if modifications.ModifyAuthorizationPolicies == nil {
		modifications.ModifyAuthorizationPolicies = defaultModifyAuthorizationPolicies
	}
	for _, policyModifications := range modifications.ModifyAuthorizationPolicies {
		policies = append(policies, GetAuthorizationPolicyModelConfig(namespace, serviceName, getExpectedAuthorizationPolicy(serviceName, policyModifications)))
	}

	return &ExpectedV2Rbac{
		AD:                    ad,
		Services:              services,
		AuthorizationPolicies: policies,
	}
}
