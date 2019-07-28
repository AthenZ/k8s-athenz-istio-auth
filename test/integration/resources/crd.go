package resources

import (
	v1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AthenzDomain returns a bare minimum crd definition of k8s-athenz-syncer's AthenzDomains
// ref - https://github.com/yahoo/k8s-athenz-syncer/blob/32fa16643313505efbbcf0177f70624841dd7043/k8s/athenzdomain.yaml#L1-L14
func AthenzDomain() *v1beta1.CustomResourceDefinition {
	return &v1beta1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
		  Kind: "CustomResourceDefinition",
		  APIVersion: CrdAPIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: AthenzDomainMetaName,
		},
		Spec: v1beta1.CustomResourceDefinitionSpec{
			Group: AthenzDomainGroup,
			Version: AthenzDomainVersion,
			Names: v1beta1.CustomResourceDefinitionNames{
				Plural: AthenzDomainPlural,
				Singular: AthenzDomainSingular,
				Kind: AthenzDomainKind,
				ShortNames: AthenzDomainShortNames,
				ListKind: AthenzDomainListKind,
			},
		},
	}
}

// ServiceRole returns a bare minimum crd definition of istio's servicerole
// ref - https://github.com/istio/istio/blob/e5f21f1c8e9a3ab366b66c7d5830c72f3b4343e8/install/kubernetes/helm/istio-init/files/crd-10.yaml#L457-L483
func ServiceRole() *v1beta1.CustomResourceDefinition {
	return &v1beta1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
		   Kind: "CustomResourceDefinition",
		   APIVersion: CrdAPIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "serviceroles.rbac.istio.io",
		},
		Spec: v1beta1.CustomResourceDefinitionSpec{
			Group: "rbac.istio.io",
			Names: v1beta1.CustomResourceDefinitionNames{
				Plural: "serviceroles",
				Singular: "servicerole",
				Kind: "ServiceRole",
				Categories:[]string{
					"istio-io",
					"rbac-istio-io",
				},
			},
			Scope: v1beta1.NamespaceScoped,
			Version: "v1alpha1",
		},
	}
}

// ServiceRoleBinding returns a bare minimum crd definition of istio's servicerolebinding
// ref - https://github.com/istio/istio/blob/e5f21f1c8e9a3ab366b66c7d5830c72f3b4343e8/install/kubernetes/helm/istio-init/files/crd-10.yaml#L485-L523
func ServiceRoleBinding() *v1beta1.CustomResourceDefinition {
	return &v1beta1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind: "CustomResourceDefinition",
			APIVersion: CrdAPIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "servicerolebindings.rbac.istio.io",
		},
		Spec: v1beta1.CustomResourceDefinitionSpec{
			Group: "rbac.istio.io",
			Names: v1beta1.CustomResourceDefinitionNames{
				Plural: "servicerolebindings",
				Singular: "servicerolebinding",
				Kind: "ServiceRoleBinding",
				Categories:[]string{
					"istio-io",
					"rbac-istio-io",
				},
			},
			Scope: v1beta1.NamespaceScoped,
			Version: "v1alpha1",
		},
	}
}