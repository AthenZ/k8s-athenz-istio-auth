// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.

// +build integration

package fixtures

import (
	"log"
	"time"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/yahoo/athenz/clients/go/zms"
	athenzdomain "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	athenzdomainclientset "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CreateAthenzDomainCrd creates the athenz domain custom resource definition
func CreateAthenzDomainCrd(clientset *apiextensionsclient.Clientset) error {
	crd := &v1beta1.CustomResourceDefinition{
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

	created, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Create(crd)
	if err != nil {
		return err
	}
	log.Println("created:", created)

	got, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Get("athenzdomains.athenz.io", metav1.GetOptions{})
	if err != nil {
		return err
	}
	log.Println("got:", got)
	time.Sleep(time.Second)
	return nil
}

// CreateAthenzDomain creates an athenz domain custom resource
func CreateAthenzDomain(clientset *athenzdomainclientset.Clientset) {
	domain := "home.foo"
	fakeDomain := getFakeDomain()
	newCR := &athenzdomain.AthenzDomain{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AthenzDomain",
			APIVersion: "athenz.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: domain,
		},
		Spec: athenzdomain.AthenzDomainSpec{
			SignedDomain: fakeDomain,
		},
		Status: athenzdomain.AthenzDomainStatus{
			Message: "",
		},
	}

	list, err := clientset.AthenzV1().AthenzDomains().List(metav1.ListOptions{})
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("list:", list)

	created, err := clientset.AthenzV1().AthenzDomains().Create(newCR)
	if err != nil {
		log.Println("error creating athenz domain:", err)
		return
	}
	log.Println("created cr:", created)

	got, err := clientset.AthenzV1().AthenzDomains().Get(domain, metav1.GetOptions{})
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("got cr:", got)
}

// getFakeDomain provides a populated fake domain object
func getFakeDomain() zms.SignedDomain {
	allow := zms.ALLOW
	timestamp, err := rdl.TimestampParse("2019-06-21T19:28:09.305Z")
	if err != nil {
		panic(err)
	}

	domainName := "home.foo"
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
									Role:     domainName + ":role.admin",
									Resource: domainName + ".test:*",
									Action:   "*",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     zms.ResourceName(domainName + ":policy.admin"),
						},
					},
				},
				KeyId:     "col-env-1.1",
				Signature: "signature-policy",
			},
			Roles: []*zms.Role{
				{
					Members:  []zms.MemberName{zms.MemberName(username)},
					Modified: &timestamp,
					Name:     zms.ResourceName(domainName + ":role.admin"),
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: zms.MemberName(username),
						},
					},
				},
				{
					Trust:    "parent.domain",
					Modified: &timestamp,
					Name:     zms.ResourceName(domainName + ":role.trust"),
				},
			},
			Services: []*zms.ServiceIdentity{},
			Entities: []*zms.Entity{},
		},
		KeyId:     "colo-env-1.1",
		Signature: "signature",
	}
}
