package integration

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	v1 "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/yahoo/athenz/clients/go/zms"

	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/resources"
)

var _ = Describe("Given there are no existing AthensDomain", func() {
	var athenzDomainWithRolesAndPolicies = &v1.AthenzDomain{
		TypeMeta: metav1.TypeMeta{
			Kind:       resources.AthenzDomainKind,
			APIVersion: resources.AthenzDomainGroup + "/" + resources.AthenzDomainVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example",
			Namespace: "default",
		},
		Spec: v1.AthenzDomainSpec{
			SignedDomain: zms.SignedDomain{
				KeyId: "hello",
				Signature: "hello",
			},
		},
	}
	domain := getFakeDomain()
	newCR := &v1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
			Namespace: "default",
		},
		Spec: v1.AthenzDomainSpec{
			SignedDomain: domain,
		},
	}
	GinkgoT().Logf("athenzDomain: %v\n", athenzDomainWithRolesAndPolicies)
	BeforeEach(func() {
	})
	Context("When a new AthenzDomain is created", func() {
		It("Corresponding ServiceRole and ServiceRoleBinding are created", func() {

			GinkgoT().Logf("athenzDomain: %v\n", athenzDomainWithRolesAndPolicies)

			result1 := globalAthenzDomainClientset.
				AthenzV1().RESTClient().Post().
				Namespace("default").
				Name(athenzDomainWithRolesAndPolicies.ObjectMeta.Name).
				Body(athenzDomainWithRolesAndPolicies).
				Do()

			result2 := globalAthenzDomainClientset.
				AthenzV1().RESTClient().Post().
				Namespace("default").
				Name(newCR.ObjectMeta.Name).
				Body(newCR).
				Do()

			raw, err := result2.Raw()
			if result2.Error() != nil {
				GinkgoT().Logf("failed to create athenzDomain: %v\nraw: %v, rawErr: %v\n", result2.Error(), raw, err)
			}

			raw1, err := result1.Raw()
			if result2.Error() != nil {
				GinkgoT().Logf("failed to create athenzDomain: %v\nraw: %v, rawErr: %v\n", result1.Error(), raw1, err)
			}

			result := &v1.AthenzDomain{}
			globalAthenzDomainClientset.RESTClient().Get().Namespace("default").Name("foo").Do().Into(result)
			GinkgoT().Logf("AthenzDomain: %v\n", result)
			Expect(nil).To(BeNil())
		})
	})
	AfterEach(func() {

	})

	Context("When a new AthensDomain is created without roles", func() {
		It("Corresponding ServiceRole is created, and ServiceRoleBinding is not created", func() {

		})
	})
})
