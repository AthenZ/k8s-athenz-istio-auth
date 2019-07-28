package integration

import (
	"testing"
	"fmt"

	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/resources"

	"istio.io/istio/pilot/pkg/config/kube/crd"
	adClientset "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/controller"


	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	globalIstioClient *crd.Client
	globalAthenzDomainClientset *adClientset.Clientset
	globalAthenzController *controller.Controller

	kubeName      = "integration_tests"
	globalCluster = NewCluster(kubeName)
	dnsSuffix = "svc.cluster.local"
	adResyncIntervalRaw = "1h"
	crcResyncIntervalRaw = "1h"
)

var _ = BeforeSuite(func() {
	err := globalCluster.Start()
	if err != nil {
		GinkgoT().Errorf(err.Error())
	}
	err = createCRD(globalCluster.restApiExtensionClient, resources.AthenzDomain(), resources.ServiceRole(), resources.ServiceRoleBinding())
	if err != nil {
		GinkgoT().Errorf(err.Error())
	}

	globalIstioClient, err = NewIstioClient(globalCluster.kubeConfigPath, dnsSuffix)
	if err != nil {
		GinkgoT().Errorf(err.Error())
	}

	globalAthenzDomainClientset, err = NewAthenzDomainClient(globalCluster.restConfig)
	if err != nil {
		GinkgoT().Errorf(err.Error())
	}

	globalAthenzController, err = NewAthenzController(dnsSuffix, globalIstioClient, globalCluster.restClient, globalAthenzDomainClientset, adResyncIntervalRaw, crcResyncIntervalRaw)
	if err != nil {
		GinkgoT().Errorf(err.Error())
	}
	 fmt.Printf("istioClient: %v, athenzDomainClient: %v, globalAthenzController: %v\n", globalIstioClient, globalAthenzDomainClientset, globalAthenzController)

})

var _ = AfterSuite(func() {
	err := globalCluster.Stop()
	if err != nil {
		GinkgoT().Errorf(err.Error())
	}
})

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}