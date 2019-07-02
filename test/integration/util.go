package integration

import (
	adClientset "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/clientset/versioned"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/controller"
	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/test/integration/framework"
	"log"
	"net/http/httptest"
	"testing"
	"time"
)

// dcSetup sets up necessities for Deployment integration test, including master, apiserver, informers, and clientset
func dcSetup(t *testing.T) (*httptest.Server, framework.CloseFunc, clientset.Interface, *controller.Controller) {
	masterConfig := framework.NewIntegrationTestMasterConfig()
	_, s, closeFn := framework.RunAMaster(masterConfig)

	config := restclient.Config{Host: s.URL}
	clientSet, err := clientset.NewForConfig(&config)
	if err != nil {
		t.Fatalf("error in create clientset: %v", err)
	}

	return s, closeFn, clientSet, controllerSetup()
}

func controllerSetup() *controller.Controller {
	configDescriptor := model.ConfigDescriptor{
		model.ClusterRbacConfig,
		model.ServiceRole,
		model.ServiceRoleBinding,
	}


	istioClient, err := crd.NewClient("/tmp/config", "", configDescriptor, "svc.cluster.local")
	if err != nil {
		log.Panicln("Error creating istio crd client:", err.Error())
	}

	config, err := clientcmd.BuildConfigFromFlags("", "/tmp/config")
	if err != nil {
		log.Panicln("Error creating kubernetes in cluster config: " + err.Error())
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panicln("Error creating k8s client:", err.Error())
	}

	adClient, err := adClientset.NewForConfig(config)
	if err != nil {
		log.Panicln("Error creating athenz domain client:", err.Error())
	}

	adResyncInterval, err := time.ParseDuration("1h")
	if err != nil {
		log.Panicln("Error parsing ad-resync-interval duration:", err.Error())
	}

	crcResyncInterval, err := time.ParseDuration("1h")
	if err != nil {
		log.Panicln("Error parsing crc-resync-interval duration:", err.Error())
	}

	return controller.NewController("svc.cluster.local", istioClient, k8sClient, adClient, adResyncInterval, crcResyncInterval)
}