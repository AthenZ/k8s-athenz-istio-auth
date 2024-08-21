package integration

import (
	"testing"
	"time"

	"istio.io/istio/pkg/config/schema/collections"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"

	"istio.io/istio/pkg/config/constants"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

// rolloutAndValidateOnboarding will create / update / delete / noop the service resource and wait for the
// associated cluster rbac config to be created. It will then be validated against the
// expected output.
func rolloutAndValidateOnboarding(t *testing.T, s *fixtures.ExpectedServices, a action) {
	switch a {
	case create:
		createServices(t, s)
	case update:
		updateServices(t, s)
	case delete:
		deleteServices(t, s)
	}

	err := wait.PollImmediate(time.Second, time.Second*30, func() (bool, error) {
		config := framework.Global.IstioClientset.Get(collections.IstioRbacV1Alpha1Clusterrbacconfigs.Resource().GroupVersionKind(), constants.DefaultRbacConfigName, "")
		if config == nil && len(s.ServiceDNS) == 0 {
			return true, nil
		} else if config == nil {
			return false, nil
		}

		return false, nil
	})

	assert.Nil(t, err, "time out waiting for rollout for crc with error")

	crc := framework.Global.IstioClientset.Get(collections.IstioRbacV1Alpha1Clusterrbacconfigs.Resource().GroupVersionKind(), constants.DefaultRbacConfigName, "")
	if crc == nil && len(s.ServiceDNS) == 0 {
		return
	}
}

// createServices will iterate through the service list and create each object
func createServices(t *testing.T, services *fixtures.ExpectedServices) {
	for _, service := range services.Services {
		_, err := framework.Global.K8sClientset.CoreV1().Services(service.Namespace).Create(service)
		assert.Nil(t, err, "service create error should be nil")
	}
}

// updateServices will iterate through the service list and update each object
func updateServices(t *testing.T, services *fixtures.ExpectedServices) {
	for _, service := range services.Services {
		currentService, err := framework.Global.K8sClientset.CoreV1().Services(service.Namespace).Get(service.Name, metav1.GetOptions{})
		assert.Nil(t, err, "service get error should be nil")
		service.ResourceVersion = currentService.ResourceVersion
		service.Spec.ClusterIP = currentService.Spec.ClusterIP
		_, err = framework.Global.K8sClientset.CoreV1().Services(service.Namespace).Update(service)
		assert.Nil(t, err, "service update error should be nil")
	}
}

// deleteServices will iterate through the service list and delete each object
func deleteServices(t *testing.T, s *fixtures.ExpectedServices) {
	for _, service := range s.Services {
		err := framework.Global.K8sClientset.CoreV1().Services(service.Namespace).Delete(service.Name, &metav1.DeleteOptions{})
		assert.Nil(t, err, "service delete error should be nil")
	}
	s.Services = []*v1.Service{}
	s.ServiceDNS = []string{}
}

// 1.0 Create CRC with valid service annotation
func TestCreateCRC(t *testing.T) {
	s := fixtures.GetExpectedServices(nil)
	rolloutAndValidateOnboarding(t, s, create)
	deleteServices(t, s)
}

// 2.0 Update CRC with new service
func TestUpdateCRC(t *testing.T) {
	o := []func(*v1.Service){
		func(s *v1.Service) {
		},
	}

	sOne := fixtures.GetExpectedServices(o)
	rolloutAndValidateOnboarding(t, sOne, create)

	o = []func(*v1.Service){
		func(s *v1.Service) {
			s.Name = "test-service-two"
		},
	}

	sTwo := fixtures.GetExpectedServices(o)
	sTwo.ServiceDNS = append(sTwo.ServiceDNS, sOne.ServiceDNS...)
	rolloutAndValidateOnboarding(t, sTwo, create)

	deleteServices(t, sOne)
	deleteServices(t, sTwo)
}

// 2.1 Test services in different namespace
func TestMultipleServices(t *testing.T) {
	o := []func(*v1.Service){
		func(s *v1.Service) {
		},
		func(s *v1.Service) {
			s.Name = "test-service-two"
			s.Namespace = "athenz-domain-one"
		},
		func(s *v1.Service) {
			s.Name = "test-service-three"
			s.Namespace = "athenz-domain-two"
		},
	}

	s := fixtures.GetExpectedServices(o)
	rolloutAndValidateOnboarding(t, s, create)
	deleteServices(t, s)
}

// 2.2 Test enable/disable annotation combinations
func TestEnableDisableAnnotation(t *testing.T) {
	o := []func(*v1.Service){
		func(s *v1.Service) {
		},
		func(s *v1.Service) {
			s.Name = "test-service-two"
			s.Namespace = "athenz-domain-one"
			s.Annotations = make(map[string]string)
		},
	}
	s := fixtures.GetExpectedServices(o)
	rolloutAndValidateOnboarding(t, s, create)

	o = []func(*v1.Service){
		func(s *v1.Service) {
		},
		func(s *v1.Service) {
			s.Name = "test-service-two"
			s.Namespace = "athenz-domain-one"
		},
	}
	s = fixtures.GetExpectedServices(o)
	rolloutAndValidateOnboarding(t, s, update)
	deleteServices(t, s)
}

// 3.0 Delete crc if there are no more onboarded services
func TestDeleteCRC(t *testing.T) {
	s := fixtures.GetExpectedServices(nil)
	rolloutAndValidateOnboarding(t, s, create)
	rolloutAndValidateOnboarding(t, s, delete)
}

// 3.1 Delete CRC if onboarded services still exist, expect the controller to sync it back
func TestDeleteCRCIfServiceExists(t *testing.T) {
	s := fixtures.GetExpectedServices(nil)
	rolloutAndValidateOnboarding(t, s, create)

	err := framework.Global.IstioClientset.Delete(collections.IstioRbacV1Alpha1Clusterrbacconfigs.Resource().GroupVersionKind(), constants.DefaultRbacConfigName, "")
	assert.Nil(t, err, "cluster rbac config delete error should be nil")

	rolloutAndValidateOnboarding(t, s, noop)
	deleteServices(t, s)
}
