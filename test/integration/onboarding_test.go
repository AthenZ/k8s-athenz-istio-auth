package integration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

// TODO, add cluster dns suffix everywhere and test main controller
// TODO, go through each test and make sure it works, validate against document
// rolloutAndValidateCRC will create / update / noop the service resource and wait for the
// associated cluster rbac config to be created. It will then be validated against the
// expected output.
func rolloutAndValidateCRC(t *testing.T, services *fixtures.ExpectedServiceResources, a action) {
	if a == update {
		updateServices(t, services)
	} else if a == create {
		createServices(t, services)
	}

	err := wait.PollImmediate(time.Second, time.Second*10, func() (bool, error) {
		if len(services.ServiceDNS) == 0 {
			return true, nil
		}

		crc := framework.Global.IstioClientset.Get(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, "")
		if crc == nil {
			return false, nil
		}

		clusterRbacConfig, ok := crc.Spec.(*v1alpha1.RbacConfig)
		if !ok {
			return false, nil
		}

		if len(clusterRbacConfig.Inclusion.Services) == len(services.ServiceDNS) {
			return true, nil
		}

		return false, nil
	})

	if err != nil {
		t.Error("time out waiting for rollout for crc with error", err)
	}

	crc := framework.Global.IstioClientset.Get(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, "")
	if crc == nil && len(services.ServiceDNS) == 0 {
		return
	}

	clusterRbacConfig, ok := crc.Spec.(*v1alpha1.RbacConfig)
	assert.True(t, ok, "cluster rbac config cast should pass")
	assert.Equal(t, clusterRbacConfig.Mode, v1alpha1.RbacConfig_ON_WITH_INCLUSION, "cluster rbac config inclusion field should be set")
	assert.Nil(t, clusterRbacConfig.Exclusion, "cluster rbac config exclusion field should be nil")
	assert.ElementsMatch(t, services.ServiceDNS, clusterRbacConfig.Inclusion.Services, "cluster rbac config service list should be equal to expected")
}

// createServices will iterate through the service list and create each object
func createServices(t *testing.T, services *fixtures.ExpectedServiceResources) {
	for _, s := range services.Services {
		_, err := framework.Global.K8sClientset.CoreV1().Services(s.Namespace).Create(s)
		assert.Nil(t, err, "service create error should be nil")
	}
}

// updateServices will iterate through the service list and update each object
func updateServices(t *testing.T, services *fixtures.ExpectedServiceResources) {
	for _, s := range services.Services {
		currentS, err := framework.Global.K8sClientset.CoreV1().Services(s.Namespace).Get(s.Name, metav1.GetOptions{})
		assert.Nil(t, err, "service get error should be nil")
		s.ResourceVersion = currentS.ResourceVersion
		s.Spec.ClusterIP = currentS.Spec.ClusterIP
		_, err = framework.Global.K8sClientset.CoreV1().Services(s.Namespace).Update(s)
		assert.Nil(t, err, "service update error should be nil")
	}
}

// cleanupServices will iterate through the service list and delete each object
func cleanupServices(t *testing.T, services *fixtures.ExpectedServiceResources) {
	for _, s := range services.Services {
		err := framework.Global.K8sClientset.CoreV1().Services(s.Namespace).Delete(s.Name, &metav1.DeleteOptions{})
		assert.Nil(t, err, "service delete error should be nil")
	}
}

// 1.0 Create CRC with valid service annotation
func TestCreateCRC(t *testing.T) {
	s := fixtures.GetOverrideService(nil)
	rolloutAndValidateCRC(t, s, create)
	cleanupServices(t, s)
}

// 2.0 Update CRC with new service
func TestUpdateCRC(t *testing.T) {
	o := []func(*v1.Service){
		func(s *v1.Service) {
		},
		func(s *v1.Service) {
			s.Name = "test-service-two"
		},
	}

	s := fixtures.GetOverrideService(o)
	rolloutAndValidateCRC(t, s, create)
	cleanupServices(t, s)
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

	s := fixtures.GetOverrideService(o)
	rolloutAndValidateCRC(t, s, create)
	cleanupServices(t, s)
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
	s := fixtures.GetOverrideService(o)
	rolloutAndValidateCRC(t, s, create)

	o = []func(*v1.Service){
		func(s *v1.Service) {
		},
		func(s *v1.Service) {
			s.Name = "test-service-two"
			s.Namespace = "athenz-domain-one"
		},
	}
	s = fixtures.GetOverrideService(o)
	rolloutAndValidateCRC(t, s, update)
	cleanupServices(t, s)
}

// 3.0 Delete crc if there are no more onboarded services
func TestDeleteCRC(t *testing.T) {
	s := fixtures.GetOverrideService(nil)
	rolloutAndValidateCRC(t, s, create)

	err := framework.Global.K8sClientset.CoreV1().Services(s.Services[0].Namespace).Delete(s.Services[0].Name, &metav1.DeleteOptions{})
	assert.Nil(t, err, "service delete error should be nil")

	rolloutAndValidateCRC(t, &fixtures.ExpectedServiceResources{}, noop)
}

// 3.1 Delete CRC if onboarded services still exist, expect the controller to sync it back
func TestDeleteCRCIfServiceExists(t *testing.T) {
	s := fixtures.GetOverrideService(nil)
	rolloutAndValidateCRC(t, s, create)

	err := framework.Global.IstioClientset.Delete(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, "")
	assert.Nil(t, err, "service delete error should be nil")

	rolloutAndValidateCRC(t, s, noop)
	cleanupServices(t, s)
}
