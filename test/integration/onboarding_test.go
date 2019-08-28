package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"
	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"time"
)

// TODO, update everywhere to use assert
// TODO, add cluster dns suffix everywhere

func rolloutAndValidateCRC(t *testing.T, services []*v1.Service, a action) {
	if a == update {
		updateServices(t, services)
	} else if a == create {
		createServices(t, services)
	}

	onboardedServices := 0
	for _, s := range services {
		enabled := s.Annotations["authz.istio.io/enabled"]
		if enabled == "true" {
			onboardedServices++
		}
	}

	err := wait.PollImmediate(time.Second, time.Second*5, func() (bool, error) {
		crc := framework.Global.IstioClientset.Get(model.ClusterRbacConfig.Type, "default", "")
		if crc == nil {
			return false, nil
		}
		clusterRbacConfig, ok := crc.Spec.(*v1alpha1.RbacConfig)
		if !ok {
			return false, nil
		}

		if len(clusterRbacConfig.Inclusion.Services) == onboardedServices {
			return true, nil
		}

		// TODO, add comparison
		return false, nil
	})

	if err != nil {
		t.Error("time out waiting for rollout for crc with error", err)
	}

	crc := framework.Global.IstioClientset.Get(model.ClusterRbacConfig.Type, "default", "")
	clusterRbacConfig, ok := crc.Spec.(*v1alpha1.RbacConfig)
	assert.True(t, ok, "cast should have worked")
	assert.Equal(t, clusterRbacConfig.Mode, v1alpha1.RbacConfig_ON_WITH_INCLUSION, "should be inclusion")
	assert.Nil(t, clusterRbacConfig.Exclusion, "should be nil")
	// TODO, add check which works out of order
	expected := []string{}
	for _, s := range services {
		expected = append(expected, s.Name+"."+s.Namespace+".")
	}
	assert.Equal(t, expected, clusterRbacConfig.Inclusion.Services, "should be equal")
}

func createServices(t *testing.T, services []*v1.Service) {
	for _, s := range services {
		_, err := framework.Global.K8sClientset.CoreV1().Services(s.Namespace).Create(s)
		assert.Nil(t, err, "should be nil")
	}
}

func updateServices(t *testing.T, services []*v1.Service) {
	for _, s := range services {
		currentS, err := framework.Global.K8sClientset.CoreV1().Services(s.Namespace).Get(s.Name, metav1.GetOptions{})
		assert.Nil(t, err, "")
		s.ResourceVersion = currentS.ResourceVersion
		_, err = framework.Global.K8sClientset.CoreV1().Services(s.Namespace).Update(s)
	}
}

func cleanupServices(t *testing.T, services []*v1.Service) {
	for _, s := range services {
		err := framework.Global.K8sClientset.CoreV1().Services(s.Namespace).Delete(s.Name, &metav1.DeleteOptions{})
		assert.Nil(t, err, "should be nil")
	}
}

// 1.0 Create CRC with valid service annotation
func TestCreateCRC(t *testing.T) {
	services := fixtures.GetOverrideService(nil)
	rolloutAndValidateCRC(t, services, create)
	cleanupServices(t, services)
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

	services := fixtures.GetOverrideService(o)
	rolloutAndValidateCRC(t, services, create)
	cleanupServices(t, services)
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

	services := fixtures.GetOverrideService(o)
	rolloutAndValidateCRC(t, services, create)
	cleanupServices(t, services)
}

// TODO, look into delete of crc
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
	services := fixtures.GetOverrideService(o)
	rolloutAndValidateCRC(t, services, create)

	// TODO, make this cleaner
	services[1].Annotations = map[string]string{
		"authz.istio.io/enabled": "true",
	}

	rolloutAndValidateCRC(t, services, update)
	cleanupServices(t, services)
}

// 3.0 Delete crc if there are no more onboarded services
func TestDeleteCRC(t *testing.T) {
	services := fixtures.GetOverrideService(nil)
	rolloutAndValidateCRC(t, services, create)

	err := framework.Global.K8sClientset.CoreV1().Services(services[0].Namespace).Delete(services[0].Name, &metav1.DeleteOptions{})
	assert.Nil(t, err, "")

	rolloutAndValidateCRC(t, []*v1.Service{}, noop)
}

// 3.1 Delete CRC if onboarded services still exist, expect the controller to sync it back
func TestDeleteCRCIfServiceExists(t *testing.T) {
	services := fixtures.GetOverrideService(nil)
	rolloutAndValidateCRC(t, services, create)

	err := framework.Global.IstioClientset.Delete(model.ClusterRbacConfig.Type, "default", "")
	assert.Nil(t, err, "should be nil")

	rolloutAndValidateCRC(t, services, noop)
	cleanupServices(t, services)
}
