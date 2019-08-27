package integration

import (
	"log"
	"testing"

	"github.com/davecgh/go-spew/spew"
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

func rolloutAndValidateCRC(t *testing.T, expected []string) {
	err := wait.PollImmediate(time.Second, time.Second*5, func() (bool, error) {
		crc := framework.Global.IstioClientset.Get(model.ClusterRbacConfig.Type, "default", "default")
		if crc == nil {
			return false, nil
		}
		clusterRbacConfig, ok := crc.Spec.(*v1alpha1.RbacConfig)
		if !ok {
			return false, nil
		}

		if len(clusterRbacConfig.Inclusion.Services) == len(expected) {
			spew.Dump(crc)
			return true, nil
		}

		// TODO, add comparison
		return false, nil
	})

	if err != nil {
		t.Error("time out waiting for rollout for crc with error", err)
	}

	crc := framework.Global.IstioClientset.Get(model.ClusterRbacConfig.Type, "default", "default")
	clusterRbacConfig, ok := crc.Spec.(*v1alpha1.RbacConfig)
	assert.True(t, ok, "cast should have worked")
	assert.Equal(t, clusterRbacConfig.Mode, v1alpha1.RbacConfig_ON_WITH_INCLUSION, "should be inclusion")
	assert.Nil(t, clusterRbacConfig.Exclusion, "should be nil")
	assert.Equal(t, expected, clusterRbacConfig.Inclusion.Services, "should be equal")
}

// TODO, pass service
func cleanupService(t *testing.T, s *v1.Service) {
	err := framework.Global.K8sClientset.CoreV1().Services(s.Namespace).Delete(s.Name, &metav1.DeleteOptions{})
	assert.Nil(t, err, "should be nil")
}

// 1.0 Create CRC with valid service annotation
func TestCreateCRC(t *testing.T) {
	s := fixtures.GetDefaultService()
	_, err := framework.Global.K8sClientset.CoreV1().Services(s.Namespace).Create(s)
	assert.Nil(t, err, "")
	sList, err := framework.Global.K8sClientset.CoreV1().Services(s.Namespace).List(metav1.ListOptions{})
	assert.Nil(t, err, "")
	spew.Dump(sList)

	// TODO, add dns suffix
	rolloutAndValidateCRC(t, []string{s.Name + "." + s.Namespace + "."})
	cleanupService(t, s)
}

// 2.0 Update CRC with new service
func TestUpdateCRC(t *testing.T) {
	sOne := fixtures.GetDefaultService()
	// TODO, combine the creates
	_, err := framework.Global.K8sClientset.CoreV1().Services(sOne.Namespace).Create(sOne)
	assert.Nil(t, err, "")

	sTwo := fixtures.GetDefaultService()
	sTwo.Name = "test-service-two"
	_, err = framework.Global.K8sClientset.CoreV1().Services(sOne.Namespace).Create(sTwo)
	assert.Nil(t, err, "")

	rolloutAndValidateCRC(t, []string{sOne.Name + "." + sOne.Namespace + ".", sTwo.Name + "." + sTwo.Namespace + "."})
	cleanupService(t, sOne)
	cleanupService(t, sTwo)
}

// 2.1 Test services in different namespace
func TestMultipleServices(t *testing.T) {
	sOne := fixtures.GetDefaultService()
	_, err := framework.Global.K8sClientset.CoreV1().Services(sOne.Namespace).Create(sOne)
	assert.Nil(t, err, "")

	sTwo := fixtures.GetDefaultService()
	sTwo.Name = "test-service-two"
	sTwo.Namespace = "athenz-domain-one"
	_, err = framework.Global.K8sClientset.CoreV1().Services(sTwo.Namespace).Create(sTwo)
	assert.Nil(t, err, "")

	sThree := fixtures.GetDefaultService()
	sThree.Name = "test-service-three"
	sThree.Namespace = "athenz-domain-two"
	_, err = framework.Global.K8sClientset.CoreV1().Services(sThree.Namespace).Create(sThree)
	assert.Nil(t, err, "")

	rolloutAndValidateCRC(t, []string{sOne.Name + "." + sOne.Namespace + ".", sTwo.Name + "." + sTwo.Namespace + ".", sThree.Name + "." + sThree.Namespace + "."})
	cleanupService(t, sOne)
	cleanupService(t, sTwo)
	cleanupService(t, sThree)
}

// TODO, look into delete of crc
// 2.2 Test enable/disable annotation combinations
func TestEnableDisableAnnotation(t *testing.T) {
	sOne := fixtures.GetDefaultService()
	_, err := framework.Global.K8sClientset.CoreV1().Services(sOne.Namespace).Create(sOne)
	assert.Nil(t, err, "")

	sTwo := fixtures.GetDefaultService()
	sTwo.Name = "test-service-two"
	sTwo.Namespace = "athenz-domain-one"
	sTwo.Annotations = make(map[string]string)

	_, err = framework.Global.K8sClientset.CoreV1().Services(sTwo.Namespace).Create(sTwo)
	assert.Nil(t, err, "")
	log.Println("rolling out and validating")
	rolloutAndValidateCRC(t, []string{sOne.Name + "." + sOne.Namespace + "."})

	sTwo, err = framework.Global.K8sClientset.CoreV1().Services(sTwo.Namespace).Get(sTwo.Name, metav1.GetOptions{})
	assert.Nil(t, err, "")
	sTwo.Annotations = map[string]string{
		"authz.istio.io/enabled": "true",
	}

	log.Println("updating service")
	_, err = framework.Global.K8sClientset.CoreV1().Services(sTwo.Namespace).Update(sTwo)
	assert.Nil(t, err, "")
	rolloutAndValidateCRC(t, []string{sOne.Name + "." + sOne.Namespace + ".", sTwo.Name + "." + sTwo.Namespace + "."})
	cleanupService(t, sOne)
	cleanupService(t, sTwo)
}

// 3.0 Delete crc if there are no more onboarded services
func TestDeleteCRC(t *testing.T) {
	s := fixtures.GetDefaultService()
	_, err := framework.Global.K8sClientset.CoreV1().Services(s.Namespace).Create(s)
	assert.Nil(t, err, "")
	rolloutAndValidateCRC(t, []string{s.Name + "." + s.Namespace + "."})

	err = framework.Global.K8sClientset.CoreV1().Services(s.Namespace).Delete(s.Name, &metav1.DeleteOptions{})
	assert.Nil(t, err, "")

	time.Sleep(time.Second * 5)
	crc := framework.Global.IstioClientset.Get(model.ClusterRbacConfig.Type, "default", "default")
	assert.Nil(t, crc, "nil")

}

// 3.1 Delete CRC if onboarded services still exist, expect the controller to sync it back
