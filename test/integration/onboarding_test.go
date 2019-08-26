package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"github.com/davecgh/go-spew/spew"
)

// 1.0 Create CRC with valid service annotation
func TestCreateCRC(t *testing.T) {
	s := fixtures.GetDefaultService()
	_, err := framework.Global.K8sClientset.CoreV1().Services(s.Namespace).Create(s)
	assert.Nil(t, err, "")
	sList, err := framework.Global.K8sClientset.CoreV1().Services(s.Namespace).List(v1.ListOptions{})
	assert.Nil(t, err, "")
	spew.Dump(sList)
}
