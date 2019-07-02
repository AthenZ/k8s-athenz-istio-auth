package integration

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"
)

func TestNewDeployment(t *testing.T) {

	stopCh := make(chan struct{})
	s, _, cs, c := dcSetup(t)
	go c.Run(stopCh)

	time.Sleep(time.Minute)
	fmt.Println(cs.ApiextensionsV1beta1().CustomResourceDefinitions().Get("default", v1.GetOptions{}))
	spew.Dump(s)

}