package integration

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"
)

func TestMain(m *testing.M) {
	err := framework.Setup()
	if err != nil {
		log.Println("Error setting up test framework:", err)
		os.Exit(1)
	}

	// TODO, remove sleep after merging with crd rollout code
	time.Sleep(time.Second * 5)
	exitCode := m.Run()
	framework.Teardown()
	os.Exit(exitCode)
}
