package integration

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"
)

// TODO, figure out how to make these run in different folders
func TestMain(m *testing.M) {
	f, err := framework.Setup()
	if err != nil {
		log.Println("Error setting up test framework:", err)
		os.Exit(1)
	}
	time.Sleep(time.Second * 15)
	fixtures.CreateAthenzDomain(f.AthenzDomainClientset)
	exitCode := m.Run()
	f.Teardown()
	os.Exit(exitCode)
}
