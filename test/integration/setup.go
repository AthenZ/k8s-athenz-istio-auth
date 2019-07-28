package integration

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	v1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	// istio
	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/ardielle/ardielle-go/rdl"


	// athenz
	adClientset "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned"
	// athenzclient "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned/typed/athenz/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/controller"
)

const (
	kindPath = "/Users/aaeron/workspace/gocode/bin/kind"

)

var (
	kindImageVersions = map[string]string{
		"1.11": "kindest/node:v1.11.10@sha256:176845d919899daef63d0dbd1cf62f79902c38b8d2a86e5fa041e491ab795d33",
		"1.12": "kindest/node:v1.12.9@sha256:bcb79eb3cd6550c1ba9584ce57c832dcd6e442913678d2785307a7ad9addc029",
		"1.13": "kindest/node:v1.13.7@sha256:f3f1cfc2318d1eb88d91253a9c5fa45f6e9121b6b1e65aea6c7ef59f1549aaaf",
		"1.14": "kindest/node:v1.14.3@sha256:583166c121482848cd6509fbac525dd62d503c52a84ff45c338ee7e8b5cfe114",
		"1.15": "kindest/node:v1.15.0@sha256:b4d092fd2b507843dd096fe6c85d06a27a0cbd740a0b32a880fe61aba24bb478",
	}
)

type Cluster struct {
	name                   string
	restConfig             *rest.Config
	kubeConfigPath string
	restClient             kubernetes.Interface
	restApiExtensionClient *apiextensionsclient.Clientset
}

func NewCluster(name string) *Cluster {
	return &Cluster{
		name: name,
	}
}

func (c *Cluster) Start() error {
	cmd := exec.Command(
		kindPath,
		"create",
		"cluster",
		"--name",
		c.name,
		"--image",
		kindImageVersions["1.13"],
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to start kubernetes cluster: %v", err)
	}
	config, err := c.readKubeConfig()
	if err != nil {
		return fmt.Errorf("failed while setting up kubeclient: %v", err)
	}

	c.restConfig, err = clientcmd.RESTConfigFromKubeConfig(config)
	if err != nil {
		return fmt.Errorf("failed while setting up restConfig: %v", err)
	}
	c.restClient, err = kubernetes.NewForConfig(c.restConfig)
	if err != nil {
		return fmt.Errorf("failed while setting up restClient: %v", err)
	}
	c.restApiExtensionClient, err = apiextensionsclient.NewForConfig(c.restConfig)
	if err != nil {
		return fmt.Errorf("failed while setting up apiextension client: %v", err)
	}
	return nil
}

func (c *Cluster) Stop() error {
	cmd := exec.Command(
		kindPath,
		"delete",
		"cluster",
		"--name",
		c.name,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to delete %s kubernetes cluster: %v", c.name, err)
	}
	return nil
}

func (c *Cluster) readKubeConfig() ([]byte, error) {
	cmd := exec.Command(
		kindPath,
		"get",
		"kubeconfig-path",
		"--name",
		c.name,
	)
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return []byte{}, err
	}
	c.kubeConfigPath = strings.TrimRight(out.String(), "\r\n")
	return ioutil.ReadFile(c.kubeConfigPath)
}

func createCRD(clientset *apiextensionsclient.Clientset, crds ...*v1beta1.CustomResourceDefinition) error {
	for _, crd := range crds {
		_, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Create(crd)
		if err != nil {
			return err
		}
	}
	return nil
}

// NewIstioClient returns pilots CRD client for ServiceRole, ServiceRoleBinding and ClusterRbacConfig
func NewIstioClient(kubeConfigPath string, dnsSuffix string) (*crd.Client, error) {
	configDescriptor := model.ConfigDescriptor{
		model.ServiceRole,
		model.ServiceRoleBinding,
		model.ClusterRbacConfig,
	}
	return crd.NewClient(kubeConfigPath, "", configDescriptor, dnsSuffix)
}

// NewAthenzDomainClient returns a CRD client for AthenzDomain
func NewAthenzDomainClient(restConfig *rest.Config) (*adClientset.Clientset, error) {
	return adClientset.NewForConfig(restConfig)
}

func NewAthenzController(
	dnsSuffix string,
	istioClient *crd.Client,
	k8sClient kubernetes.Interface,
	adClient *adClientset.Clientset,
	adResyncIntervalRaw, crcResyncIntervalRaw string,
	) (*controller.Controller, error) {
	adResyncInterval, err := time.ParseDuration(adResyncIntervalRaw)
	if err != nil {
		return nil, err
	}

	crcResyncInterval, err := time.ParseDuration(crcResyncIntervalRaw)
	if err != nil {
		return nil, err
	}
	return controller.NewController(dnsSuffix, istioClient, k8sClient, adClient, adResyncInterval, crcResyncInterval), nil
}



func getFakeDomain() zms.SignedDomain {
	domainName := "foo"
	const (
		username   = "user.name"
	)
	allow := zms.ALLOW
	timestamp, err := rdl.TimestampParse("2019-06-21T19:28:09.305Z")
	if err != nil {
		panic(err)
	}

	return zms.SignedDomain{
		Domain: &zms.DomainData{
			Modified: timestamp,
			Name:     zms.DomainName(domainName),
			Policies: &zms.SignedPolicies{
				Contents: &zms.DomainPolicies{
					Domain: zms.DomainName(domainName),
					Policies: []*zms.Policy{
						{
							Assertions: []*zms.Assertion{
								{
									Role:     domainName + ":role.admin",
									Resource: domainName + ".test:*",
									Action:   "*",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     zms.ResourceName(domainName + ":policy.admin"),
						},
					},
				},
				KeyId:     "col-env-1.1",
				Signature: "signature-policy",
			},
			Roles: []*zms.Role{
				{
					Members:  []zms.MemberName{zms.MemberName(username)},
					Modified: &timestamp,
					Name:     zms.ResourceName(domainName + ":role.admin"),
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: zms.MemberName(username),
						},
					},
				},
				{
					Trust:    "parent.domain",
					Modified: &timestamp,
					Name:     zms.ResourceName(domainName + ":role.trust"),
				},
			},
			Services: []*zms.ServiceIdentity{},
			Entities: []*zms.Entity{},
		},
		KeyId:     "colo-env-1.1",
		Signature: "signature",
	}
}