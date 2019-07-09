package integration

import (
		"log"
	"os"

			"k8s.io/component-base/logs"
	"testing"
		"k8s.io/client-go/rest"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"time"
		"k8s.io/apiextensions-apiserver/pkg/cmd/server/options"
	genericapiserver "k8s.io/apiserver/pkg/server"
		"net"
)

func run(o *options.CustomResourceDefinitionsServerOptions, stopCh <-chan struct{}) {
	config, err := o.Config()
	if err != nil {
		log.Panic(err)
	}

	server, err := config.Complete().New(genericapiserver.NewEmptyDelegate())
	if err != nil {
		log.Panic(err)
	}
	err = server.GenericAPIServer.PrepareRun().Run(stopCh)
	if err != nil {
		log.Panic(err)
	}
}

func NewOptions() {
	//o := &CustomResourceDefinitionsServerOptions{
	//	RecommendedOptions: genericoptions.NewRecommendedOptions(
	//		defaultEtcdPathPrefix,
	//		apiserver.Codecs.LegacyCodec(v1beta1.SchemeGroupVersion),
	//		genericoptions.NewProcessInfo("apiextensions-apiserver", "kube-system"),
	//	),
	//	APIEnablement: genericoptions.NewAPIEnablementOptions(),
	//
	//	StdOut: out,
	//	StdErr: errOut,
	//}
}



func runApiServer() {
	stopCh := make(chan struct{})
	//apiserveroptions.NewRecommendedOptions()
	//o := apiserveroptions.NewCoreAPIOptions()

	o := options.NewCustomResourceDefinitionsServerOptions(os.Stdout, os.Stderr)

	listener, err := net.Listen("tcp4", "127.0.0.1:9999")
	if err != nil {
		log.Panicln(err)
	}
	o.RecommendedOptions.SecureServing.Listener = listener
	//o.RecommendedOptions.CoreAPI.CoreAPIKubeconfigPath
	o.RecommendedOptions.Etcd.StorageConfig.Transport.ServerList = []string{"localhost:2379"}
	o.RecommendedOptions.Authentication.RemoteKubeConfigFile = "/Users/mcieplak/.kube/config"
	o.RecommendedOptions.Authorization.RemoteKubeConfigFile = "/Users/mcieplak/.kube/config"
	o.RecommendedOptions.CoreAPI.CoreAPIKubeconfigPath = "/Users/mcieplak/.kube/config"
	if err := o.Complete(); err != nil {
		log.Panic(err)
	}
	if err := o.Validate(); err != nil {
		log.Panic(err)
	}

	go run(o, stopCh)
}


func TestMain(m *testing.M) {
	logs.InitLogs()
	defer logs.FlushLogs()
	runApiServer()

	createCr()

	time.Sleep(10 * time.Minute)
}

func createCr() {
	restConfig := &rest.Config{}
	restConfig.Host = "https://127.0.0.1:9999"
	restConfig.TLSClientConfig.Insecure = true

	crd := &v1beta1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind: "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "athenzdomains.athenz.io",
		},
		Spec: v1beta1.CustomResourceDefinitionSpec{
			Group: "athenz.io",
			Version: "v1",
			Names: v1beta1.CustomResourceDefinitionNames{
				Plural: "athenzdomains",
				Singular: "athenzdomain",
				Kind: "AthenzDomain",
				ShortNames: []string{"domain"},
				ListKind: "AthenzDomainList",
			},
		},
	}

	rClientset, err := apiextensionsclient.NewForConfig(restConfig)
	if err != nil {
		log.Println(err)
	}
	_, err = rClientset.ApiextensionsV1beta1().CustomResourceDefinitions().Create(crd)
	if err != nil {
		log.Println(err)
	}
}
























//package integration
//
//import (
//	"crypto/tls"
//	"io/ioutil"
//	"log"
//	"net"
//	"os"
//	"testing"
//	"time"
//
//	openapi "github.com/go-openapi/spec"
//	"k8s.io/apimachinery/pkg/runtime"
//	"k8s.io/apimachinery/pkg/runtime/serializer"
//	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
//	openapinamer "k8s.io/apiserver/pkg/endpoints/openapi"
//	"k8s.io/apiserver/pkg/server"
//	"k8s.io/client-go/informers"
//	"k8s.io/client-go/kubernetes"
//	"k8s.io/client-go/rest"
//	kubeopenapi "k8s.io/kube-openapi/pkg/common"
//		"github.com/coreos/etcd/etcdserver"
//	"github.com/coreos/etcd/pkg/types"
//	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
//	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
//	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
//	"k8s.io/klog"
//	"k8s.io/apiserver/pkg/registry/rest"
//	genericoptions "k8s.io/apiserver/pkg/server/options"
//	extensionsapiv1beta1 "k8s.io/api/extensions/v1beta1"
//	extensionsrest "k8s.io/kubernetes/pkg/registry/extensions/rest"
//	serverstorage "k8s.io/apiserver/pkg/server/storage"
//)
//
//func TestMain(m *testing.M) {
//	restConfig := &rest.Config{}
//	restConfig.Host = "https://127.0.0.1:9999"
//	restConfig.TLSClientConfig.Insecure = true
//
//	clientset, err := kubernetes.NewForConfig(restConfig)
//	if err != nil {
//		log.Panicln(err)
//	}
//
//	Scheme := runtime.NewScheme()
//	config := server.NewConfig(serializer.NewCodecFactory(Scheme))
//	config.Authorization.Authorizer = authorizerfactory.NewAlwaysAllowAuthorizer()
//	listener, err := net.Listen("tcp4", "127.0.0.1:9999")
//	if err != nil {
//		log.Panicln(err)
//	}
//	cert, err := tls.LoadX509KeyPair("/Users/mcieplak/.athenz/cert", "/Users/mcieplak/.athenz/key")
//	if err != nil {
//		log.Panicln(err)
//	}
//	config.SecureServing = &server.SecureServingInfo{
//		Listener: listener,
//		Cert:     &cert,
//	}
//	config.LoopbackClientConfig = restConfig
//	config.OpenAPIConfig = server.DefaultOpenAPIConfig(testGetOpenAPIDefinitions, openapinamer.NewDefinitionNamer(runtime.NewScheme()))
//
//	stopCh := make(chan struct{})
//	shared := informers.NewSharedInformerFactory(clientset, 0)
//	apiServer, err := config.Complete(shared).New("api-server", server.NewEmptyDelegate())
//	if err != nil {
//		log.Panicln(err)
//	}
//
//
//	//restStorageProviders := []RESTStorageProvider{
//		//auditregistrationrest.RESTStorageProvider{},
//		//authenticationrest.RESTStorageProvider{Authenticator: c.GenericConfig.Authentication.Authenticator, APIAudiences: c.GenericConfig.Authentication.APIAudiences},
//		//authorizationrest.RESTStorageProvider{Authorizer: c.GenericConfig.Authorization.Authorizer, RuleResolver: c.GenericConfig.RuleResolver},
//		//autoscalingrest.RESTStorageProvider{},
//		//batchrest.RESTStorageProvider{},
//		//certificatesrest.RESTStorageProvider{},
//		//coordinationrest.RESTStorageProvider{},
//		//extensionsrest.RESTStorageProvider{},
//		//networkingrest.RESTStorageProvider{},
//		//noderest.RESTStorageProvider{},
//		//policyrest.RESTStorageProvider{},
//		//rbacrest.RESTStorageProvider{Authorizer: c.GenericConfig.Authorization.Authorizer},
//		//schedulingrest.RESTStorageProvider{},
//		//settingsrest.RESTStorageProvider{},
//		//storagerest.RESTStorageProvider{},
//		// keep apps after extensions so legacy clients resolve the extensions versions of shared resource names.
//		// See https://github.com/kubernetes/kubernetes/issues/42392
//		//appsrest.RESTStorageProvider{},
//		//admissionregistrationrest.RESTStorageProvider{},
//		//eventsrest.RESTStorageProvider{TTL: c.ExtraConfig.EventTTL},
//	//}
//
//	apiGroupsInfo := []*server.APIGroupInfo{}
//
//	restStorageBuilder := extensionsrest.RESTStorageProvider{}
//	rest.Storage
//	//&ResourceConfig{GroupVersionConfigs: map[schema.GroupVersion]bool{}, ResourceConfigs: map[schema.GroupVersionResource]bool{}}
//	//for _, restStorageBuilder := range restStorageProviders {
//		groupName := restStorageBuilder.GroupName()
//		apiResourceConfigSource := DefaultAPIResourceConfigSource()
//		if !apiResourceConfigSource.AnyVersionForGroupEnabled(groupName) {
//			log.Panicf("Skipping disabled API group %q.", groupName)
//		}
//		restOptionsGetter := &genericoptions.SimpleRestOptionsFactory{}
//		apiGroupInfo, enabled := restStorageBuilder.NewRESTStorage(apiResourceConfigSource, restOptionsGetter)
//		if !enabled {
//			log.Panicf("Problem initializing API group %q, skipping.", groupName)
//		}
//		klog.V(1).Infof("Enabling API group %q.", groupName)
//
//		//if postHookProvider, ok := restStorageBuilder.(genericapiserver.PostStartHookProvider); ok {
//		//	name, hook, err := postHookProvider.PostStartHook()
//		//	if err != nil {
//		//		klog.Fatalf("Error building PostStartHook: %v", err)
//		//	}
//		//	m.GenericAPIServer.AddPostStartHookOrDie(name, hook)
//		//}
//
//		apiGroupsInfo = append(apiGroupsInfo, &apiGroupInfo)
//	//}
//
//
//
//
//
//
//	go apiServer.PrepareRun().Run(stopCh)
//
//	crd := &v1beta1.CustomResourceDefinition{
//		TypeMeta: metav1.TypeMeta{
//			Kind: "CustomResourceDefinition",
//			APIVersion: "apiextensions.k8s.io/v1beta1",
//		},
//		ObjectMeta: metav1.ObjectMeta{
//			Name: "athenzdomains.athenz.io",
//		},
//		Spec: v1beta1.CustomResourceDefinitionSpec{
//			Group: "athenz.io",
//			Version: "v1",
//			Names: v1beta1.CustomResourceDefinitionNames{
//				Plural: "athenzdomains",
//				Singular: "athenzdomain",
//				Kind: "AthenzDomain",
//				ShortNames: []string{"domain"},
//				ListKind: "AthenzDomainList",
//			},
//		},
//	}
//
//	rClientset, err := apiextensionsclient.NewForConfig(restConfig)
//	if err != nil {
//		log.Println(err)
//	}
//	_, err = rClientset.ApiextensionsV1beta1().CustomResourceDefinitions().Create(crd)
//	if err != nil {
//		log.Println(err)
//	}
//	//config := server.RecommendedConfig{}
//	//config.Serializer = &fakeNegotiatedSerializer{}
//	//config.LoopbackClientConfig = restConfig
//	//config.OpenAPIConfig = nil
//	//config.SecureServing = nil
//	//foo := config.Complete()
//
//	//foo := server.CompletedConfig{}
//	//delegate := server.NewEmptyDelegate()
//	//if delegate == nil {
//	//	log.Println("delegate is nil")
//	//	return
//	//}
//	//
//	//log.Println("here")
//	//_, err := foo.New("api-server", delegate)
//	//log.Println("after here")
//	//if err != nil {
//	//	log.Println(err)
//	//	return
//	//}
//	//
//	//stopCh := make(chan struct{})
//	//err = srv.PrepareRun().Run(stopCh)
//	//if err != nil {
//	//	log.Println(err)
//	//	return
//	//}
//
//	etcdDataDir, err := ioutil.TempDir(os.TempDir(), "integration_test_etcd_data")
//	if err != nil {
//		log.Panicf("unable to make temp etcd data dir: %v", err)
//	}
//	etcdUrl, err := types.NewURLs([]string{"http://127.0.0.1:2379"})
//	if err != nil {
//		log.Panicf("err getting etc url: %v", err)
//	}
//	etcdUrlMap, err := types.NewURLsMap("myetcd=http://127.0.0.1:2379")
//	if err != nil {
//		log.Panicf("err getting etc url map: %v", err)
//	}
//
//	cfg := etcdserver.ServerConfig{
//		Name:               "myetcd",
//		DataDir:            etcdDataDir,
//		NewCluster:         true,
//		ClientURLs:         etcdUrl,
//		PeerURLs:           etcdUrl,
//		ForceNewCluster:    true,
//		InitialPeerURLsMap: etcdUrlMap,
//		ElectionTicks:      2,
//	}
//	etcd, err := etcdserver.NewServer(cfg)
//	if err != nil {
//		log.Panicln(err)
//	}
//	go etcd.Start()
//
//	m.Run()
//	time.Sleep(time.Minute)
//	log.Println("exiting...")
//}
//
//func testGetOpenAPIDefinitions(_ kubeopenapi.ReferenceCallback) map[string]kubeopenapi.OpenAPIDefinition {
//	return map[string]kubeopenapi.OpenAPIDefinition{
//		"k8s.io/apimachinery/pkg/apis/meta/v1.Status":          {},
//		"k8s.io/apimachinery/pkg/apis/meta/v1.APIVersions":     {},
//		"k8s.io/apimachinery/pkg/apis/meta/v1.APIGroupList":    {},
//		"k8s.io/apimachinery/pkg/apis/meta/v1.APIGroup":        buildTestOpenAPIDefinition(),
//		"k8s.io/apimachinery/pkg/apis/meta/v1.APIResourceList": {},
//	}
//}
//
//func buildTestOpenAPIDefinition() kubeopenapi.OpenAPIDefinition {
//	return kubeopenapi.OpenAPIDefinition{
//		Schema: openapi.Schema{
//			SchemaProps: openapi.SchemaProps{
//				Description: "Description",
//				Properties:  map[string]openapi.Schema{},
//			},
//			VendorExtensible: openapi.VendorExtensible{
//				Extensions: openapi.Extensions{
//					"x-kubernetes-group-version-kind": []map[string]string{
//						{
//							"group":   "",
//							"version": "v1",
//							"kind":    "Getter",
//						},
//						{
//							"group":   "batch",
//							"version": "v1",
//							"kind":    "Getter",
//						},
//						{
//							"group":   "extensions",
//							"version": "v1",
//							"kind":    "Getter",
//						},
//					},
//				},
//			},
//		},
//	}
//}
//
//
//func DefaultAPIResourceConfigSource() *serverstorage.ResourceConfig {
//	ret := serverstorage.NewResourceConfig()
//	// NOTE: GroupVersions listed here will be enabled by default. Don't put alpha versions in the list.
//	ret.EnableVersions(
//		//admissionregistrationv1.SchemeGroupVersion,
//		//admissionregistrationv1beta1.SchemeGroupVersion,
//		//apiv1.SchemeGroupVersion,
//		//appsv1.SchemeGroupVersion,
//		//authenticationv1.SchemeGroupVersion,
//		//authenticationv1beta1.SchemeGroupVersion,
//		//authorizationapiv1.SchemeGroupVersion,
//		//authorizationapiv1beta1.SchemeGroupVersion,
//		//autoscalingapiv1.SchemeGroupVersion,
//		//autoscalingapiv2beta1.SchemeGroupVersion,
//		//autoscalingapiv2beta2.SchemeGroupVersion,
//		//batchapiv1.SchemeGroupVersion,
//		//batchapiv1beta1.SchemeGroupVersion,
//		//certificatesapiv1beta1.SchemeGroupVersion,
//		//coordinationapiv1.SchemeGroupVersion,
//		//coordinationapiv1beta1.SchemeGroupVersion,
//		//eventsv1beta1.SchemeGroupVersion,
//		extensionsapiv1beta1.SchemeGroupVersion,
//		//networkingapiv1.SchemeGroupVersion,
//		//networkingapiv1beta1.SchemeGroupVersion,
//		//nodev1beta1.SchemeGroupVersion,
//		//policyapiv1beta1.SchemeGroupVersion,
//		//rbacv1.SchemeGroupVersion,
//		//rbacv1beta1.SchemeGroupVersion,
//		//storageapiv1.SchemeGroupVersion,
//		//storageapiv1beta1.SchemeGroupVersion,
//		//schedulingapiv1beta1.SchemeGroupVersion,
//		//schedulingapiv1.SchemeGroupVersion,
//	)
//	// enable non-deprecated beta resources in extensions/v1beta1 explicitly so we have a full list of what's possible to serve
//	ret.EnableResources(
//		extensionsapiv1beta1.SchemeGroupVersion.WithResource("ingresses"),
//	)
//	// disable deprecated beta resources in extensions/v1beta1 explicitly so we have a full list of what's possible to serve
//	ret.DisableResources(
//		extensionsapiv1beta1.SchemeGroupVersion.WithResource("daemonsets"),
//		extensionsapiv1beta1.SchemeGroupVersion.WithResource("deployments"),
//		extensionsapiv1beta1.SchemeGroupVersion.WithResource("networkpolicies"),
//		extensionsapiv1beta1.SchemeGroupVersion.WithResource("podsecuritypolicies"),
//		extensionsapiv1beta1.SchemeGroupVersion.WithResource("replicasets"),
//		extensionsapiv1beta1.SchemeGroupVersion.WithResource("replicationcontrollers"),
//	)
//	// disable deprecated beta versions explicitly so we have a full list of what's possible to serve
//	//ret.DisableVersions(
//	//	appsv1beta1.SchemeGroupVersion,
//	//	appsv1beta2.SchemeGroupVersion,
//	//)
//	// disable alpha versions explicitly so we have a full list of what's possible to serve
//	//ret.DisableVersions(
//	//	auditregistrationv1alpha1.SchemeGroupVersion,
//	//	batchapiv2alpha1.SchemeGroupVersion,
//	//	nodev1alpha1.SchemeGroupVersion,
//	//	rbacv1alpha1.SchemeGroupVersion,
//	//	schedulingv1alpha1.SchemeGroupVersion,
//	//	settingsv1alpha1.SchemeGroupVersion,
//	//	storageapiv1alpha1.SchemeGroupVersion,
//	//)
//
//	return ret
//}