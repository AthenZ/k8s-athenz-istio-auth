// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.

package framework

import (
	"flag"
	authzpolicy "github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/authorizationpolicy"
	"io/ioutil"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
	"net"
	"os"
	"time"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	adInformer "github.com/yahoo/k8s-athenz-syncer/pkg/client/informers/externalversions/athenz/v1"
	"go.etcd.io/etcd/embed"
	crd "istio.io/istio/pilot/pkg/config/kube/crd/controller"
	istioController "istio.io/istio/pilot/pkg/serviceregistry/kube/controller"
	"istio.io/istio/pkg/config/schema/collection"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/pkg/ledger"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	athenzdomainclientset "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/kubernetes/cmd/kube-apiserver/app"
	"k8s.io/kubernetes/cmd/kube-apiserver/app/options"
)

var Global *Framework

type Framework struct {
	K8sClientset          kubernetes.Interface
	AthenzDomainClientset athenzdomainclientset.Interface
	IstioClientset        *crd.Client
	Controller            *authzpolicy.Controller
	etcd                  *embed.Etcd
	stopCh                chan struct{}
}

// runEtcd will setup up the etcd configuration and run the etcd server
func runEtcd() (*embed.Etcd, error) {
	etcdDataDir, err := ioutil.TempDir(os.TempDir(), "integration_test_etcd_data")
	if err != nil {
		return nil, err
	}

	config := embed.NewConfig()
	config.Dir = etcdDataDir
	return embed.StartEtcd(config)
}

// runApiServer will setup the api configuration and run the api server
func runApiServer(certDir string) (*rest.Config, chan struct{}, error) {
	s := options.NewServerRunOptions()

	// TODO, remove the webhooks and api server certs
	s.InsecureServing.BindAddress = net.ParseIP("127.0.0.1")
	s.InsecureServing.BindPort = 8080
	s.Etcd.StorageConfig.Transport.ServerList = []string{"http://127.0.0.1:2379"}
	s.SecureServing.ServerCert.CertDirectory = certDir

	completedOptions, err := app.Complete(s)
	if err != nil {
		return nil, nil, err
	}

	if errs := completedOptions.Validate(); len(errs) != 0 {
		return nil, nil, errors.NewAggregate(errs)
	}

	stopCh := make(chan struct{})
	server, err := app.CreateServerChain(completedOptions, stopCh)
	if err != nil {
		return nil, nil, err
	}

	restConfig := &rest.Config{}
	restConfig.Host = "http://127.0.0.1:8080"
	preparedApiAggregator, err := server.PrepareRun()
	if err != nil {
		return nil, nil, err
	}
	go func() {
		err = preparedApiAggregator.Run(stopCh)
		if err != nil {
			os.Exit(1)
		}
	}()
	return restConfig, stopCh, nil
}

// Setup will run both etcd and api server together
func Setup() error {
	if !flag.Parsed() {
		flag.Parse()
	}

	etcd, err := runEtcd()
	if err != nil {
		return err
	}

	restConfig, stopCh, err := runApiServer(etcd.Server.Cfg.DataDir)
	if err != nil {
		return err
	}

	crdClientset, err := apiextensionsclient.NewForConfig(restConfig)
	if err != nil {
		return err
	}

	err = fixtures.CreateCrds(crdClientset)
	if err != nil {
		return err
	}

	k8sClientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return err
	}

	err = fixtures.CreateNamespaces(k8sClientset)
	if err != nil {
		return err
	}

	athenzDomainClientset, err := athenzdomainclientset.NewForConfig(restConfig)
	if err != nil {
		return err
	}

	configDescriptor := collection.SchemasFor(collections.IstioSecurityV1Beta1Authorizationpolicies)
	ledgerValue := ledger.Make(time.Hour)
	istioClient, err := crd.NewClient("", "", configDescriptor, "", ledgerValue, "")
	if err != nil {
		return err
	}

	configStoreCache := crd.NewController(istioClient, istioController.Options{})
	serviceListWatch := cache.NewListWatchFromClient(k8sClientset.CoreV1().RESTClient(), "services", v1.NamespaceAll, fields.Everything())
	serviceIndexInformer := cache.NewSharedIndexInformer(serviceListWatch, &v1.Service{}, 0, nil)
	adIndexInformer := adInformer.NewAthenzDomainInformer(athenzDomainClientset, 0, cache.Indexers{})

	apController := authzpolicy.NewController(configStoreCache, serviceIndexInformer, adIndexInformer, istioClient, time.Minute, true, true, true, true, true, []string{"istio-system", "kube-yahoo"}, map[string]string{"istio-ingressgateway": "istio-system"}, []string{"k8s.omega.stage"})
	go apController.Run(stopCh)

	log.InitLogger("", "debug")

	Global = &Framework{
		K8sClientset:          k8sClientset,
		AthenzDomainClientset: athenzDomainClientset,
		IstioClientset:        istioClient,
		Controller:            apController,
		etcd:                  etcd,
		stopCh:                stopCh,
	}

	return nil
}

// Teardown will request the api server to shutdown
func Teardown() {
	close(Global.stopCh)
	Global.etcd.Close()
	err := os.RemoveAll(Global.etcd.Server.Cfg.DataDir)
	if err != nil {
		log.Println(err)
	}
	Global = nil
}
