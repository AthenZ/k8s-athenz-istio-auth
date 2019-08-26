// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.

package framework

import (
	"flag"
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/coreos/etcd/embed"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/controller"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	athenzdomainclientset "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned"

	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/cmd/kube-apiserver/app"
	"k8s.io/kubernetes/cmd/kube-apiserver/app/options"

	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
)

var Global *Framework

type Framework struct {
	K8sClientset          kubernetes.Interface
	AthenzDomainClientset athenzdomainclientset.Interface
	IstioClientset        *crd.Client
	Controller            *controller.Controller
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
	s.Etcd.StorageConfig.ServerList = []string{"http://127.0.0.1:2379"}
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
	return restConfig, stopCh, server.PrepareRun().NonBlockingRun(stopCh)
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

	configDescriptor := model.ConfigDescriptor{
		model.ServiceRole,
		model.ServiceRoleBinding,
		model.ClusterRbacConfig,
	}

	istioClientset, err := crd.NewClient("", "", configDescriptor, "")
	if err != nil {
		return err
	}

	log.InitLogger("", "debug")
	c := controller.NewController("", istioClientset, k8sClientset, athenzDomainClientset, time.Minute, time.Minute)
	go c.Run(stopCh)

	Global = &Framework{
		K8sClientset:          k8sClientset,
		AthenzDomainClientset: athenzDomainClientset,
		IstioClientset:        istioClientset,
		Controller:            c,
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
