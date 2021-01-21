// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package main

import (
	"flag"
	adClientset "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned"
	crd "istio.io/istio/pilot/pkg/config/kube/crd/controller"
	versionedclient "istio.io/client-go/pkg/clientset/versioned"

	"istio.io/istio/pkg/config/schema/collection"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/pkg/ledger"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"k8s.io/client-go/util/homedir"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/controller"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
)

func main() {
	dnsSuffix := flag.String("dns-suffix", "svc.cluster.local", "dns suffix used for service role target services")
	kubeconfig := flag.String("kubeconfig", "", "(optional) absolute path to the kubeconfig file")
	adResyncIntervalRaw := flag.String("ad-resync-interval", "1h", "athenz domain resync interval")
	crcResyncIntervalRaw := flag.String("crc-resync-interval", "1h", "cluster rbac config resync interval")
	enableOriginJwtSubject := flag.Bool("enable-origin-jwt-subject", true, "enable adding origin jwt subject to service role binding")
	apDryRun := flag.Bool("authz-policy-dry-run-mode", true, "enable dry run mode for authz policy resource")
	logFile := flag.String("log-file", "/var/log/k8s-athenz-istio-auth/k8s-athenz-istio-auth.log", "log file location")
	logLevel := flag.String("log-level", "info", "logging level")

	flag.Parse()
	log.InitLogger(*logFile, *logLevel)

	configDescriptor := collection.SchemasFor(collections.IstioRbacV1Alpha1Serviceroles, collections.IstioRbacV1Alpha1Clusterrbacconfigs, collections.IstioRbacV1Alpha1Servicerolebindings, collections.IstioSecurityV1Beta1Authorizationpolicies)
	// If kubeconfig arg is not passed-in, try user $HOME config only if it exists
	if *kubeconfig == "" {
		home := filepath.Join(homedir.HomeDir(), ".kube", "config")
		if _, err := os.Stat(home); err == nil {
			*kubeconfig = home
		}
	}

	//Ledger for tracking config distribution, specify how long it can retain its previous state
	configLedger := ledger.Make(time.Hour)
	istioClient, err := crd.NewClient(*kubeconfig, "", configDescriptor, *dnsSuffix, configLedger, "")
	if err != nil {
		log.Panicf("Error creating istio crd client: %s", err.Error())
	}

	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		log.Panicf("Error creating kubernetes in cluster config: %s", err.Error())
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panicf("Error creating k8s client: %s", err.Error())
	}

	adClient, err := adClientset.NewForConfig(config)
	if err != nil {
		log.Panicf("Error creating athenz domain client: %s", err.Error())
	}

	istioClientSet, err := versionedclient.NewForConfig(config)

	adResyncInterval, err := time.ParseDuration(*adResyncIntervalRaw)
	if err != nil {
		log.Panicf("Error parsing ad-resync-interval duration: %s", err.Error())
	}

	crcResyncInterval, err := time.ParseDuration(*crcResyncIntervalRaw)
	if err != nil {
		log.Panicf("Error parsing crc-resync-interval duration: %s", err.Error())
	}

	c := controller.NewController(*dnsSuffix, istioClient, k8sClient, adClient, istioClientSet, adResyncInterval, crcResyncInterval, *enableOriginJwtSubject, *apDryRun)

	stopCh := make(chan struct{})
	go c.Run(stopCh)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case <-signalCh:
			log.Infoln("Shutdown signal received, stopping controllers...")
			close(stopCh)
			// sleep to allow go routines to successfully exit
			time.Sleep(time.Second)
			log.Infoln("Shutting down...")
			os.Exit(0)
		}
	}
}
