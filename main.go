// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package main

import (
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	adClientset "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/clientset/versioned"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/controller"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
)

const logPrefix = "[main]"

func main() {
	dnsSuffix := flag.String("dns-suffix", "svc.cluster.local", "dns suffix used for service role target services")
	kubeconfig := flag.String("kubeconfig", "", "(optional) absolute path to the kubeconfig file")
	adResyncIntervalRaw := flag.String("ad-resync-interval", "1h", "athenz domain resync interval")
	crcResyncIntervalRaw := flag.String("crc-resync-interval", "1h", "cluster rbac config resync interval")
	logFile := flag.String("log-file", "/var/log/k8s-athenz-istio-auth/k8s-athenz-istio-auth.log", "log file location")
	logLevel := flag.String("log-level", "info", "logging level")

	flag.Parse()
	log.InitLogger(*logFile, *logLevel)

	configDescriptor := model.ConfigDescriptor{
		model.ServiceRole,
		model.ServiceRoleBinding,
		model.ClusterRbacConfig,
	}

	// If kubeconfig arg is not passed-in, try user $HOME config only if it exists
	if *kubeconfig == "" {
		home := filepath.Join(homedir.HomeDir(), ".kube", "config")
		if _, err := os.Stat(home); err == nil {
			*kubeconfig = home
		}
	}

	istioClient, err := crd.NewClient(*kubeconfig, "", configDescriptor, *dnsSuffix)
	if err != nil {
		log.Panicf("%s Error creating istio crd client: %s", logPrefix, err.Error())
	}

	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		log.Panicf("%s Error creating kubernetes in cluster config: %s", logPrefix, err.Error())
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panicf("%s Error creating k8s client: %s", logPrefix, err.Error())
	}

	adClient, err := adClientset.NewForConfig(config)
	if err != nil {
		log.Panicf("%s Error creating athenz domain client: %s", logPrefix, err.Error())
	}

	adResyncInterval, err := time.ParseDuration(*adResyncIntervalRaw)
	if err != nil {
		log.Panicf("%s Error parsing ad-resync-interval duration: %s", logPrefix, err.Error())
	}

	crcResyncInterval, err := time.ParseDuration(*crcResyncIntervalRaw)
	if err != nil {
		log.Panicf("%s Error parsing crc-resync-interval duration: %s", logPrefix, err.Error())
	}

	c := controller.NewController(*dnsSuffix, istioClient, k8sClient, adClient, adResyncInterval, crcResyncInterval)

	stopCh := make(chan struct{})
	go c.Run(stopCh)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case <-signalCh:
			log.Infof("%s Shutdown signal received, stopping controllers...", logPrefix)
			close(stopCh)
			// sleep to allow go routines to successfully exit
			time.Sleep(time.Second)
			log.Infof("%s Shutting down...", logPrefix)
			os.Exit(0)
		}
	}
}
