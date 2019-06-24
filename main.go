// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package main

import (
	"flag"
	"log"
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
)

func main() {
	dnsSuffix := flag.String("dns-suffix", "svc.cluster.local", "dns suffix used for service role target services")
	kubeconfig := flag.String("kubeconfig", "", "(optional) absolute path to the kubeconfig file")
	adResyncIntervalRaw := flag.String("ad-resync-interval", "1h", "athenz domain resync interval")
	crcResyncIntervalRaw := flag.String("crc-resync-interval", "1h", "cluster rbac config resync interval")
	flag.Parse()

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
		log.Panicln("Error creating istio crd client:", err.Error())
	}

	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		log.Panicln("Error creating kubernetes in cluster config: " + err.Error())
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panicln("Error creating k8s client:", err.Error())
	}

	adClient, err := adClientset.NewForConfig(config)
	if err != nil {
		log.Panicln("Error creating athenz domain client:", err.Error())
	}

	adResyncInterval, err := time.ParseDuration(*adResyncIntervalRaw)
	if err != nil {
		log.Panicln("Error parsing ad-resync-interval duration:", err.Error())
	}

	crcResyncInterval, err := time.ParseDuration(*crcResyncIntervalRaw)
	if err != nil {
		log.Panicln("Error parsing crc-resync-interval duration:", err.Error())
	}

	c := controller.NewController(*dnsSuffix, istioClient, k8sClient, adClient, adResyncInterval, crcResyncInterval)

	stopCh := make(chan struct{})
	go c.Run(stopCh)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case <-signalCh:
			log.Println("Shutdown signal received, stopping controllers...")
			close(stopCh)
			// sleep to allow go routines to successfully exit
			time.Sleep(time.Second)
			log.Println("Shutting down...")
			os.Exit(0)
		}
	}
}
