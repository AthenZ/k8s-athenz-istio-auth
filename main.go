// Copyright 2018, Oath Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/controller"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/zms"
	athenzClientset "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/clientset/versioned"

	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	certFile := flag.String("cert", "/var/run/athenz/service.cert.pem",
		"path to X.509 certificate file to use for zms authentication")
	keyFile := flag.String("key", "/var/run/athenz/service.key.pem",
		"path to private key file for zms authentication")
	zmsURL := flag.String("zms-url", "https://zms.url.com", "athenz full zms url including api path")
	pollInterval := flag.String("poll-interval", "1m", "controller poll interval")
	dnsSuffix := flag.String("dns-suffix", "svc.cluster.local", "dns suffix used for service role target services")
	flag.Parse()

	pi, err := time.ParseDuration(*pollInterval)
	if err != nil {
		log.Panicln("Cannot parse poll interval:", err.Error())
	}
	log.Println("Controller poll interval:", pi)

	err = zms.InitClient(*zmsURL, *certFile, *keyFile)
	if err != nil {
		log.Panicln("Error creating zms client:", err.Error())
	}

	configDescriptor := model.ConfigDescriptor{
		model.ServiceRole,
		model.ServiceRoleBinding,
		model.ClusterRbacConfig,
	}

	istioClient, err := crd.NewClient("", "", configDescriptor, *dnsSuffix)
	if err != nil {
		log.Panicln("Error creating istio crd client:", err.Error())
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Panicln("Error creating kubernetes in cluster config: " + err.Error())
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panicln("Error creating k8s client:", err.Error())
	}

	versiondClient, err := athenzClientset.NewForConfig(config)
	if err != nil {
		log.Panicln("Error creating athenz domain client:", err.Error())
	}

	c := controller.NewController(pi, *dnsSuffix, istioClient, k8sClient, versiondClient)

	stopChan := make(chan struct{})
	go c.Run(stopChan)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case <-signalChan:
			log.Println("Shutdown signal received, exiting...")
			close(stopChan)
			os.Exit(0)
		}
	}
}
