// Copyright 2018, Oath Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package main

import (
	"errors"
	"flag"
	"k8s.io/client-go/dynamic"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/controller"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/zms"
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

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Panicln("Failed to create InClusterConfig:", err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panicln(err.Error())
	}

	dynClientSet, err := dynamic.NewForConfig(config)
	if err != nil {
		log.Panicln(err.Error())
	}

	namespaceListWatch := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "namespaces",
		v1.NamespaceAll, fields.Everything())
	namespaceIndexer, namespaceInformer := cache.NewIndexerInformer(namespaceListWatch, &v1.Namespace{}, 0,
		cache.ResourceEventHandlerFuncs{}, cache.Indexers{})

	stopChan := make(chan struct{})
	go namespaceInformer.Run(stopChan)

	if !cache.WaitForCacheSync(stopChan, namespaceInformer.HasSynced) {
		runtime.HandleError(errors.New("Timed out waiting for namespace cache to sync"))
		log.Panicln("Timed out waiting for namespace cache to sync.")
	}

	c := controller.Controller{
		NamespaceIndexer: namespaceIndexer,
		PollInterval:     pi,
		DNSSuffix:        *dnsSuffix,
		DynamicClientSet: dynClientSet,
		DomainsLister:    zms.NewDomainsLister(),
	}
	go c.Run()

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
