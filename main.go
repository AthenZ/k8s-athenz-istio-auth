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

	c, err := controller.NewController(pi, *dnsSuffix)
	if err != nil {
		log.Panicln(err)
	}

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
