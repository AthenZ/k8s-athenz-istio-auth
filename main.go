// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package main

import (
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	authzpolicy "github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/authorizationpolicy"
	adInformer "github.com/yahoo/k8s-athenz-syncer/pkg/client/informers/externalversions/athenz/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	adClientset "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned"
	versionedclient "istio.io/client-go/pkg/clientset/versioned"
	crdController "istio.io/istio/pilot/pkg/config/kube/crd/controller"
	istioController "istio.io/istio/pilot/pkg/serviceregistry/kube/controller"
	"istio.io/istio/pkg/config/schema/collection"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/pkg/ledger"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/klog/v2"
)

func main() {
	dnsSuffix := flag.String("dns-suffix", "svc.cluster.local", "dns suffix used for service role target services")
	kubeconfig := flag.String("kubeconfig", "", "(optional) absolute path to the kubeconfig file")
	apResyncIntervalRaw := flag.String("ap-resync-interval", "1h", "authorization policy resync interval")
	enableOriginJwtSubject := flag.Bool("enable-origin-jwt-subject", true, "enable adding origin jwt subject to service role binding")
	logFile := flag.String("log-file", "/var/log/k8s-athenz-istio-auth/k8s-athenz-istio-auth.log", "log file location")
	logLevel := flag.String("log-level", "info", "logging level")
	enableAuthzPolicyController := flag.Bool("enable-ap-controller", true, "enable authzpolicy controller to create authzpolicy dry run resource")
	authzPolicyEnabledList := flag.String("ap-enabled-list", "", "List of namespace/service that enabled authz policy, "+
		"use format 'example-ns1/example-service1' to enable a single service, use format 'example-ns2/*' to enable all services in a namespace, and use '*' to enable all services in the cluster' ")
	combinationPolicyTag := flag.String("combo-policy-tag", "proxy-principals", "key of tag for proxy principals list")
	enableSpiffeTrustDomain := flag.Bool("enable-spiffe-trust-domain", true, "Allow new SPIFFE ID's")
	adminDomain := flag.String("admin-domain", "", "admin domain")
	systemNamespaces := flag.String("system-namespaces", "istio-system,kube-system", "list of cluster system namespaces")
	customServiceMap := flag.String("service-account-map", "", "for cloud cluster trace the namespace based on the sa")

	klog.InitFlags(nil)
	flag.Set("logtostderr", "false")
	flag.Set("logtostdout", "false")
	flag.Parse()
	log.InitLogger(*logFile, *logLevel)

	// Throw error if the admin domain is nil or empty
	if adminDomain == nil || len(strings.TrimSpace(*adminDomain)) == 0 {
		log.Panicf("Error admin-domain is nil or empty")
	}

	// Throw error if service account map is empty of nil
	if customServiceMap == nil || len(strings.TrimSpace(*customServiceMap)) == 0 {
		log.Panicf("Error service-account-map is nil or empty")
	}

	// When enableAuthzPolicyController is set to true create a dry run folder which
	// would contain the Authorization Policy resource for all the namespaces/services which
	// are not passed as a parameter in --ap-enabled-list
	if *enableAuthzPolicyController {
		// If the Authz Policy folder already exists remove the stale data
		if _, err := os.Stat(common.DryRunStoredFilesDirectory); err == nil {
			err := os.RemoveAll(common.DryRunStoredFilesDirectory)
			if err != nil {
				log.Panicf("Error when removing authz policy directory: %s", err.Error())
			}
		} else if !os.IsNotExist(err) {
			log.Panicf("Error when checking for the presence of the dry run directory: %s", err.Error())
		}

		err := os.MkdirAll(common.DryRunStoredFilesDirectory, 0755)
		if err != nil {
			log.Panicf("Error when creating authz policy directory: %s", err.Error())
		}
	}
	var configDescriptor collection.Schemas
	configDescriptor = collection.SchemasFor(collections.IstioSecurityV1Beta1Authorizationpolicies)
	// If kubeconfig arg is not passed-in, try user $HOME config only if it exists
	if *kubeconfig == "" {
		home := filepath.Join(homedir.HomeDir(), ".kube", "config")
		if _, err := os.Stat(home); err == nil {
			*kubeconfig = home
		}
	}

	// Ledger for tracking config distribution, specify how long it can retain its previous state
	configLedger := ledger.Make(time.Hour)
	istioClient, err := crdController.NewClient(*kubeconfig, "", configDescriptor, *dnsSuffix, configLedger, "")
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

	apResyncInterval, err := time.ParseDuration(*apResyncIntervalRaw)
	if err != nil {
		log.Panicf("Error parsing ap-resync-interval duration: %s", err.Error())
	}

	// When enableAuthzPolicyController is set to true determine which services,
	// namespaces or cluster to create Authorization Policies for
	var componentsEnabledAuthzPolicy *common.ComponentEnabled
	if *enableAuthzPolicyController {
		componentsEnabledAuthzPolicy, err = common.ParseComponentsEnabledAuthzPolicy(*authzPolicyEnabledList)
		if err != nil {
			log.Panicf("Error parsing components-enabled-authzpolicy list from command line arguments: %s", err.Error())
		}
	}

	stopCh := make(chan struct{})
	namespaces := strings.Split(*systemNamespaces, ",")
	for i, namespace := range namespaces {
		namespaces[i] = strings.TrimSpace(namespace)
	}
	serviceAccountNamespaceMap := map[string]string{}
	for _, serviceAccount := range strings.Split(*customServiceMap, ",") {
		saKeyValue := strings.Split(serviceAccount, ":")
		if len(saKeyValue) == 2 {
			serviceAccountNamespaceMap[saKeyValue[0]] = saKeyValue[1]
		}
	}
	var adminDomains = make([]string, 0)
	for _, domain := range strings.Split(*adminDomain, ",") {
		adminDomains = append(adminDomains, strings.TrimSpace(domain))
	}
	configStoreCache := crdController.NewController(istioClient, istioController.Options{})
	serviceListWatch := cache.NewListWatchFromClient(k8sClient.CoreV1().RESTClient(), "services", v1.NamespaceAll, fields.Everything())
	serviceIndexInformer := cache.NewSharedIndexInformer(serviceListWatch, &v1.Service{}, 0, nil)
	adIndexInformer := adInformer.NewAthenzDomainInformer(adClient, 0, cache.Indexers{})

	apController := authzpolicy.NewController(configStoreCache, serviceIndexInformer, adIndexInformer, istioClientSet, apResyncInterval, *enableOriginJwtSubject, componentsEnabledAuthzPolicy, *combinationPolicyTag, *enableSpiffeTrustDomain, namespaces, serviceAccountNamespaceMap, adminDomains)
	configStoreCache.RegisterEventHandler(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), apController.EventHandler)
	go apController.Run(stopCh)

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
