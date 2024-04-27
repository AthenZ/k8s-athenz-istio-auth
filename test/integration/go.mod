module github.com/yahoo/k8s-athenz-istio-auth/test/integration

go 1.16

require (
	github.com/MakeNowJust/heredoc v0.0.0-20171113091838-e9091a26100e // indirect
	github.com/NYTimes/gziphandler v1.1.1 // indirect
	github.com/ardielle/ardielle-go v1.5.2
	github.com/armon/go-metrics v0.0.0-20190430140413-ec5e00d3c878 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/chai2010/gettext-go v0.0.0-20170215093142-bf70f2a70fb1 // indirect
	github.com/coreos/bbolt v1.3.3 // indirect
	github.com/coreos/etcd v3.3.15+incompatible
	github.com/hashicorp/go-hclog v0.9.0 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.3 // indirect
	github.com/kr/pty v1.1.5 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.5.1
	github.com/yahoo/athenz v1.9.30
	github.com/yahoo/k8s-athenz-istio-auth v0.0.0-00010101000000-000000000000
	github.com/yahoo/k8s-athenz-syncer v0.1.7
	go.etcd.io/etcd v3.3.25+incompatible
	istio.io/api v0.0.0-20200513175333-ae3da0d240e3
	istio.io/client-go v0.0.0-20200513180646-f8d9d8ff84e6
	istio.io/istio v0.0.0-20200708165503-80f49905d910
	istio.io/pkg v0.0.0-20200324191837-25e6bb9cf135
	k8s.io/api v0.17.14
	k8s.io/apiextensions-apiserver v0.17.14
	k8s.io/apimachinery v0.17.14
	k8s.io/client-go v0.17.14
	k8s.io/klog/v2 v2.2.0
	k8s.io/kubernetes v0.17.14
	vbom.ml/util v0.0.0-20180919145318-efcd4e0f9787 // indirect
)

replace (
	github.com/yahoo/k8s-athenz-istio-auth => /sd/workspace/src/github.com/AthenZ/k8s-athenz-istio-auth
	go.etcd.io/bbolt => go.etcd.io/bbolt v1.3.3
	go.etcd.io/etcd => go.etcd.io/etcd v0.0.0-20191023171146-3cf2f69b5738
	k8s.io/api => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/api
	k8s.io/apiextensions-apiserver => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver
	k8s.io/apimachinery => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/apimachinery
	k8s.io/apiserver => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/apiserver
	k8s.io/cli-runtime => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/cli-runtime
	k8s.io/client-go => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/client-go
	k8s.io/cloud-provider => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/cloud-provider
	k8s.io/cluster-bootstrap => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/cluster-bootstrap
	k8s.io/code-generator => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/code-generator
	k8s.io/component-base => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/component-base
	k8s.io/cri-api => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/cri-api
	k8s.io/csi-translation-lib => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/csi-translation-lib
	k8s.io/kube-aggregator => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator
	k8s.io/kube-controller-manager => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/kube-controller-manager
	k8s.io/kube-openapi => /sd/workspace/src/k8s.io/kubernetes/vendor/k8s.io/kube-openapi
	k8s.io/kube-proxy => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/kube-proxy
	k8s.io/kube-scheduler => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/kube-scheduler
	k8s.io/kubectl => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/kubectl
	k8s.io/kubelet => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/kubelet
	k8s.io/kubernetes => /sd/workspace/src/k8s.io/kubernetes
	k8s.io/legacy-cloud-providers => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/legacy-cloud-providers
	k8s.io/metrics => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/metrics
	k8s.io/sample-apiserver => /sd/workspace/src/k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver
)
