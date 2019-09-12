module github.com/yahoo/k8s-athenz-istio-auth/test/integration

go 1.12

require (
	github.com/ardielle/ardielle-go v1.5.2
	github.com/aws/aws-sdk-go v1.23.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/coreos/etcd v3.3.15+incompatible
	github.com/coreos/go-systemd v0.0.0-20190719114852-fd7a80b32e1f // indirect
	github.com/d2g/dhcp4client v1.0.0 // indirect
	github.com/emicklei/go-restful-swagger12 v0.0.0-20170926063155-7524189396c6 // indirect
	github.com/go-openapi/strfmt v0.19.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.9.5 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/prometheus/procfs v0.0.3 // indirect
	github.com/robfig/cron v1.2.0 // indirect
	github.com/stretchr/testify v1.3.0
	github.com/vmware/govmomi v0.21.0 // indirect
	github.com/xanzy/go-cloudstack v2.4.1+incompatible // indirect
	github.com/yahoo/athenz v1.8.23
	github.com/yahoo/k8s-athenz-istio-auth v0.0.0-00010101000000-000000000000
	github.com/yahoo/k8s-athenz-syncer v0.1.1
	go.etcd.io/etcd v3.3.13+incompatible // indirect
	gopkg.in/gcfg.v1 v1.2.3 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	istio.io/api v0.0.0-20190906131201-ca4ba7013e1c
	istio.io/istio v0.0.0-20190911205955-c2bd59595ce6
	k8s.io/api v0.0.0-20190905160310-fb749d2f1064
	k8s.io/apiextensions-apiserver v0.0.0-20190906235842-a644246473f1
	k8s.io/apimachinery v0.0.0-20190831074630-461753078381
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/kubernetes v1.13.1
)

replace (
	github.com/Azure/azure-sdk-for-go => github.com/Azure/azure-sdk-for-go v21.4.0+incompatible
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v11.1.0+incompatible
	github.com/gophercloud/gophercloud => github.com/gophercloud/gophercloud v0.0.0-20180330165814-781450b3c4fc
	github.com/yahoo/k8s-athenz-istio-auth => /home/travis/gopath/src/github.com/yahoo/k8s-athenz-istio-auth
	k8s.io/api => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/api
	k8s.io/apiextensions-apiserver => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver
	k8s.io/apimachinery => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/apimachinery
	k8s.io/apiserver => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/apiserver
	k8s.io/client-go => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/client-go
	k8s.io/cloud-provider => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/cloud-provider
	k8s.io/cluster-bootstrap => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/cluster-bootstrap
	k8s.io/csi-api => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/csi-api
	k8s.io/kube-aggregator => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator
	k8s.io/kube-openapi => /home/travis/gopath/src/k8s.io/kubernetes/vendor/k8s.io/kube-openapi
	k8s.io/kubernetes => /home/travis/gopath/src/k8s.io/kubernetes
)
