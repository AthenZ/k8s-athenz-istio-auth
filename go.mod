module github.com/yahoo/k8s-athenz-istio-auth

go 1.12

require (
	bitbucket.org/ww/goautoneg v0.0.0-20120707110453-75cd24fc2f2c
	github.com/Azure/go-autorest v11.1.2+incompatible // indirect
	github.com/NYTimes/gziphandler v0.0.0-20170623195520-56545f4a5d46
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578
	github.com/ardielle/ardielle-go v1.5.2
	github.com/beorn7/perks v0.0.0-20180321164747-3a771d992973
	github.com/coreos/bbolt v1.3.3
	github.com/coreos/etcd v3.3.13+incompatible
	github.com/coreos/go-semver v0.3.0
	github.com/coreos/go-systemd v0.0.0-20190719114852-fd7a80b32e1f
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f
	github.com/davecgh/go-spew v1.1.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/elazarl/go-bindata-assetfs v1.0.0
	github.com/emicklei/go-restful v2.9.5+incompatible
	github.com/emicklei/go-restful-swagger12 v0.0.0-20170926063155-7524189396c6
	github.com/envoyproxy/go-control-plane v0.8.2
	github.com/envoyproxy/protoc-gen-validate v0.0.14
	github.com/evanphx/json-patch v4.5.0+incompatible
	github.com/ghodss/yaml v1.0.0
	github.com/go-openapi/spec v0.19.2
	github.com/gogo/googleapis v1.1.0
	github.com/gogo/protobuf v1.2.1
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/groupcache v0.0.0-20190129154638-5b532d6fd5ef
	github.com/golang/protobuf v1.3.2
	github.com/golangci/golangci-lint v1.17.1
	github.com/google/btree v1.0.0
	github.com/google/gofuzz v1.0.0
	github.com/googleapis/gnostic v0.3.0
	github.com/gophercloud/gophercloud v0.1.0 // indirect
	github.com/gorilla/mux v1.7.1
	github.com/gorilla/websocket v1.4.0
	github.com/gregjones/httpcache v0.0.0-20190212212710-3befbb6ad0cc
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.9.5
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/golang-lru v0.5.1
	github.com/hpcloud/tail v1.0.0
	github.com/imdario/mergo v0.3.7
	github.com/jonboulle/clockwork v0.1.0
	github.com/json-iterator/go v1.1.6
	github.com/kisielk/errcheck v1.2.0 // indirect
	github.com/mailru/easyjson v0.0.0-20190614124828-94de47d64c63
	github.com/matttproud/golang_protobuf_extensions v1.0.1
	github.com/mitchellh/copystructure v1.0.0
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd
	github.com/modern-go/reflect2 v1.0.1
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/natefinch/lumberjack v2.0.0+incompatible
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.0
	github.com/pborman/uuid v1.2.0
	github.com/peterbourgon/diskv v2.0.1+incompatible
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v0.9.3-0.20190127221311-3c4408c8b829
	github.com/prometheus/client_model v0.0.0-20190115171406-56726106282f
	github.com/prometheus/common v0.2.0
	github.com/prometheus/procfs v0.0.0-20190117184657-bf6a532e95b1
	github.com/sirupsen/logrus v1.4.2
	github.com/soheilhy/cmux v0.1.4
	github.com/spf13/cobra v0.0.3
	github.com/spf13/pflag v1.0.3
	github.com/stretchr/testify v1.3.0
	github.com/tmc/grpc-websocket-proxy v0.0.0-20190109142713-0ad062ec5ee5
	github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2
	github.com/yahoo/athenz v1.8.23
	github.com/yahoo/k8s-athenz-syncer v0.0.0-20190723220116-8fdcf4f19bd0
	github.com/yl2chen/cidranger v0.0.0-20180214081945-928b519e5268 // indirect
	go.opencensus.io v0.22.0
	go.uber.org/atomic v1.4.0
	go.uber.org/multierr v1.1.0
	go.uber.org/zap v1.10.0
	golang.org/x/crypto v0.0.0-20190611184440-5c40567a22f8
	golang.org/x/net v0.0.0-20190613194153-d28f0bde5980
	golang.org/x/oauth2 v0.0.0-20190402181905-9f3314589c9a
	golang.org/x/sys v0.0.0-20190616124812-15dcb6c0061f
	golang.org/x/text v0.3.2
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	google.golang.org/appengine v1.5.0
	google.golang.org/genproto v0.0.0-20190425155659-357c62f0e4bb
	google.golang.org/grpc v1.20.1
	gopkg.in/fsnotify.v1 v1.4.7
	gopkg.in/inf.v0 v0.9.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7
	gopkg.in/yaml.v1 v1.0.0-20140924161607-9f9df34309c0 // indirect
	gopkg.in/yaml.v2 v2.2.2
	istio.io/api v0.0.0-20190515205759-982e5c3888c6
	istio.io/istio v0.0.0-20190515005051-eec7a74473de
	istio.io/pkg v0.0.0-20190726080000-e5d6de6b352b
	k8s.io/api v0.0.0-20190726022912-69e1bce1dad5
	k8s.io/apiextensions-apiserver v0.0.0-20180905004947-16750353bf97
	k8s.io/apimachinery v0.0.0-20190726022757-641a75999153
	k8s.io/apiserver v0.0.0-20190726023815-781c3cd1b3dc
	k8s.io/client-go v8.0.0+incompatible
	k8s.io/klog v0.3.1
	k8s.io/kube-openapi v0.0.0-20190722073852-5e22f3d471e6
	k8s.io/utils v0.0.0-20190712204705-3dccf664f023
)

replace (
	istio.io/api => istio.io/api v0.0.0-20190416154520-4a9a2a12a700
	istio.io/istio => istio.io/istio v0.0.0-20190515005051-eec7a74473de
	k8s.io/api => k8s.io/api v0.0.0-20190118113203-912cbe2bfef3
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20180905004947-16750353bf97 // indirect
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190223001710-c182ff3b9841
	k8s.io/client-go => k8s.io/client-go v8.0.0+incompatible
)
