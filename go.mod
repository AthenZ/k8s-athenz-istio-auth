module github.com/yahoo/k8s-athenz-istio-auth

go 1.12

require (
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/SAP/go-hdb v0.14.1 // indirect
	github.com/SermoDigital/jose v0.9.1 // indirect
	github.com/ardielle/ardielle-go v1.5.2
	github.com/armon/go-metrics v0.0.0-20190430140413-ec5e00d3c878 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/bitly/go-hostpool v0.0.0-20171023180738-a3a6125de932 // indirect
	github.com/containerd/continuity v0.0.0-20190426062206-aaeac12a7ffc // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/denisenkom/go-mssqldb v0.0.0-20190423183735-731ef375ac02 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/duosecurity/duo_api_golang v0.0.0-20190308151101-6c680f768e74 // indirect
	github.com/elazarl/go-bindata-assetfs v1.0.0 // indirect
	github.com/ghodss/yaml v1.0.0
	github.com/go-sql-driver/mysql v1.4.1 // indirect
	github.com/gocql/gocql v0.0.0-20190423091413-b99afaf3b163 // indirect
	github.com/gogo/protobuf v1.3.1
	github.com/gotestyourself/gotestyourself v2.2.0+incompatible // indirect
	github.com/hashicorp/go-hclog v0.9.0 // indirect
	github.com/hashicorp/go-memdb v1.0.1 // indirect
	github.com/hashicorp/vault v0.10.0 // indirect
	github.com/jefferai/jsonx v1.0.0 // indirect
	github.com/keybase/go-crypto v0.0.0-20190416182011-b785b22cc757 // indirect
	github.com/lib/pq v1.2.0 // indirect
	github.com/opencontainers/runc v0.1.1 // indirect
	github.com/ory/dockertest v3.3.4+incompatible // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/sethgrid/pester v0.0.0-20180227223404-ed9870dad317 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	github.com/yahoo/athenz v1.8.40
	github.com/yahoo/k8s-athenz-syncer v0.1.6
	gopkg.in/mgo.v2 v2.0.0-20180705113604-9856a29383ce // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/ory-am/dockertest.v3 v3.3.4 // indirect
	istio.io/api v0.0.0-20200513175333-ae3da0d240e3
	istio.io/client-go v0.0.0-20200513180646-f8d9d8ff84e6
	istio.io/istio v0.0.0-20200708165503-80f49905d910
	istio.io/operator v0.0.0-20200213054244-508c83195d0b // indirect
	istio.io/pkg v0.0.0-20200324191837-25e6bb9cf135
	k8s.io/api v0.18.0
	k8s.io/apimachinery v0.18.0
	k8s.io/client-go v15.0.0+incompatible
)

// Kubernetes makes it challenging to depend on their libraries. To get around this, we need to force
// the sha to use. All of these are pinned to the tag "kubernetes-1.17.14"
replace k8s.io/api => k8s.io/api v0.17.14

replace k8s.io/apimachinery => k8s.io/apimachinery v0.17.14

replace k8s.io/client-go => k8s.io/client-go v0.17.14

replace k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.17.14

replace k8s.io/kube-proxy => k8s.io/kube-proxy v0.17.14
