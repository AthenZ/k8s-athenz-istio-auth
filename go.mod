module github.com/yahoo/k8s-athenz-istio-auth

go 1.12

require (
	github.com/ardielle/ardielle-go v1.5.2
	github.com/docker/go-units v0.4.0 // indirect
	github.com/ghodss/yaml v1.0.0
	github.com/gogo/protobuf v1.3.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	github.com/yahoo/athenz v1.8.40
	github.com/yahoo/k8s-athenz-syncer v0.1.6
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	istio.io/api v0.0.0-20200513175333-ae3da0d240e3
	istio.io/client-go v0.0.0-20200513180646-f8d9d8ff84e6
	istio.io/istio v0.0.0-20200708165503-80f49905d910
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
