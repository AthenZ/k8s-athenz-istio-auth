module github.com/yahoo/k8s-athenz-istio-auth/test/integration

go 1.12

require (
    github.com/ardielle/ardielle-go v1.5.2
    github.com/aws/aws-sdk-go v1.23.2 // indirect
    github.com/beorn7/perks v1.0.1 // indirect
    github.com/coreos/bbolt v1.3.3 // indirect
    github.com/coreos/etcd v3.3.13+incompatible
    github.com/coreos/go-oidc v2.0.0+incompatible // indirect
    github.com/coreos/go-semver v0.3.0 // indirect
    github.com/coreos/go-systemd v0.0.0-20190719114852-fd7a80b32e1f // indirect
    github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
    github.com/d2g/dhcp4client v1.0.0 // indirect
    github.com/docker/distribution v2.7.1+incompatible // indirect
    github.com/docker/docker v1.13.1 // indirect
    github.com/docker/go-connections v0.4.0 // indirect
    github.com/docker/spdystream v0.0.0-20181023171402-6480d4af844c // indirect
    github.com/elazarl/go-bindata-assetfs v1.0.0 // indirect
    github.com/emicklei/go-restful-swagger12 v0.0.0-20170926063155-7524189396c6 // indirect
    github.com/evanphx/json-patch v4.5.0+incompatible // indirect
    github.com/fatih/camelcase v1.0.0 // indirect
    github.com/go-kit/kit v0.8.0 // indirect
    github.com/go-logfmt/logfmt v0.4.0 // indirect
    github.com/go-openapi/strfmt v0.19.2 // indirect
    github.com/go-openapi/validate v0.19.2 // indirect
    github.com/gogo/protobuf v1.2.2-0.20190723190241-65acae22fc9d // indirect
    github.com/gorilla/websocket v1.4.0 // indirect
    github.com/grpc-ecosystem/go-grpc-middleware v1.0.0 // indirect
    github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
    github.com/grpc-ecosystem/grpc-gateway v1.9.5 // indirect
    github.com/jonboulle/clockwork v0.1.0 // indirect
    github.com/julienschmidt/httprouter v1.2.0 // indirect
    github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
    github.com/mwitkow/go-conntrack v0.0.0-20161129095857-cc309e4a2223 // indirect
    github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
    github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
    github.com/prometheus/client_model v0.0.0-20190129233127-fd36f4220a90 // indirect
    github.com/prometheus/procfs v0.0.3 // indirect
    github.com/robfig/cron v1.2.0 // indirect
    github.com/satori/go.uuid v1.2.0 // indirect
    github.com/soheilhy/cmux v0.1.4 // indirect
    github.com/spf13/cobra v0.0.5 // indirect
    github.com/tmc/grpc-websocket-proxy v0.0.0-20190109142713-0ad062ec5ee5 // indirect
    github.com/vmware/govmomi v0.21.0 // indirect
    github.com/xanzy/go-cloudstack v2.4.1+incompatible // indirect
    github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2 // indirect
    github.com/yahoo/athenz v1.8.23
    github.com/yahoo/k8s-athenz-istio-auth v0.1.0
    github.com/yahoo/k8s-athenz-syncer v0.1.0
    go.etcd.io/etcd v3.3.13+incompatible // indirect
    golang.org/x/sys v0.0.0-20190801041406-cbf593c0f2f3 // indirect
    google.golang.org/api v0.8.0 // indirect
    gopkg.in/alecthomas/kingpin.v2 v2.2.6 // indirect
    gopkg.in/gcfg.v1 v1.2.3 // indirect
    gopkg.in/square/go-jose.v2 v2.3.1 // indirect
    gopkg.in/warnings.v0 v0.1.2 // indirect
    istio.io/api v0.0.0-20190416154520-4a9a2a12a700
    istio.io/istio v0.0.0-20190515005051-eec7a74473de
    k8s.io/apiextensions-apiserver v0.0.0-20190223021643-57c81b676ab1
    k8s.io/apimachinery v0.0.0-20190223001710-c182ff3b9841
    k8s.io/apiserver v0.0.0-20190321070451-3f1a34edf9b8 // indirect
    k8s.io/client-go v8.0.0+incompatible
    k8s.io/kube-aggregator v0.0.0-20190223015803-f706565beac0 // indirect
    k8s.io/kubernetes v0.0.0-00010101000000-000000000000
)

replace (
    k8s.io/api => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/api
    k8s.io/apimachinery => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/apimachinery
    k8s.io/apiserver => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/apiserver
    k8s.io/client-go => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/client-go
    k8s.io/kube-aggregator => /home/travis/gopath/src/k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator
    k8s.io/kube-openapi => /home/travis/gopath/src/k8s.io/kubernetes/vendor/k8s.io/kube-openapi
    k8s.io/kubernetes => /home/travis/gopath/src/k8s.io/kubernetes
)
