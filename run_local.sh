#!/bin/bash

apt-get update
apt-get upgrade
apt install curl git make rsync -y
curl -OL https://go.dev/dl/go1.16.linux-amd64.tar.gz
tar -C /usr/local -xvf go1.16.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
source ~/.profile
mkdir -p /sd/workspace/src/github.com/AthenZ/k8s-athenz-istio-auth
cp -r /go/src/github.com/AthenZ/k8s-athenz-istio-auth/* /sd/workspace/src/github.com/AthenZ/k8s-athenz-istio-auth
mkdir -p /sd/workspace/src/k8s.io
pushd /sd/workspace/src/k8s.io
git clone https://github.com/kubernetes/kubernetes.git --branch release-1.17 --depth 1
pushd /sd/workspace/src/k8s.io/kubernetes
GO111MODULE=auto make WHAT=cmd/kube-apiserver
pushd $GOPATH/src/k8s.io/kubernetes/vendor/k8s.io/kube-openapi
go mod init kube-openapi
go mod tidy
sleep 10000000