FROM alpine:latest

ARG git_url
ARG git_commit

LABEL git_url=$git_url git_commit=$git_commit

COPY ./k8s-athenz-istio-auth  /usr/bin/k8s-athenz-istio-auth

ENTRYPOINT [ "k8s-athenz-istio-auth" ]
