// Copyright 2018, Oath Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package zms

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/yahoo/athenz/clients/go/zms"
)

const (
	serviceRolePrefix = "service.role"
)

var (
	client zms.ZMSClient
)

type Domain struct {
	Roles []*ServiceMapping
}

type ServiceMapping struct {
	Role   *zms.Role
	Policy *zms.Policy
}

// InitClient initializes the zms client
func InitClient(zmsURL, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client = zms.NewClient(zmsURL, transport)
	client.Timeout = 30 * time.Second
	return nil
}

// GetServiceMapping will create a domain object which contains the athenz mappings of a role and its corresponding
// members and policies
func GetServiceMapping(domainName string) (*Domain, error) {
	getMembers := true
	roles, err := client.GetRoles(zms.DomainName(domainName), &getMembers)
	if err != nil {
		return nil, err
	}

	domain := &Domain{}
	domain.Roles = make([]*ServiceMapping, 0)

	for _, role := range roles.List {
		roleName := strings.TrimPrefix(string(role.Name), domainName+":role.")
		if strings.HasPrefix(roleName, serviceRolePrefix) {
			policy, err := client.GetPolicy(zms.DomainName(domainName), zms.EntityName(roleName))
			if err != nil {
				return nil, err
			}

			sMapping := &ServiceMapping{
				Role:   role,
				Policy: policy,
			}
			domain.Roles = append(domain.Roles, sMapping)
		}
	}

	return domain, err
}
