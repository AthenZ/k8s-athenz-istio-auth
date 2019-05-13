// Copyright 2018, Oath Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package zms

import (
	"crypto/tls"
	"log"
	"net/http"
	"strings"
	"sync"
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

type DomainsLister struct {
	latestTag string
	tagLock   *sync.Mutex
}

func NewDomainsLister() *DomainsLister {
	return &DomainsLister{
		latestTag: "",
		tagLock:   &sync.Mutex{},
	}
}

func GetSignedDomains(domain zms.DomainName, matchingTag string) (*zms.SignedDomains, string, error) {

	domains, eTag, err := client.GetSignedDomains(domain, "true", "", matchingTag)
	if err != nil {
		return nil, "", err
	}
	return domains, eTag, nil
}

func (dl *DomainsLister) GetChangedDomainsUntilNow() (*zms.SignedDomains, string, error) {
	dl.tagLock.Lock()
	defer dl.tagLock.Unlock()
	currentTag := dl.latestTag
	log.Printf("Setting current tag: %s", currentTag)

	changedDomains, newTag, err := GetSignedDomains("", currentTag)
	if err != nil {
		return nil, currentTag, err
	}

	if newTag != "" {
		dl.latestTag = newTag
	}

	return changedDomains, newTag, nil
}
