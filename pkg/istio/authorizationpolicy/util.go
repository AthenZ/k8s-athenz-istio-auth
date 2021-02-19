// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package authzpolicy

import (
	"fmt"
	"strings"
)

// ServiceEnabled - service and namespace combination that enabled authz policy
type ServiceEnabled struct {
	service   string
	namespace string
}

type ComponentEnabled struct {
	serviceList   []ServiceEnabled
	namespaceList []string
	cluster       bool
}

func ParseComponentsEnabledAuthzPolicy(componentsList string) (*ComponentEnabled, error) {
	componentEnabledObj := ComponentEnabled{}
	if componentsList == "" {
		return &componentEnabledObj, nil
	}
	serviceEnabledList := []ServiceEnabled{}
	namespaceEnabledList := []string{}
	serviceNamespaceComboList := strings.Split(componentsList, ",")
	if len(serviceNamespaceComboList) == 1 && serviceNamespaceComboList[0] == "*" {
		componentEnabledObj.cluster = true
		return &componentEnabledObj, nil
	}
	for _, item := range serviceNamespaceComboList {
		if item != "" {
			serviceWithNS := strings.Split(item, "/")
			if len(serviceWithNS) != 2 {
				return nil, fmt.Errorf("Service item %s from command line arg components-enabled-authzpolicy is in incorrect format", item)
			} else {
				if serviceWithNS[1] == "*" {
					namespaceEnabledList = append(namespaceEnabledList, serviceWithNS[0])
				} else {
					serviceObj := ServiceEnabled{
						service:   serviceWithNS[1],
						namespace: serviceWithNS[0],
					}
					serviceEnabledList = append(serviceEnabledList, serviceObj)
				}
			}
		}
	}
	componentEnabledObj.serviceList = serviceEnabledList
	componentEnabledObj.namespaceList = namespaceEnabledList
	return &componentEnabledObj, nil
}

func (c *ComponentEnabled) containsService(service string, ns string) bool {
	for _, item := range c.serviceList {
		if item.service == service && item.namespace == ns {
			return true
		}
	}
	return false
}

func (c *ComponentEnabled) containsNamespace(ns string) bool {
	for _, item := range c.namespaceList {
		if item == ns {
			return true
		}
	}
	return false
}

func (c *ComponentEnabled) IsEnabled(serviceName string, serviceNamespace string) bool {
	if c.cluster {
		return true
	}
	if c.containsNamespace(serviceNamespace) {
		return true
	}
	if c.containsService(serviceName, serviceNamespace) {
		return true
	}
	return false
}
