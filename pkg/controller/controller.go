// Copyright 2018, Oath Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package controller

import (
	"log"
	"strings"
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/yahoo/k8s-athenz-istio-auth/pkg/servicerole"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/servicerolebinding"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/util"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/zms"
)

type Controller struct {
	NamespaceIndexer cache.Indexer
	PollInterval     time.Duration
	DNSSuffix        string
}

// getNamespaces is responsible for retrieving the namespaces currently in the indexer
func (c *Controller) getNamespaces() *v1.NamespaceList {
	namespaceList := v1.NamespaceList{}
	nList := c.NamespaceIndexer.List()

	for _, n := range nList {
		namespace, ok := n.(*v1.Namespace)
		if !ok {
			log.Println("Namespace cast failed")
			continue
		}

		namespaceList.Items = append(namespaceList.Items, *namespace)
	}

	return &namespaceList
}

// sync will be ran at every poll interval and will be responsible for the following:
// 1. Get the current ServiceRoles and ServiceRoleBindings on the cluster.
// 2. Call every Athenz domain which has a corresponding namespace in the cluster.
// 3. For every role name prefixed with service.role, call its corresponding policy in order to get the actions defined.
// 4. Each role / policy combo will create or update the associated ServiceRole if there were any changes.
// 5. The members of the role will be used to create or update the ServiceRoleBindings if there were any changes.
// 6. Delete any ServiceRoles or ServiceRoleBindings which do not have a corresponding Athenz mapping.
func (c *Controller) sync() error {
	serviceRoleMap, err := servicerole.GetServiceRoleMap()
	if err != nil {
		return err
	}
	log.Println("serviceRoleMap:", serviceRoleMap)

	serviceRoleBindingMap, err := servicerolebinding.GetServiceRoleBindingMap()
	if err != nil {
		return err
	}
	log.Println("serviceRoleBindingMap:", serviceRoleBindingMap)

	domainMap := make(map[string]*zms.Domain)
	errDomainMap := make(map[string]bool)
	namespaceList := c.getNamespaces()
	for _, namespace := range namespaceList.Items {
		domainName := util.NamespaceToDomain(namespace.Name)
		domain, err := zms.GetServiceMapping(domainName)
		if err != nil {
			log.Println(err)
			errDomainMap[domainName] = true
			continue
		}
		domainMap[domainName] = domain
	}
	log.Println("domainMap:", domainMap)

	for domainName, domain := range domainMap {
		for _, role := range domain.Roles {
			// ex: service.role.domain.service
			namespace := util.DomainToNamespace(domainName)
			roleName := strings.TrimPrefix(string(role.Role.Name), domainName+":role.service.role.")
			serviceRole, exists := serviceRoleMap[roleName+"-"+namespace]
			if !exists {
				log.Println("Service role", roleName, "does not exist, creating...")
				err := servicerole.CreateServiceRole(namespace, c.DNSSuffix, roleName, role.Policy)
				if err != nil {
					log.Println("Error creating service role:", err)
					continue
				}
				log.Println("Created service role", roleName, "in namespace", namespace)
				continue
			}

			log.Println("Service role", roleName, "already exists, updating...")
			serviceRole.Processed = true
			updated, err := servicerole.UpdateServiceRole(serviceRole.ServiceRole, c.DNSSuffix, roleName, role.Policy)
			if err != nil {
				log.Println("Error updating service role:", err)
				continue
			}
			if updated {
				log.Println("Updated service role", roleName, "in namespace", namespace)
			} else {
				log.Println("No difference found for service role", roleName, "in namespace", namespace,
					"not updating")
			}

			if len(role.Role.Members) == 0 {
				log.Println("Role", roleName, "has no members, skipping service role binding creation")
				continue
			}

			serviceRoleBinding, exists := serviceRoleBindingMap[roleName+"-"+namespace]
			if !exists {
				err = servicerolebinding.CreateServiceRoleBinding(namespace, roleName, role.Role.Members)
				if err != nil {
					log.Println("Error creating service role binding:", err)
					continue
				}
				log.Println("Created service role binding", roleName, "in namespace", namespace)
				continue
			}
			log.Println("Service role binding", roleName, "already exists, updating...")
			serviceRoleBinding.Processed = true
			updated, err = servicerolebinding.UpdateServiceRoleBinding(serviceRoleBinding.ServiceRoleBinding,
				namespace, roleName, role.Role.Members)
			if err != nil {
				log.Println("Error updating service role binding:", err)
				continue
			}

			if updated {
				log.Println("Updated service role binding", roleName, "in namespace", namespace)
			} else {
				log.Println("No difference found for service role binding", roleName, "in namespace", namespace,
					"not updating")
			}
		}
	}

	for _, serviceRole := range serviceRoleMap {
		domain := util.NamespaceToDomain(serviceRole.ServiceRole.Namespace)
		if _, exists := errDomainMap[domain]; exists {
			log.Println("Skipping delete for service role", serviceRole.ServiceRole.Name, "in namespace",
				serviceRole.ServiceRole.Namespace, "due to Athens error")
			continue
		}

		if !serviceRole.Processed {
			err := servicerole.DeleteServiceRole(serviceRole.ServiceRole.Name, serviceRole.ServiceRole.Namespace)
			if err != nil {
				log.Println("Error deleting service role:", err)
				continue
			}
			log.Println("Deleted service role", serviceRole.ServiceRole.Name, "in namespace",
				serviceRole.ServiceRole.Namespace)
		}
	}

	for _, serviceRoleBinding := range serviceRoleBindingMap {
		domain := util.NamespaceToDomain(serviceRoleBinding.ServiceRoleBinding.Namespace)
		if _, exists := errDomainMap[domain]; exists {
			log.Println("Skipping delete for service role binding", serviceRoleBinding.ServiceRoleBinding.Name,
				"in namespace", serviceRoleBinding.ServiceRoleBinding.Namespace, "due to Athens error")
			continue
		}

		if !serviceRoleBinding.Processed {
			err := servicerolebinding.DeleteServiceRoleBinding(serviceRoleBinding.ServiceRoleBinding.Name,
				serviceRoleBinding.ServiceRoleBinding.Namespace)
			if err != nil {
				log.Println("Error deleting service role binding:", err)
				continue
			}
			log.Println("Deleted service role binding", serviceRoleBinding.ServiceRoleBinding.Name, "in namespace",
				serviceRoleBinding.ServiceRoleBinding.Namespace)
		}
	}

	return nil
}

// Run starts the main controller loop running sync at every poll interval
func (c *Controller) Run() {
	for {
		err := c.sync()
		if err != nil {
			log.Println("Error running sync:", err)
		}
		log.Println("Sleeping for", c.PollInterval)
		time.Sleep(c.PollInterval)
	}
}
