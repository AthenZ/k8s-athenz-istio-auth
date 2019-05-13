// Copyright 2018, Oath Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in github.com/yahoo/k8s-athenz-istio-auth
// for terms.
package util

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"hash"
	"hash/fnv"
	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/dynamic"
	"log"
	"strings"
)

// DomainToNamespace will convert an athenz domain to a kubernetes namespace. Dots are converted to dashes
// and dashes are converted to double dashes.
// ex: k8s.athenz-istio-auth -> k8s-athenz--istio--auth
func DomainToNamespace(domain string) (namespace string) {
	dubdash := strings.Replace(domain, "-", "--", -1)
	return strings.Replace(dubdash, ".", "-", -1)
}

// NamespaceToDomain will convert the kubernetes namespace to an athenz domain. Dashes are converted to dots and
// double dashes are converted to single dashes.
// ex: k8s-athenz--istio--auth -> k8s.athenz-istio-auth
func NamespaceToDomain(ns string) (domain string) {
	dotted := strings.Replace(ns, "-", ".", -1)
	return strings.Replace(dotted, "..", "-", -1)
}

func DeepHashObject(hasher hash.Hash, objectToWrite interface{}) {
	hasher.Reset()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(hasher, "%#v", objectToWrite)
}

func ComputeHash(obj model.Config) string {
	hasher := fnv.New32a()
	DeepHashObject(hasher, obj.Spec)
	return rand.SafeEncodeString(fmt.Sprint(hasher.Sum32()))
}

func GetPatch(domain string, tag string, hash string) (types.PatchType, []byte) {
	return types.MergePatchType, []byte(fmt.Sprintf(`
		{
			"metadata": {
				"annotations": { 
					"authz.athenz.io/controller": "true",
					"authz.athenz.io/domain": %q,
					"authz.athenz.io/e-tag": %q,
					"authz.athenz.io/spec-hash": %q
				}
			}
		}`, domain, tag, hash))
}

func AnnotateModifiedResource(client dynamic.Interface, obj model.Config, domain string, tag string) error {

	patchType, patch := GetPatch(domain, tag, ComputeHash(obj))
	log.Printf("Patch bytes: %s", string(patch))

	sch, ok := model.IstioConfigTypes.GetByType(obj.Type)
	if !ok {
		return fmt.Errorf("error determining the schema for the Istio resource: %s/%s/%s", crd.ResourceName(obj.Type), obj.Namespace, obj.Name)
	}
	resource, ns, name := schema.GroupVersionResource{
		Group:    obj.Group,
		Version:  obj.Version,
		Resource: crd.ResourceName(sch.Plural),
	}, obj.Namespace, obj.Name

	res, err := client.Resource(resource).Namespace(ns).Patch(name, patchType, patch)
	if err != nil {
		return fmt.Errorf("error patching the servicerolebinding: %s", err.Error())
	}
	log.Printf("Patched resource: %+v", res)
	return nil
}
