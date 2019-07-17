// Copyright 2019, Oath Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
// Code generated by informer-gen. DO NOT EDIT.

package v1

import (
	time "time"

	athenzv1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/apis/athenz/v1"
	versioned "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/clientset/versioned"
	internalinterfaces "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/informers/externalversions/internalinterfaces"
	v1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/listers/athenz/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// AthenzDomainInformer provides access to a shared informer and lister for
// AthenzDomains.
type AthenzDomainInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.AthenzDomainLister
}

type athenzDomainInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewAthenzDomainInformer constructs a new informer for AthenzDomain type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewAthenzDomainInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredAthenzDomainInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredAthenzDomainInformer constructs a new informer for AthenzDomain type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredAthenzDomainInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AthenzV1().AthenzDomains().List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AthenzV1().AthenzDomains().Watch(options)
			},
		},
		&athenzv1.AthenzDomain{},
		resyncPeriod,
		indexers,
	)
}

func (f *athenzDomainInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredAthenzDomainInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *athenzDomainInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&athenzv1.AthenzDomain{}, f.defaultInformer)
}

func (f *athenzDomainInformer) Lister() v1.AthenzDomainLister {
	return v1.NewAthenzDomainLister(f.Informer().GetIndexer())
}
