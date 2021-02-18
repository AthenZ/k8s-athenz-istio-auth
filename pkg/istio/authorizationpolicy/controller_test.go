// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package authzpolicy

import (
	"github.com/ardielle/ardielle-go/rdl"
	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	adv1 "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	fakev1 "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned/fake"
	adInformer "github.com/yahoo/k8s-athenz-syncer/pkg/client/informers/externalversions/athenz/v1"
	fakeversionedclient "istio.io/client-go/pkg/clientset/versioned/fake"
	"istio.io/istio/pilot/pkg/config/memory"
	"istio.io/istio/pilot/pkg/model"
	"time"

	"istio.io/istio/pkg/config/schema/collection"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/istio/pkg/config/schema/resource"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	fcache "k8s.io/client-go/tools/cache/testing"
	"k8s.io/client-go/util/workqueue"
	"sync"
	"testing"
)

const (
	DomainName = "test.namespace"
	username   = "user.name"
	username1  = "user.*"
)

var (
	onboardedService = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "onboarded-service",
			Namespace: "test-namespace",
			Annotations: map[string]string{
				authzEnabledAnnotation: "true",
			},
			Labels: map[string]string{
				"app": "productpage",
			},
		},
	}
	notOnboardedService = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "not-onboarded-service",
			Namespace: "test-namespace",
		},
	}

	onboardedServiceName    = "onboarded-service.test-namespace.svc.cluster.local"
	existingServiceName     = "existing-service.test-namespace.svc.cluster.local"
	notOnboardedServiceName = "not-onboarded-service.test-namespace.svc.cluster.local"
	dnsSuffix               = "svc.cluster.local"

	ad1 = &adv1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DomainName,
			Namespace: "",
		},
		Spec: adv1.AthenzDomainSpec{
			SignedDomain: getFakeDomain(),
		},
	}
)

func init() {
	log.InitLogger("", "debug")
}

// fakeConfigStore a wrapper around a passed-in config store that does mutex lock on all store operations
type fakeConfigStore struct {
	model.ConfigStore
	m sync.Mutex
}

func (cs *fakeConfigStore) Get(typ resource.GroupVersionKind, name, namespace string) *model.Config {
	cs.m.Lock()
	defer cs.m.Unlock()
	return cs.ConfigStore.Get(typ, name, namespace)
}
func (cs *fakeConfigStore) List(typ resource.GroupVersionKind, namespace string) ([]model.Config, error) {
	cs.m.Lock()
	defer cs.m.Unlock()
	return cs.ConfigStore.List(typ, namespace)
}

func (cs *fakeConfigStore) Create(cfg model.Config) (string, error) {
	cs.m.Lock()
	defer cs.m.Unlock()
	return cs.ConfigStore.Create(cfg)
}

func (cs *fakeConfigStore) Update(cfg model.Config) (string, error) {
	cs.m.Lock()
	defer cs.m.Unlock()
	return cs.ConfigStore.Update(cfg)
}

func (cs *fakeConfigStore) Delete(typ resource.GroupVersionKind, name, namespace string) error {
	cs.m.Lock()
	defer cs.m.Unlock()
	return cs.ConfigStore.Delete(typ, name, namespace)
}

func newFakeController(services []*v1.Service, fake bool, stopCh <-chan struct{}) *Controller {
	c := &Controller{}
	configDescriptor := collection.SchemasFor(collections.IstioSecurityV1Beta1Authorizationpolicies)

	configStore := memory.Make(configDescriptor)
	if fake {
		configStore = &fakeConfigStore{
			configStore,
			sync.Mutex{},
		}
	}
	c.configStoreCache = memory.NewController(configStore)

	source := fcache.NewFakeControllerSource()
	for _, service := range services {
		source.Add(service)
	}
	fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
	go fakeIndexInformer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, fakeIndexInformer.HasSynced) {
		log.Panicln("timed out waiting for cache to sync")
	}
	c.serviceIndexInformer = fakeIndexInformer

	fakeClientset := fakev1.NewSimpleClientset()
	adIndexInformer := adInformer.NewAthenzDomainInformer(fakeClientset, 0, cache.Indexers{})
	adIndexInformer.GetStore().Add(ad1.DeepCopy())
	c.adIndexInformer = adIndexInformer

	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	c.queue = queue

	c.enableOriginJwtSubject = true

	return c
}

func TestNewController(t *testing.T) {
	configDescriptor := collection.SchemasFor(collections.IstioSecurityV1Beta1Authorizationpolicies)
	source := fcache.NewFakeControllerSource()
	fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
	athenzclientset := fakev1.NewSimpleClientset()
	fakeAthenzInformer := adInformer.NewAthenzDomainInformer(athenzclientset, 0, cache.Indexers{})
	istioClientSet := fakeversionedclient.NewSimpleClientset()
	apResyncInterval, err := time.ParseDuration("1h")
	assert.Equal(t, nil, err, "time parseDuration call should not fail with error")
	configStore := memory.Make(configDescriptor)
	configStoreCache := memory.NewController(configStore)
	c := NewController(configStoreCache, fakeIndexInformer, fakeAthenzInformer, istioClientSet, apResyncInterval, true, true)
	assert.Equal(t, fakeIndexInformer, c.serviceIndexInformer, "service index informer pointer should be equal")
	assert.Equal(t, configStoreCache, c.configStoreCache, "config configStoreCache cache pointer should be equal")
	assert.Equal(t, fakeAthenzInformer, c.adIndexInformer, "athenz index informer cache should be equal")
	assert.Equal(t, true, c.enableOriginJwtSubject, "enableOriginJwtSubject bool should be equal")
}

func getFakeDomain() zms.SignedDomain {
	allow := zms.ALLOW
	timestamp, err := rdl.TimestampParse("2019-07-22T20:29:10.305Z")
	if err != nil {
		panic(err)
	}

	return zms.SignedDomain{
		Domain: &zms.DomainData{
			Modified: timestamp,
			Name:     DomainName,
			Policies: &zms.SignedPolicies{
				Contents: &zms.DomainPolicies{
					Domain: DomainName,
					Policies: []*zms.Policy{
						{
							Assertions: []*zms.Assertion{
								{
									Role:     DomainName + ":role.admin",
									Resource: DomainName + ":*",
									Action:   "*",
									Effect:   &allow,
								},
								{
									Role:     DomainName + ":role.productpage-reader",
									Resource: DomainName + ":svc.productpage",
									Action:   "get",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     DomainName + ":policy.admin",
						},
					},
				},
				KeyId:     "col-env-1.1",
				Signature: "signature-policy",
			},
			Roles: []*zms.Role{
				{
					Members:  []zms.MemberName{username},
					Modified: &timestamp,
					Name:     DomainName + ":role.admin",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: username,
						},
					},
				},
				{
					Members:  []zms.MemberName{"productpage-reader"},
					Modified: &timestamp,
					Name:     DomainName + ":role.productpage-reader",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: username1,
						},
					},
				},
			},
			Services: []*zms.ServiceIdentity{},
			Entities: []*zms.Entity{},
		},
		KeyId:     "colo-env-1.1",
		Signature: "signature",
	}
}
