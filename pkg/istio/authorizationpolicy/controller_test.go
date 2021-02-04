// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package authzpolicy

import (
	"fmt"
	"github.com/ardielle/ardielle-go/rdl"
	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	m "github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	rbacv1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/v1"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	adv1 "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	fakev1 "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned/fake"
	adInformer "github.com/yahoo/k8s-athenz-syncer/pkg/client/informers/externalversions/athenz/v1"
	"istio.io/api/security/v1beta1"
	workloadv1beta1 "istio.io/api/type/v1beta1"
	authz "istio.io/client-go/pkg/apis/security/v1beta1"
	fakeversionedclient "istio.io/client-go/pkg/clientset/versioned/fake"
	"istio.io/istio/pilot/pkg/config/memory"
	"istio.io/istio/pilot/pkg/model"
	"time"

	"istio.io/istio/pkg/config/schema/collection"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/istio/pkg/config/schema/resource"
	v1 "k8s.io/api/core/v1"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	fcache "k8s.io/client-go/tools/cache/testing"
	"k8s.io/client-go/util/workqueue"
	"sync"
	"testing"
)

const (
	DomainName = "test.namespace"
	DomainName1 = "test1.namespace"
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
				"svc": "productpage",
			},
		},
	}
	notOnboardedService = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "not-onboarded-service",
			Namespace: "test1-namespace",
		},
	}

	onboardedAthenzDomain = &adv1.AthenzDomain{
		ObjectMeta: k8sv1.ObjectMeta{
			Name:      DomainName,
			Namespace: "",
		},
		Spec: adv1.AthenzDomainSpec{
			SignedDomain: getFakeOnboardedDomain(),
		},
	}
	notOnboardedAthenzDomain = &adv1.AthenzDomain{
		ObjectMeta: k8sv1.ObjectMeta{
			Name:      DomainName1,
			Namespace: "",
		},
		Spec: adv1.AthenzDomainSpec{
			SignedDomain: getFakeNotOnboardedDomain(),
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

func TestNewController(t *testing.T) {
	configDescriptor := collection.SchemasFor(collections.IstioSecurityV1Beta1Authorizationpolicies)
	source := fcache.NewFakeControllerSource()
	fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
	athenzclientset := fakev1.NewSimpleClientset()
	fakeAthenzInformer := adInformer.NewAthenzDomainInformer(athenzclientset, 0, cache.Indexers{})
	istioClientSet := fakeversionedclient.NewSimpleClientset()
	apResyncInterval, _ := time.ParseDuration("1h")
	configStore := memory.Make(configDescriptor)
	configStoreCache := memory.NewController(configStore)
	c := NewController(configStoreCache, fakeIndexInformer, fakeAthenzInformer, istioClientSet, apResyncInterval, true, true)
	assert.Equal(t, fakeIndexInformer, c.serviceIndexInformer, "service index informer pointer should be equal")
	assert.Equal(t, configStoreCache, c.configStoreCache, "config configStoreCache cache pointer should be equal")
	assert.Equal(t, fakeAthenzInformer, c.adIndexInformer, "athenz index informer cache should be equal")
	assert.Equal(t, true, c.enableOriginJwtSubject, "enableOriginJwtSubject bool should be equal")
}

func newFakeController(athenzDomain *adv1.AthenzDomain, fake bool, stopCh <-chan struct{}) *Controller {
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
	source.Add(onboardedService)
	go c.configStoreCache.Run(stopCh)

	fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
	go fakeIndexInformer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, fakeIndexInformer.HasSynced) {
		log.Panicln("timed out waiting for cache to sync")
	}
	c.serviceIndexInformer = fakeIndexInformer

	fakeClientset := fakev1.NewSimpleClientset()
	adIndexInformer := adInformer.NewAthenzDomainInformer(fakeClientset, 0, cache.Indexers{})
	adIndexInformer.GetStore().Add(athenzDomain.DeepCopy())
	go adIndexInformer.Run(stopCh)
	c.adIndexInformer = adIndexInformer

	authzpolicyIndexInformer := cache.NewSharedIndexInformer(source, &authz.AuthorizationPolicy{}, 0, nil)
	go authzpolicyIndexInformer.Run(stopCh)
	c.authzpolicyIndexInformer = authzpolicyIndexInformer

	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	c.queue = queue

	c.enableOriginJwtSubject = true
	c.rbacProvider = rbacv1.NewProvider(c.enableOriginJwtSubject)
	return c
}

func TestSyncService(t *testing.T) {
	tests := []struct {
		name                       string
		inputService               *v1.Service
		inputAthenzDomain          *adv1.AthenzDomain
		fake                       bool
		existingAuthzPolicy        model.Config
		expectedAuthzPolicy        model.Config
		item                       Item
	}{
		{
			name:                "generate Authorization Policy spec for service with annotation set",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			fake:                true,
			existingAuthzPolicy: model.Config{},
			expectedAuthzPolicy: getExpectedCR(),
			item:                Item{Operation: model.EventAdd, Resource: onboardedService},
		},
		{
			name:                "not generate Authorization Policy spec for service without annotation set",
			inputService:        notOnboardedService,
			inputAthenzDomain:   notOnboardedAthenzDomain,
			fake:                true,
			existingAuthzPolicy: model.Config{},
			expectedAuthzPolicy: model.Config{},
			item:                Item{Operation: model.EventAdd, Resource: notOnboardedService},
		},
		{
			name:                "delete Authorization Policy spec when there is deletion event of service with annotation set",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			fake:                true,
			existingAuthzPolicy: getOldCR(),
			expectedAuthzPolicy: getExpectedCR(),
			item:                Item{Operation: model.EventDelete, Resource: onboardedService},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(tt.inputAthenzDomain, tt.fake, make(chan struct{}))
			switch action := tt.item.Operation; action {
			case model.EventAdd:
				// Add a sleep for processing controller to work on the queue
				time.Sleep(100 * time.Millisecond)
				err := c.sync(tt.item)
				if err != nil {
					log.Panicln("controller has sync err: ", err)
				}

				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.inputService.Name, tt.inputService.Namespace)
				if genAuthzPolicy != nil {
					assert.Equal(t, tt.expectedAuthzPolicy.Spec, genAuthzPolicy.Spec, "created authorization policy spec should be equal")
					// except creation timestamp and revision, configMeta field should be same
					assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Namespace, genAuthzPolicy.ConfigMeta.Namespace, "namespace should be equal")
					assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Type, genAuthzPolicy.ConfigMeta.Type, "resource type should be equal")
					assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Name, genAuthzPolicy.ConfigMeta.Name, "resource name should be equal")
					assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Group, genAuthzPolicy.ConfigMeta.Group, "apiGroup should be equal")
					assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Version, genAuthzPolicy.ConfigMeta.Version, "apiVersion should be equal")
				} else {
					// generated spec returns nil, compare with empty config
					assert.Equal(t, tt.expectedAuthzPolicy, model.Config{}, "generated authorization policy should be nil")
				}
			case model.EventDelete:
				c.configStoreCache.Create(tt.expectedAuthzPolicy)
				time.Sleep(100 * time.Millisecond)
				err := c.sync(tt.item)
				if err != nil {
					log.Panicln("controller has sync err: ", err)
				}

				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.inputService.Name, tt.inputService.Namespace)
				if genAuthzPolicy != nil {
					assert.Errorf(t, fmt.Errorf("authorization policy spec still exists in the cache"), "authorization policy should be deleted after delete action")
				}
			case model.EventUpdate:
				_, err := c.configStoreCache.Create(tt.expectedAuthzPolicy)
				if err != nil {
					log.Panicln("controller not able to create authz policy spec: ", err)
				}
				time.Sleep(100 * time.Millisecond)
				err = c.sync(tt.item)
				if err != nil {
					log.Panicln("controller has sync err: ", err)
				}

				// Updated Spec should be equal
				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.inputService.Name, tt.inputService.Namespace)
				if genAuthzPolicy != nil {
					assert.Equal(t, tt.expectedAuthzPolicy.Spec, genAuthzPolicy.Spec, "created authorization policy spec should be equal")
					// except creation timestamp and revision, configMeta field should be same
					assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Namespace, genAuthzPolicy.ConfigMeta.Namespace, "namespace should be equal")
					assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Type, genAuthzPolicy.ConfigMeta.Type, "resource type should be equal")
					assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Name, genAuthzPolicy.ConfigMeta.Name, "resource name should be equal")
					assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Group, genAuthzPolicy.ConfigMeta.Group, "apiGroup should be equal")
					assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Version, genAuthzPolicy.ConfigMeta.Version, "apiVersion should be equal")
				} else {
					// generated spec returns nil, compare with empty config
					assert.Equal(t, tt.expectedAuthzPolicy, model.Config{}, "generated authorization policy should be nil")
				}
			}
		})
	}
}

func TestSyncAthenzDomain(t *testing.T) {
	tests := []struct {
		name                       string
		expectedAuthzPolicy        model.Config
		fake                       bool
		item                       Item
	}{
		{
			name:                  "update existing authz policy spec when there is athenz domain crd update",
			expectedAuthzPolicy:   getExpectedCR(),
			fake:                  true,
			item:                  Item{Operation: model.EventUpdate, Resource: onboardedAthenzDomain},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(&adv1.AthenzDomain{}, tt.fake, make(chan struct{}))
			switch action := tt.item.Operation; action {
			case model.EventUpdate:
				_, err := c.configStoreCache.Create(getOldCR())
				if err != nil {
					log.Panicln("controller not able to create authz policy spec: ", err)
				}

				time.Sleep(100 * time.Millisecond)
				err = c.sync(tt.item)
				if err != nil {
					log.Panicln("controller has sync err: ", err)
				}

				// Updated Spec should be equal
				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.expectedAuthzPolicy.Name, tt.expectedAuthzPolicy.Namespace)
				assert.Equal(t, tt.expectedAuthzPolicy.Spec, genAuthzPolicy.Spec, "created authorization policy spec should be equal")
				// except creation timestamp and revision, configMeta field should be same
				assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Namespace, genAuthzPolicy.ConfigMeta.Namespace, "namespace should be equal")
				assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Type, genAuthzPolicy.ConfigMeta.Type, "resource type should be equal")
				assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Name, genAuthzPolicy.ConfigMeta.Name, "resource name should be equal")
				assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Group, genAuthzPolicy.ConfigMeta.Group, "apiGroup should be equal")
				assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Version, genAuthzPolicy.ConfigMeta.Version, "apiVersion should be equal")
			}
		})
	}
}

func TestSyncAuthzPolicy(t *testing.T) {
	tests := []struct {
		name                       string
		fake                       bool
		inputAthenzDomain          *adv1.AthenzDomain
		item                       Item
		expectedAuthzPolicy        model.Config
	}{
		{
			name:                  "when there is manual modification of authz policy resource, controller will revert back to spec matched with athenz domain crd",
			fake:                  true,
			inputAthenzDomain:     onboardedAthenzDomain,
			item:                  Item{Operation: model.EventUpdate, Resource: getModifiedAuthzPolicy()},
			expectedAuthzPolicy:   getExpectedCR(),
		},
		{
			name:                  "when there is deletion of authz policy resource, controller will recreate the authz policy",
			fake:                  true,
			inputAthenzDomain:     onboardedAthenzDomain,
			item:                  Item{Operation: model.EventDelete, Resource: getModifiedAuthzPolicy()},
			expectedAuthzPolicy:   getExpectedCR(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(tt.inputAthenzDomain, tt.fake, make(chan struct{}))
			switch action := tt.item.Operation; action {
			case model.EventUpdate:
				resourceVersion, err := c.configStoreCache.Create(getOldCR())
				if err != nil {
					log.Panicln("controller not able to create authz policy spec: ", err)
				}

				time.Sleep(100 * time.Millisecond)
				(tt.item.Resource).(*authz.AuthorizationPolicy).ObjectMeta.ResourceVersion = resourceVersion
				err = c.sync(tt.item)
				if err != nil {
					log.Panicln("controller has sync err: ", err)
				}
				// Updated Spec should be equal
				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.expectedAuthzPolicy.Name, tt.expectedAuthzPolicy.Namespace)
				assert.Equal(t, tt.expectedAuthzPolicy.Spec, genAuthzPolicy.Spec, "created authorization policy spec should be equal")
				// except creation timestamp and revision, configMeta field should be same
				assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Namespace, genAuthzPolicy.ConfigMeta.Namespace, "namespace should be equal")
				assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Type, genAuthzPolicy.ConfigMeta.Type, "resource type should be equal")
				assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Name, genAuthzPolicy.ConfigMeta.Name, "resource name should be equal")
				assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Group, genAuthzPolicy.ConfigMeta.Group, "apiGroup should be equal")
				assert.Equal(t, tt.expectedAuthzPolicy.ConfigMeta.Version, genAuthzPolicy.ConfigMeta.Version, "apiVersion should be equal")
			case model.EventDelete:
				err := c.sync(tt.item)
				if err != nil {
					log.Panicln("controller has sync err: ", err)
				}
			}

		})
	}
}

func TestConvertAthenzModelIntoIstioAuthzPolicy(t *testing.T) {
	tests := []struct {
		name                       string
		inputService               *v1.Service
		fake                       bool
		athenzDomain               *adv1.AthenzDomain
		expectedCR                 model.Config
	}{
		{
			name:                  "generate Authorization Policy spec for service with annotation set",
			inputService:          onboardedService,
			fake:                  true,
			athenzDomain:          onboardedAthenzDomain,
			expectedCR:            getExpectedCR(),
		},
	}

	for _, tt := range tests {
		configDescriptor := collection.SchemasFor(collections.IstioSecurityV1Beta1Authorizationpolicies)
		source := fcache.NewFakeControllerSource()
		source.Add(tt.inputService)

		fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
		athenzclientset := fakev1.NewSimpleClientset()
		fakeAthenzInformer := adInformer.NewAthenzDomainInformer(athenzclientset, 0, cache.Indexers{})
		fakeAthenzInformer.GetStore().Add(tt.athenzDomain.DeepCopy())

		configStore := memory.Make(configDescriptor)
		if tt.fake {
			configStore = &fakeConfigStore{
				configStore,
				sync.Mutex{},
			}
		}
		istioClientSet := fakeversionedclient.NewSimpleClientset()
		apResyncInterval, _ := time.ParseDuration("1h")
		configStoreCache := memory.NewController(configStore)
		c := NewController(configStoreCache, fakeIndexInformer, fakeAthenzInformer, istioClientSet, apResyncInterval,true, false)

		signedDomain := tt.athenzDomain.Spec.Domain
		labels := tt.inputService.GetLabels()
		domainRBAC := m.ConvertAthenzPoliciesIntoRbacModel(signedDomain, &c.adIndexInformer)
		convertedCR := c.rbacProvider.ConvertAthenzModelIntoIstioAuthzPolicy(domainRBAC, tt.inputService.Namespace, tt.inputService.Name, labels["svc"])

		assert.Equal(t, tt.expectedCR, convertedCR, "converted authz policy should be equal")
	}
}

func getExpectedCR() model.Config{
	var out model.Config
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	createTimestamp, _ := time.Parse("", "12/8/2015 12:00:00")
	out.ConfigMeta = model.ConfigMeta{
		Type:      schema.Resource().Kind(),
		Group:     schema.Resource().Group(),
		Version:   schema.Resource().Version(),
		Namespace: "test-namespace",
		Name:      "onboarded-service",
		CreationTimestamp: createTimestamp,
	}
	out.Spec = &v1beta1.AuthorizationPolicy{
		Selector: &workloadv1beta1.WorkloadSelector{
			MatchLabels: map[string]string{"svc": "productpage"},
		},
		Rules: []*v1beta1.Rule{
			{
				To: []*v1beta1.Rule_To{
					{
						Operation: &v1beta1.Operation{
							Methods: []string{
								"GET",
							},
						},
					},
				},
			},
			{
				From: []*v1beta1.Rule_From{
					{
						Source: &v1beta1.Source{
							Principals: []string{
								"*",
								"test.namespace/ra/test.namespace:role.productpage-reader",
							},
						},
					},
					{
						Source: &v1beta1.Source{
							RequestPrincipals: []string{
								"*",
							},
						},
					},
				},
			},
		},
	}
	return out
}

func getFakeOnboardedDomain() zms.SignedDomain {
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

func getFakeNotOnboardedDomain() zms.SignedDomain {
	allow := zms.ALLOW
	timestamp, err := rdl.TimestampParse("2001-01-25T03:32:15.245Z")
	if err != nil {
		panic(err)
	}

	return zms.SignedDomain{
		Domain: &zms.DomainData{
			Modified: timestamp,
			Name:     DomainName1,
			Policies: &zms.SignedPolicies{
				Contents: &zms.DomainPolicies{
					Domain: DomainName1,
					Policies: []*zms.Policy{
						{
							Assertions: []*zms.Assertion{
								{
									Role:     DomainName1 + ":role.admin",
									Resource: DomainName1 + ":*",
									Action:   "*",
									Effect:   &allow,
								},
								{
									Role:     DomainName1 + ":role.details",
									Resource: DomainName1 + ":svc.details",
									Action:   "get",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     DomainName1 + ":policy.admin",
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
					Name:     DomainName1 + ":role.admin",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: username1,
						},
					},
				},
				{
					Members:  []zms.MemberName{"details"},
					Modified: &timestamp,
					Name:     DomainName1 + ":role.details",
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

func getOldCR() model.Config{
	var out model.Config
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	createTimestamp, _ := time.Parse("", "05/1/2017 12:00:00")
	out.ConfigMeta = model.ConfigMeta{
		Type:      schema.Resource().Kind(),
		Group:     schema.Resource().Group(),
		Version:   schema.Resource().Version(),
		Namespace: "test-namespace",
		Name:      "onboarded-service",
		CreationTimestamp: createTimestamp,
	}
	out.Spec = &v1beta1.AuthorizationPolicy{
		Selector: &workloadv1beta1.WorkloadSelector{
			MatchLabels: map[string]string{"svc": "productpage"},
		},
		Rules: []*v1beta1.Rule{
			{
				To: []*v1beta1.Rule_To{
					{
						Operation: &v1beta1.Operation{
							Methods: []string{
								"POST",
							},
						},
					},
				},
			},
			{
				From: []*v1beta1.Rule_From{
					{
						Source: &v1beta1.Source{
							Principals: []string{
								"*",
								"test.namespace/ra/test.namespace:role.random-reader",
							},
						},
					},
					{
						Source: &v1beta1.Source{
							RequestPrincipals: []string{
								"*",
							},
						},
					},
				},
			},
		},
	}
	return out
}

func getModifiedAuthzPolicy() *authz.AuthorizationPolicy{
	return &authz.AuthorizationPolicy{
		TypeMeta: k8sv1.TypeMeta{
			Kind: collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().Kind(),
			APIVersion: collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().Version(),
		},
		ObjectMeta: k8sv1.ObjectMeta{
			Namespace: "test-namespace",
			Name:      "onboarded-service",
		},
		Spec: v1beta1.AuthorizationPolicy{
			Selector: &workloadv1beta1.WorkloadSelector{
				MatchLabels: map[string]string{"svc": "productpage"},
			},
			Rules: []*v1beta1.Rule{
				{
					To: []*v1beta1.Rule_To{
						{
							Operation: &v1beta1.Operation{
								Methods: []string{
									"POST",
								},
							},
						},
					},
				},
				{
					From: []*v1beta1.Rule_From{
						{
							Source: &v1beta1.Source{
								Principals: []string{
									"*",
									"test.namespace/ra/test.namespace:role.random-reader",
								},
							},
						},
						{
							Source: &v1beta1.Source{
								RequestPrincipals: []string{
									"*",
								},
							},
						},
						{
							Source: &v1beta1.Source{
								RequestPrincipals: []string{
									"random_user",
								},
							},
						},
					},
				},
			},
		},
	}
}

