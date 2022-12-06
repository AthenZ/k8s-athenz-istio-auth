// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package authzpolicy

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	rbacv2 "github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/v2"
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
	"istio.io/istio/pkg/config/schema/collection"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/istio/pkg/config/schema/resource"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	fcache "k8s.io/client-go/tools/cache/testing"
	"k8s.io/client-go/util/workqueue"
)

type Item struct {
	Operation model.Event
	Resource  interface{}
}

const (
	domainNameOnboarded    = "test.namespace.onboarded"
	domainNameNotOnboarded = "test.namespace.not.onboarded"
	username               = "user.name"
	wildcardUsername       = "user.*"
)

var (
	onboardedService = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "onboarded-service",
			Namespace: "test-namespace-onboarded",
			Annotations: map[string]string{
				authzEnabledAnnotation: "true",
			},
			Labels: map[string]string{
				"app": "productpage",
				"svc": "productpage",
			},
		},
	}

	undefinedAthenzRulesServiceWithAnnotationTrue = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "onboarded-service",
			Namespace: "test-namespace-not-onboarded",
			Annotations: map[string]string{
				authzEnabledAnnotation: "true",
			},
			Labels: map[string]string{
				"app": "productpage",
				"svc": "productpage",
			},
		},
	}

	notOnboardedServiceWithAnnotationFalse = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "onboarded-service",
			Namespace: "test-namespace-onboarded",
			Annotations: map[string]string{
				authzEnabledAnnotation: "false",
			},
			Labels: map[string]string{
				"app": "productpage",
				"svc": "productpage",
			},
		},
	}

	notOnboardedService = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "not-onboarded-service",
			Namespace: "test-namespace-not-onboarded",
		},
	}

	onboardedAthenzDomain = &adv1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name:      domainNameOnboarded,
			Namespace: "",
		},
		Spec: adv1.AthenzDomainSpec{
			SignedDomain: getFakeOnboardedDomain(),
		},
	}
	notOnboardedAthenzDomain = &adv1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name:      domainNameNotOnboarded,
			Namespace: "",
		},
		Spec: adv1.AthenzDomainSpec{
			SignedDomain: getFakeNotOnboardedDomain(),
		},
	}

	isNotSystemDisabled, isSystemDisabled int32 = 0, 1
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

func newFakeController(athenzDomain *adv1.AthenzDomain, service *v1.Service, fake bool, apEnabledList string, stopCh <-chan struct{}, standaloneMode bool) *Controller {
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

	fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
	go fakeIndexInformer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, fakeIndexInformer.HasSynced) {
		log.Panicln("timed out waiting for cache to sync")
	}
	c.serviceIndexInformer = fakeIndexInformer
	err := c.serviceIndexInformer.GetStore().Add(service.DeepCopy())
	if err != nil {
		panic(err)
	}

	fakeClientset := fakev1.NewSimpleClientset()
	adIndexInformer := adInformer.NewAthenzDomainInformer(fakeClientset, 0, cache.Indexers{})
	go adIndexInformer.Run(stopCh)
	c.adIndexInformer = adIndexInformer
	err = c.adIndexInformer.GetStore().Add(athenzDomain.DeepCopy())
	if err != nil {
		panic(err)
	}

	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	c.queue = queue

	c.enableOriginJwtSubject = true
	componentsEnabledAuthzPolicy, err := common.ParseComponentsEnabledAuthzPolicy(apEnabledList)
	if err != nil {
		panic(err)
	}
	c.componentEnabledAuthzPolicy = componentsEnabledAuthzPolicy
	c.rbacProvider = rbacv2.NewProvider(componentsEnabledAuthzPolicy, c.enableOriginJwtSubject, "proxy-principals")
	c.dryRunHandler = common.DryRunHandler{}
	c.apiHandler = common.ApiHandler{
		ConfigStoreCache: c.configStoreCache,
	}
	c.standAloneMode = standaloneMode
	return c
}

func TestSyncService(t *testing.T) {
	tests := []struct {
		name                string
		inputService        *v1.Service
		inputAthenzDomain   *adv1.AthenzDomain
		existingAuthzPolicy *model.Config
		expectedAuthzPolicy *model.Config
		item                Item
		standaloneMode      bool
	}{
		{
			name:                "generate Authorization Policy spec for service with annotation set",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: nil,
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			item:                Item{Operation: model.EventAdd, Resource: onboardedService},
			standaloneMode:      false,
		},
		{
			name:                "not generate Authorization Policy spec for service without annotation set",
			inputService:        notOnboardedService,
			inputAthenzDomain:   notOnboardedAthenzDomain,
			existingAuthzPolicy: nil,
			expectedAuthzPolicy: nil,
			item:                Item{Operation: model.EventAdd, Resource: notOnboardedService},
			standaloneMode:      false,
		},
		{
			name:                "delete Authorization Policy spec when there is deletion event of service with annotation set",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: getExpectedAuthzPolicy(),
			expectedAuthzPolicy: nil,
			item:                Item{Operation: model.EventDelete, Resource: onboardedService},
			standaloneMode:      false,
		},
		{
			name:                "create Authorization Policy spec when there is update event of service from no annotation set to annotation set",
			inputService:        notOnboardedServiceWithAnnotationFalse,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: nil,
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			item:                Item{Operation: model.EventUpdate, Resource: onboardedService},
			standaloneMode:      false,
		},
		{
			name:                "create empty Authorization Policy spec when there is create event of service which doesn't have roles / policies defined",
			inputService:        undefinedAthenzRulesServiceWithAnnotationTrue,
			inputAthenzDomain:   notOnboardedAthenzDomain,
			existingAuthzPolicy: nil,
			expectedAuthzPolicy: getExpectedEmptyAuthzPolicy(),
			item:                Item{Operation: model.EventAdd, Resource: undefinedAthenzRulesServiceWithAnnotationTrue},
			standaloneMode:      false,
		},
		{
			name:                "generate Authorization Policy spec for service with annotation set",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: nil,
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			item:                Item{Operation: model.EventAdd, Resource: onboardedService},
			standaloneMode:      true,
		},
		{
			name:                "not generate Authorization Policy spec for service without annotation set",
			inputService:        notOnboardedService,
			inputAthenzDomain:   notOnboardedAthenzDomain,
			existingAuthzPolicy: nil,
			expectedAuthzPolicy: nil,
			item:                Item{Operation: model.EventAdd, Resource: notOnboardedService},
			standaloneMode:      true,
		},
		{
			name:                "delete Authorization Policy spec when there is deletion event of service with annotation set",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: getExpectedAuthzPolicy(),
			expectedAuthzPolicy: nil,
			item:                Item{Operation: model.EventDelete, Resource: onboardedService},
			standaloneMode:      true,
		},
		{
			name:                "create Authorization Policy spec when there is update event of service from no annotation set to annotation set",
			inputService:        notOnboardedServiceWithAnnotationFalse,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: nil,
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			item:                Item{Operation: model.EventUpdate, Resource: onboardedService},
			standaloneMode:      true,
		},
		{
			name:                "create empty Authorization Policy spec when there is create event of service which doesn't have roles / policies defined",
			inputService:        undefinedAthenzRulesServiceWithAnnotationTrue,
			inputAthenzDomain:   notOnboardedAthenzDomain,
			existingAuthzPolicy: nil,
			expectedAuthzPolicy: getExpectedEmptyAuthzPolicy(),
			item:                Item{Operation: model.EventAdd, Resource: undefinedAthenzRulesServiceWithAnnotationTrue},
			standaloneMode:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(tt.inputAthenzDomain, tt.inputService, true, "*", make(chan struct{}), tt.standaloneMode)
			switch action := tt.item.Operation; action {
			case model.EventDelete:
				c.configStoreCache.Create(*tt.existingAuthzPolicy)
				time.Sleep(100 * time.Millisecond)
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(tt.item.Resource)
				assert.Nil(t, err, "function convert item interface to key should not return error")
				err = c.sync(key)
				assert.Nil(t, err, "sync function should not return error")
				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.inputService.Name, tt.inputService.Namespace)
				if genAuthzPolicy != nil {
					assert.Errorf(t, fmt.Errorf("authorization policy spec still exists in the cache"), "authorization policy should be deleted after delete action")
				}
			// default case refers to EventAdd and EventUpdate action
			default:
				// simulate the scenario where add/update resource to the cache
				err := c.serviceIndexInformer.GetStore().Add((tt.item.Resource).(*v1.Service))
				assert.Nil(t, err, "add service object to cache should not return error")
				key, err := cache.MetaNamespaceKeyFunc(tt.item.Resource)
				assert.Nil(t, err, "function convert item interface to key should not return error")
				err = c.sync(key)
				assert.Nil(t, err, "sync function should not return error")

				// Updated Spec should be equal
				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.inputService.Name, tt.inputService.Namespace)
				if genAuthzPolicy != nil {
					// set creation timestamp and resource version for expected authz policy resource, which are generated on the fly
					tt.expectedAuthzPolicy.ConfigMeta.CreationTimestamp = genAuthzPolicy.ConfigMeta.CreationTimestamp
					tt.expectedAuthzPolicy.ConfigMeta.ResourceVersion = genAuthzPolicy.ConfigMeta.ResourceVersion
					assert.Equal(t, *tt.expectedAuthzPolicy, *genAuthzPolicy, "created authorization policy spec should be equal")
				} else {
					// generated spec returns nil, compare with empty config
					assert.Nil(t, genAuthzPolicy, "generated authorization policy should be nil")
				}
			}
		})
	}
}

func TestSyncAthenzDomain(t *testing.T) {
	tests := []struct {
		name                string
		expectedAuthzPolicy *model.Config
		item                Item
		expErr              error
		standaloneMode      bool
	}{
		{
			name:                "update existing authz policy spec when there is athenz domain crd update",
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			item:                Item{Operation: model.EventUpdate, Resource: onboardedAthenzDomain},
			standaloneMode:      false,
		},
		{
			name:                "no action on authz policy when athenz domain crd is deleted",
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			item:                Item{Operation: model.EventDelete, Resource: onboardedAthenzDomain},
			expErr:              fmt.Errorf("athenz domain test.namespace.onboarded does not exist in cache"),
			standaloneMode:      false,
		},
		{
			name:                "when athenz domain crd is created, authz policy should be created",
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			item:                Item{Operation: model.EventAdd, Resource: onboardedAthenzDomain},
			standaloneMode:      false,
		},
		{
			name:                "update existing authz policy spec when there is athenz domain crd update",
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			item:                Item{Operation: model.EventUpdate, Resource: onboardedAthenzDomain},
			standaloneMode:      true,
		},
		{
			name:                "no action on authz policy when athenz domain crd is deleted",
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			item:                Item{Operation: model.EventDelete, Resource: onboardedAthenzDomain},
			expErr:              fmt.Errorf("athenz domain test.namespace.onboarded does not exist in cache"),
			standaloneMode:      true,
		},
		{
			name:                "when athenz domain crd is created, authz policy should be created",
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			item:                Item{Operation: model.EventAdd, Resource: onboardedAthenzDomain},
			standaloneMode:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})

			switch action := tt.item.Operation; action {
			case model.EventUpdate:
				c := newFakeController(onboardedAthenzDomain, onboardedService, true, "*", stopCh, tt.standaloneMode)
				_, err := c.configStoreCache.Create(*getExistingAuthzPolicy())
				assert.Nil(t, err, "configstore create resource should not return error")
				time.Sleep(100 * time.Millisecond)
				key, err := cache.MetaNamespaceKeyFunc(tt.item.Resource)
				assert.Nil(t, err, "function convert item interface to key should not return error")
				err = c.sync(key)
				assert.Nil(t, err, "sync function should not return error")
				// Updated Spec should be equal
				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.expectedAuthzPolicy.Name, tt.expectedAuthzPolicy.Namespace)
				// set creation timestamp and resource version for expected authz policy resource, which are generated on the fly
				tt.expectedAuthzPolicy.ConfigMeta.CreationTimestamp = genAuthzPolicy.ConfigMeta.CreationTimestamp
				tt.expectedAuthzPolicy.ConfigMeta.ResourceVersion = genAuthzPolicy.ConfigMeta.ResourceVersion
				assert.Equal(t, *tt.expectedAuthzPolicy, *genAuthzPolicy, "updated authorization policy spec should be equal")
			case model.EventDelete:
				c := newFakeController(onboardedAthenzDomain, onboardedService, true, "*", stopCh, tt.standaloneMode)
				_, err := c.configStoreCache.Create(*getExpectedAuthzPolicy())
				assert.Nil(t, err, "configstore create resource should not return error")
				time.Sleep(100 * time.Millisecond)
				// simulate domain deletion
				err = c.adIndexInformer.GetStore().Delete(onboardedAthenzDomain)
				assert.Nil(t, err, "delete athenz domain crd in the cache should not return error")
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(tt.item.Resource)
				assert.Nil(t, err, "function convert item interface to key should not return error")
				err = c.sync(key)
				assert.Equal(t, err, tt.expErr, "sync function should return domain not exist error")
				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.expectedAuthzPolicy.Name, tt.expectedAuthzPolicy.Namespace)
				// set creation timestamp and resource version for expected authz policy resource, which are generated on the fly
				tt.expectedAuthzPolicy.ConfigMeta.CreationTimestamp = genAuthzPolicy.ConfigMeta.CreationTimestamp
				tt.expectedAuthzPolicy.ConfigMeta.ResourceVersion = genAuthzPolicy.ConfigMeta.ResourceVersion
				assert.Equal(t, *tt.expectedAuthzPolicy, *genAuthzPolicy, "created authorization policy spec should be equal")
			case model.EventAdd:
				c := newFakeController(&adv1.AthenzDomain{}, onboardedService, true, "*", stopCh, tt.standaloneMode)
				err := c.adIndexInformer.GetStore().Add(onboardedAthenzDomain)
				assert.Nil(t, err, "add athenz domain crd to cache should not return error")
				key, err := cache.MetaNamespaceKeyFunc(tt.item.Resource)
				assert.Nil(t, err, "function convert item interface to key should not return error")
				err = c.sync(key)
				assert.Nil(t, err, "sync function should not return error")

				// Updated Spec should be equal
				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.expectedAuthzPolicy.Name, tt.expectedAuthzPolicy.Namespace)
				// set creation timestamp and resource version for expected authz policy resource, which are generated on the fly
				tt.expectedAuthzPolicy.ConfigMeta.CreationTimestamp = genAuthzPolicy.ConfigMeta.CreationTimestamp
				tt.expectedAuthzPolicy.ConfigMeta.ResourceVersion = genAuthzPolicy.ConfigMeta.ResourceVersion
				assert.Equal(t, *tt.expectedAuthzPolicy, *genAuthzPolicy, "created authorization policy spec should be equal")
			}
		})
	}
}

func TestSyncAuthzPolicy(t *testing.T) {
	tests := []struct {
		name                string
		inputService        *v1.Service
		inputAthenzDomain   *adv1.AthenzDomain
		initAuthzPolicySpec *model.Config
		item                Item
		expectedAuthzPolicy *model.Config
		standaloneMode      bool
	}{
		{
			name:                "when there is manual modification of authz policy resource, controller will revert back to spec matched with athenz domain crd",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			initAuthzPolicySpec: getExistingAuthzPolicy(),
			item:                Item{Operation: model.EventUpdate, Resource: getModifiedAuthzPolicy()},
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			standaloneMode:      false,
		},
		{
			name:                "when there is deletion of authz policy resource, controller will recreate the authz policy",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			initAuthzPolicySpec: getExistingAuthzPolicy(),
			item:                Item{Operation: model.EventDelete, Resource: getModifiedAuthzPolicy()},
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			standaloneMode:      false,
		},
		{
			name:                "when there is manual modification of authz policy resource with override annotation, controller should do nothing",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			initAuthzPolicySpec: getModifiedAuthzPolicyCRWithOverrideAnnotation(),
			item:                Item{Operation: model.EventUpdate, Resource: getModifiedAuthzPolicyWithOverrideAnnotation()},
			expectedAuthzPolicy: getModifiedAuthzPolicyCRWithOverrideAnnotation(),
			standaloneMode:      false,
		},
		{
			name:                "when there is manual creation of authz policy without override annotation, controller should delete this create resource",
			inputService:        notOnboardedServiceWithAnnotationFalse,
			inputAthenzDomain:   onboardedAthenzDomain,
			initAuthzPolicySpec: nil,
			item:                Item{Operation: model.EventAdd, Resource: getModifiedAuthzPolicy()},
			expectedAuthzPolicy: nil,
			standaloneMode:      false,
		},
		{
			name:                "when there is manual modification of authz policy resource, controller will revert back to spec matched with athenz domain crd",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			initAuthzPolicySpec: getExistingAuthzPolicy(),
			item:                Item{Operation: model.EventUpdate, Resource: getModifiedAuthzPolicy()},
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			standaloneMode:      true,
		},
		{
			name:                "when there is deletion of authz policy resource, controller will recreate the authz policy",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			initAuthzPolicySpec: getExistingAuthzPolicy(),
			item:                Item{Operation: model.EventDelete, Resource: getModifiedAuthzPolicy()},
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			standaloneMode:      true,
		},
		{
			name:                "when there is manual modification of authz policy resource with override annotation, controller should do nothing",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			initAuthzPolicySpec: getModifiedAuthzPolicyCRWithOverrideAnnotation(),
			item:                Item{Operation: model.EventUpdate, Resource: getModifiedAuthzPolicyWithOverrideAnnotation()},
			expectedAuthzPolicy: getModifiedAuthzPolicyCRWithOverrideAnnotation(),
			standaloneMode:      true,
		},
		{
			name:                "when there is manual creation of authz policy without override annotation, controller should delete this create resource",
			inputService:        notOnboardedServiceWithAnnotationFalse,
			inputAthenzDomain:   onboardedAthenzDomain,
			initAuthzPolicySpec: nil,
			item:                Item{Operation: model.EventAdd, Resource: getModifiedAuthzPolicy()},
			expectedAuthzPolicy: nil,
			standaloneMode:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch action := tt.item.Operation; action {
			case model.EventUpdate:
				c := newFakeController(tt.inputAthenzDomain, tt.inputService, true, "*", make(chan struct{}), tt.standaloneMode)
				_, err := c.configStoreCache.Create(*tt.initAuthzPolicySpec)
				assert.Nil(t, err, "configstore create resource should not return error")
				time.Sleep(100 * time.Millisecond)
				key, err := cache.MetaNamespaceKeyFunc(tt.item.Resource)
				assert.Nil(t, err, "function convert item interface to key should not return error")
				err = c.sync(key)
				assert.Nil(t, err, "sync function should not return error")
				// Updated Spec should be equal
				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.expectedAuthzPolicy.Name, tt.expectedAuthzPolicy.Namespace)
				// set creation timestamp and resource version for expected authz policy resource, which are generated on the fly
				tt.expectedAuthzPolicy.ConfigMeta.CreationTimestamp = genAuthzPolicy.ConfigMeta.CreationTimestamp
				tt.expectedAuthzPolicy.ConfigMeta.ResourceVersion = genAuthzPolicy.ConfigMeta.ResourceVersion
				assert.Equal(t, *tt.expectedAuthzPolicy, *genAuthzPolicy, "created authorization policy spec should be equal")
			case model.EventDelete:
				c := newFakeController(tt.inputAthenzDomain, tt.inputService, true, "*", make(chan struct{}), tt.standaloneMode)
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(tt.item.Resource)
				assert.Nil(t, err, "function convert item interface to key should not return error")
				err = c.sync(key)
				assert.Nil(t, err, "sync function should not return error")
				// Updated Spec should be equal
				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.expectedAuthzPolicy.Name, tt.expectedAuthzPolicy.Namespace)
				// set creation timestamp and resource version for expected authz policy resource, which are generated on the fly
				tt.expectedAuthzPolicy.ConfigMeta.CreationTimestamp = genAuthzPolicy.ConfigMeta.CreationTimestamp
				tt.expectedAuthzPolicy.ConfigMeta.ResourceVersion = genAuthzPolicy.ConfigMeta.ResourceVersion
				assert.Equal(t, *tt.expectedAuthzPolicy, *genAuthzPolicy, "created authorization policy spec should be equal")
			case model.EventAdd:
				c := newFakeController(tt.inputAthenzDomain, tt.inputService, true, "*", make(chan struct{}), tt.standaloneMode)
				key, err := cache.MetaNamespaceKeyFunc(tt.item.Resource)
				assert.Nil(t, err, "function convert item interface to key should not return error")
				err = c.sync(key)
				assert.Nil(t, err, "sync function should not return error")
				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.inputService.Name, tt.inputService.Namespace)
				if genAuthzPolicy != nil {
					assert.Errorf(t, fmt.Errorf("authz policy should not exist in the cache"), "controller should delete spec which is manually created without override annotation")
				}
			}
		})
	}
}

func TestNewController(t *testing.T) {
	configDescriptor := collection.SchemasFor(collections.IstioSecurityV1Beta1Authorizationpolicies)
	source := fcache.NewFakeControllerSource()
	fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
	athenzclientset := fakev1.NewSimpleClientset()
	fakeAthenzInformer := adInformer.NewAthenzDomainInformer(athenzclientset, 0, cache.Indexers{})
	istioClientSet := fakeversionedclient.NewSimpleClientset()
	apResyncInterval, err := time.ParseDuration("1h")
	assert.Nil(t, err, "time parseDuration call should not fail with error")
	configStore := memory.Make(configDescriptor)
	configStoreCache := memory.NewController(configStore)
	apiHandler := common.ApiHandler{
		ConfigStoreCache: configStoreCache,
	}
	standAloneMode := true
	c := NewController(configStoreCache, fakeIndexInformer, fakeAthenzInformer, istioClientSet, apResyncInterval, true, &common.ComponentEnabled{}, "proxy-principals", standAloneMode)
	assert.Equal(t, fakeIndexInformer, c.serviceIndexInformer, "service index informer pointer should be equal")
	assert.Equal(t, configStoreCache, c.configStoreCache, "config configStoreCache cache pointer should be equal")
	assert.Equal(t, fakeAthenzInformer, c.adIndexInformer, "athenz index informer cache should be equal")
	assert.Equal(t, true, c.enableOriginJwtSubject, "enableOriginJwtSubject bool should be equal")
	assert.Equal(t, common.DryRunHandler{}, c.dryRunHandler, "dryRun handler should be equal")
	assert.Equal(t, apiHandler, c.apiHandler, "api handler should be equal")
	assert.Equal(t, standAloneMode, c.standAloneMode, "stand alone mode should be equal")
}

func TestCleanUpStaleAP(t *testing.T) {
	tests := []struct {
		name                string
		inputService        *v1.Service
		inputAthenzDomain   *adv1.AthenzDomain
		existingAuthzPolicy *model.Config
		expectedAuthzPolicy *model.Config
		apEnabledList       string
		standaloneMode      bool
	}{
		{
			name:                "delete all authorization policies as apEnabledList has a different namespace than onboarded namespace",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: getExpectedAuthzPolicy(),
			expectedAuthzPolicy: nil,
			apEnabledList:       "foobar/*",
			standaloneMode:      false,
		},
		{
			name:                "existing authorization policy is not deleted as all namespaces are part of apEnabledList",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: getExpectedAuthzPolicy(),
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			apEnabledList:       "*",
			standaloneMode:      false,
		},
		{
			name:                "existing authorization policy is not deleted as the same namespace as the existing service is part of apEnabledList",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: getExpectedAuthzPolicy(),
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			apEnabledList:       "test-namespace-onboarded/*",
			standaloneMode:      false,
		},
		{
			name:                "existing authorization policy is not deleted as the override annotation is enabled even when not in the same namespace",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: getModifiedAuthzPolicyCRWithOverrideAnnotation(),
			expectedAuthzPolicy: getModifiedAuthzPolicyCRWithOverrideAnnotation(),
			apEnabledList:       "foobar/*",
			standaloneMode:      true,
		},
		{
			name:                "delete all authorization policies as apEnabledList has a different namespace than onboarded namespace",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: getExpectedAuthzPolicy(),
			expectedAuthzPolicy: nil,
			apEnabledList:       "foobar/*",
			standaloneMode:      true,
		},
		{
			name:                "existing authorization policy is not deleted as all namespaces are part of apEnabledList",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: getExpectedAuthzPolicy(),
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			apEnabledList:       "*",
			standaloneMode:      true,
		},
		{
			name:                "existing authorization policy is not deleted as the same namespace as the existing service is part of apEnabledList",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: getExpectedAuthzPolicy(),
			expectedAuthzPolicy: getExpectedAuthzPolicy(),
			apEnabledList:       "test-namespace-onboarded/*",
			standaloneMode:      true,
		},
		{
			name:                "existing authorization policy is not deleted as the override annotation is enabled even when not in the same namespace",
			inputService:        onboardedService,
			inputAthenzDomain:   onboardedAthenzDomain,
			existingAuthzPolicy: getModifiedAuthzPolicyCRWithOverrideAnnotation(),
			expectedAuthzPolicy: getModifiedAuthzPolicyCRWithOverrideAnnotation(),
			apEnabledList:       "foobar/*",
			standaloneMode:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(tt.inputAthenzDomain, tt.inputService, true, tt.apEnabledList, make(chan struct{}), tt.standaloneMode)
			c.configStoreCache.Create(*tt.existingAuthzPolicy)
			time.Sleep(100 * time.Millisecond)

			c.cleanUpStaleAP()

			genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.inputService.Name, tt.inputService.Namespace)

			if genAuthzPolicy != nil {
				tt.expectedAuthzPolicy.ConfigMeta.CreationTimestamp = genAuthzPolicy.ConfigMeta.CreationTimestamp
				tt.expectedAuthzPolicy.ConfigMeta.ResourceVersion = genAuthzPolicy.ConfigMeta.ResourceVersion
			}

			assert.Equal(t, tt.expectedAuthzPolicy, genAuthzPolicy, "expected and generated authorization policy spec should be the same")
		})
	}
}

func getExpectedAuthzPolicy() *model.Config {
	var out model.Config
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	createTimestamp, err := time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
	if err != nil {
		panic(err)
	}
	out.ConfigMeta = model.ConfigMeta{
		Type:              schema.Resource().Kind(),
		Group:             schema.Resource().Group(),
		Version:           schema.Resource().Version(),
		Namespace:         "test-namespace-onboarded",
		Name:              "onboarded-service",
		CreationTimestamp: createTimestamp,
	}
	out.Spec = &v1beta1.AuthorizationPolicy{
		Selector: &workloadv1beta1.WorkloadSelector{
			MatchLabels: map[string]string{"app": "productpage"},
		},
		Rules: []*v1beta1.Rule{
			{
				From: []*v1beta1.Rule_From{
					{
						Source: &v1beta1.Source{
							Principals: []string{
								"*",
								"test.namespace.onboarded/ra/productpage-reader",
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
		},
	}
	return &out
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
			Name:     domainNameOnboarded,
			Policies: &zms.SignedPolicies{
				Contents: &zms.DomainPolicies{
					Domain: domainNameOnboarded,
					Policies: []*zms.Policy{
						{
							Assertions: []*zms.Assertion{
								{
									Role:     domainNameOnboarded + ":role.admin",
									Resource: domainNameOnboarded + ":*",
									Action:   "*",
									Effect:   &allow,
								},
								{
									Role:     domainNameOnboarded + ":role.productpage-reader",
									Resource: domainNameOnboarded + ":svc.productpage",
									Action:   "get",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     domainNameOnboarded + ":policy.admin",
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
					Name:     domainNameOnboarded + ":role.admin",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: username,
						},
					},
				},
				{
					Members:  []zms.MemberName{"productpage-reader"},
					Modified: &timestamp,
					Name:     domainNameOnboarded + ":role.productpage-reader",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: wildcardUsername,
						},
					},
				},
				{
					Name:     domainNameOnboarded + "role.invalid",
					Modified: &timestamp,
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: "user.expired",
							Expiration: &rdl.Timestamp{
								Time: time.Now().Add(-time.Hour),
							},
							SystemDisabled: &isNotSystemDisabled,
						},
						{
							MemberName: "user.disabled",
							Expiration: &rdl.Timestamp{
								Time: time.Now().Add(time.Hour),
							},
							SystemDisabled: &isSystemDisabled,
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
			Name:     domainNameNotOnboarded,
			Policies: &zms.SignedPolicies{
				Contents: &zms.DomainPolicies{
					Domain: domainNameNotOnboarded,
					Policies: []*zms.Policy{
						{
							Assertions: []*zms.Assertion{
								{
									Role:     domainNameNotOnboarded + ":role.admin",
									Resource: domainNameNotOnboarded + ":*",
									Action:   "*",
									Effect:   &allow,
								},
								{
									Role:     domainNameNotOnboarded + ":role.details",
									Resource: domainNameNotOnboarded + ":svc.details",
									Action:   "get",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     domainNameNotOnboarded + ":policy.admin",
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
					Name:     domainNameNotOnboarded + ":role.admin",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: wildcardUsername,
						},
					},
				},
				{
					Members:  []zms.MemberName{"details"},
					Modified: &timestamp,
					Name:     domainNameNotOnboarded + ":role.details",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: wildcardUsername,
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

func getExistingAuthzPolicy() *model.Config {
	var out model.Config
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	createTimestamp, err := time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
	if err != nil {
		panic(err)
	}
	out.ConfigMeta = model.ConfigMeta{
		Type:              schema.Resource().Kind(),
		Group:             schema.Resource().Group(),
		Version:           schema.Resource().Version(),
		Namespace:         "test-namespace-onboarded",
		Name:              "onboarded-service",
		CreationTimestamp: createTimestamp,
	}
	out.Spec = &v1beta1.AuthorizationPolicy{
		Selector: &workloadv1beta1.WorkloadSelector{
			MatchLabels: map[string]string{"app": "productpage"},
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
								"test.namespace.onboarded/ra/random-reader",
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
	return &out
}

func getModifiedAuthzPolicy() *authz.AuthorizationPolicy {
	return &authz.AuthorizationPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().Kind(),
			APIVersion: collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().Version(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-namespace-onboarded",
			Name:      "onboarded-service",
		},
		Spec: v1beta1.AuthorizationPolicy{
			Selector: &workloadv1beta1.WorkloadSelector{
				MatchLabels: map[string]string{"app": "productpage"},
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
									"test.namespace.onboarded/ra/random-reader",
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

func getExpectedEmptyAuthzPolicy() *model.Config {
	out := &model.Config{}
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	createTimestamp, err := time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
	if err != nil {
		panic(err)
	}
	out.ConfigMeta = model.ConfigMeta{
		Type:              schema.Resource().Kind(),
		Group:             schema.Resource().Group(),
		Version:           schema.Resource().Version(),
		Namespace:         "test-namespace-not-onboarded",
		Name:              "onboarded-service",
		CreationTimestamp: createTimestamp,
	}
	out.Spec = &v1beta1.AuthorizationPolicy{
		Selector: &workloadv1beta1.WorkloadSelector{
			MatchLabels: map[string]string{"app": "productpage"},
		},
	}
	return out
}

func getModifiedAuthzPolicyWithOverrideAnnotation() *authz.AuthorizationPolicy {
	authzPolicySpec := getModifiedAuthzPolicy()
	authzPolicySpec.ObjectMeta.Annotations = map[string]string{"overrideAuthzPolicy": "true"}
	return authzPolicySpec
}

func getModifiedAuthzPolicyCRWithOverrideAnnotation() *model.Config {
	out := getExistingAuthzPolicy()
	out.ConfigMeta.Annotations = map[string]string{"overrideAuthzPolicy": "true"}
	return out
}
