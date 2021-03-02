// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package authzpolicy

import (
	"fmt"
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
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	fcache "k8s.io/client-go/tools/cache/testing"
	"k8s.io/client-go/util/workqueue"
	"sync"
	"testing"
	"time"
)

type Item struct {
	Operation model.Event
	Resource  interface{}
}

const (
	domainNameOnboarded             = "test.namespace.onboarded"
	domainNameOnboardedNotOnboarded = "test.namespace.not.onboarded"
	username                        = "user.name"
	wildcardUsername                = "user.*"
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
				"svc": "productpage",
			},
		},
	}

	onboardedServiceWithoutAnnotation = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "onboarded-service",
			Namespace: "test-namespace-onboarded",
			Annotations: map[string]string{
				authzEnabledAnnotation: "false",
			},
			Labels: map[string]string{
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
			Name:      domainNameOnboardedNotOnboarded,
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

func newFakeController(athenzDomain *adv1.AthenzDomain, service *v1.Service, fake bool, stopCh <-chan struct{}) *Controller {
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
	source.Add(service)

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
	c.dryRun = false
	c.rbacProvider = rbacv2.NewProvider(c.dryRun, c.enableOriginJwtSubject)
	c.eventHandler = &common.ApiHandler{
		ConfigStoreCache: c.configStoreCache,
	}
	return c
}

func TestSyncService(t *testing.T) {
	tests := []struct {
		name                string
		inputService        *v1.Service
		inputAthenzDomain   *adv1.AthenzDomain
		fake                bool
		existingAuthzPolicy model.Config
		expectedAuthzPolicy model.Config
		item                Item
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
			existingAuthzPolicy: getExpectedCR(),
			expectedAuthzPolicy: model.Config{},
			item:                Item{Operation: model.EventDelete, Resource: onboardedService},
		},
		{
			name:                "create Authorization Policy spec when there is update event of service from no annotation set to annotation set",
			inputService:        onboardedServiceWithoutAnnotation,
			inputAthenzDomain:   onboardedAthenzDomain,
			fake:                true,
			existingAuthzPolicy: getExpectedCR(),
			expectedAuthzPolicy: model.Config{},
			item:                Item{Operation: model.EventUpdate, Resource: onboardedService},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(tt.inputAthenzDomain, tt.inputService, tt.fake, make(chan struct{}))
			switch action := tt.item.Operation; action {
			case model.EventDelete:
				c.configStoreCache.Create(tt.existingAuthzPolicy)
				time.Sleep(100 * time.Millisecond)
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(tt.item.Resource)
				assert.Equal(t, nil, err, "function convert item interface to key should not return error")
				err = c.sync(key)
				if err != nil {
					log.Panicln("controller has sync err: ", err)
				}

				genAuthzPolicy := c.configStoreCache.Get(collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().GroupVersionKind(), tt.inputService.Name, tt.inputService.Namespace)
				if genAuthzPolicy != nil {
					assert.Errorf(t, fmt.Errorf("authorization policy spec still exists in the cache"), "authorization policy should be deleted after delete action")
				}
			// default case refers to EventAdd and EventUpdate action
			default:
				time.Sleep(100 * time.Millisecond)
				key, err := cache.MetaNamespaceKeyFunc(tt.item.Resource)
				assert.Equal(t, nil, err, "function convert item interface to key should not return error")
				err = c.sync(key)
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
		name                string
		expectedAuthzPolicy model.Config
		fake                bool
		item                Item
	}{
		{
			name:                "update existing authz policy spec when there is athenz domain crd update",
			expectedAuthzPolicy: getExpectedCR(),
			fake:                true,
			item:                Item{Operation: model.EventUpdate, Resource: onboardedAthenzDomain},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			c := newFakeController(&adv1.AthenzDomain{}, &v1.Service{}, tt.fake, stopCh)
			c.adIndexInformer.GetStore().Add(onboardedAthenzDomain.DeepCopy())
			c.serviceIndexInformer.GetStore().Add(onboardedService.DeepCopy())
			switch action := tt.item.Operation; action {
			case model.EventUpdate:
				_, err := c.configStoreCache.Create(getOldCR())
				if err != nil {
					log.Panicln("controller not able to create authz policy spec: ", err)
				}

				time.Sleep(100 * time.Millisecond)
				key, err := cache.MetaNamespaceKeyFunc(tt.item.Resource)
				assert.Equal(t, nil, err, "function convert item interface to key should not return error")
				err = c.sync(key)
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
		name                string
		inputService        *v1.Service
		fake                bool
		inputAthenzDomain   *adv1.AthenzDomain
		item                Item
		expectedAuthzPolicy model.Config
	}{
		{
			name:                "when there is manual modification of authz policy resource, controller will revert back to spec matched with athenz domain crd",
			inputService:        onboardedService,
			fake:                true,
			inputAthenzDomain:   onboardedAthenzDomain,
			item:                Item{Operation: model.EventUpdate, Resource: getModifiedAuthzPolicy()},
			expectedAuthzPolicy: getExpectedCR(),
		},
		{
			name:                "when there is deletion of authz policy resource, controller will recreate the authz policy",
			inputService:        onboardedService,
			fake:                true,
			inputAthenzDomain:   onboardedAthenzDomain,
			item:                Item{Operation: model.EventDelete, Resource: getModifiedAuthzPolicy()},
			expectedAuthzPolicy: getExpectedCR(),
		},
		{
			name:                "when there is manual modification of authz policy resource with override annotation, controller should do nothing",
			inputService:        onboardedService,
			fake:                true,
			inputAthenzDomain:   onboardedAthenzDomain,
			item:                Item{Operation: model.EventUpdate, Resource: getModifiedAuthzPolicyWithOverrideAnnotation()},
			expectedAuthzPolicy: getModifiedAuthzPolicyCRWithOverrideAnnotation(),
		},
		{
			name:                "when there is manual creation of authz policy without override annotation, controller should delete this create resource",
			inputService:        onboardedServiceWithoutAnnotation,
			fake:                true,
			inputAthenzDomain:   onboardedAthenzDomain,
			item:                Item{Operation: model.EventAdd, Resource: getModifiedAuthzPolicy()},
			expectedAuthzPolicy: model.Config{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch action := tt.item.Operation; action {
			case model.EventUpdate:
				c := newFakeController(tt.inputAthenzDomain, tt.inputService, tt.fake, make(chan struct{}))
				resourceVersion, err := c.configStoreCache.Create(getOldCR())
				if err != nil {
					log.Panicln("controller not able to create authz policy spec: ", err)
				}
				time.Sleep(100 * time.Millisecond)
				(tt.item.Resource).(*authz.AuthorizationPolicy).ObjectMeta.ResourceVersion = resourceVersion
				key, err := cache.MetaNamespaceKeyFunc(tt.item.Resource)
				assert.Equal(t, nil, err, "function convert item interface to key should not return error")
				err = c.sync(key)
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
				c := newFakeController(&adv1.AthenzDomain{}, &v1.Service{}, tt.fake, make(chan struct{}))
				c.adIndexInformer.GetStore().Add(tt.inputAthenzDomain.DeepCopy())
				c.serviceIndexInformer.GetStore().Add(tt.inputService.DeepCopy())
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(tt.item.Resource)
				assert.Equal(t, nil, err, "function convert item interface to key should not return error")
				err = c.sync(key)
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
			case model.EventAdd:
				c := newFakeController(tt.inputAthenzDomain, tt.inputService, tt.fake, make(chan struct{}))
				key, err := cache.MetaNamespaceKeyFunc(tt.item.Resource)
				assert.Equal(t, nil, err, "function convert item interface to key should not return error")
				err = c.sync(key)
				if err != nil {
					log.Panicln("controller has sync err: ", err)
				}
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
	assert.Equal(t, nil, err, "time parseDuration call should not fail with error")
	configStore := memory.Make(configDescriptor)
	configStoreCache := memory.NewController(configStore)
	c := NewController(configStoreCache, fakeIndexInformer, fakeAthenzInformer, istioClientSet, apResyncInterval, true, true)
	assert.Equal(t, fakeIndexInformer, c.serviceIndexInformer, "service index informer pointer should be equal")
	assert.Equal(t, configStoreCache, c.configStoreCache, "config configStoreCache cache pointer should be equal")
	assert.Equal(t, fakeAthenzInformer, c.adIndexInformer, "athenz index informer cache should be equal")
	assert.Equal(t, true, c.enableOriginJwtSubject, "enableOriginJwtSubject bool should be equal")
}

func getExpectedCR() model.Config {
	var out model.Config
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	createTimestamp, _ := time.Parse("", "12/8/2015 12:00:00")
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
			MatchLabels: map[string]string{"svc": "productpage"},
		},
		Rules: []*v1beta1.Rule{
			{
				From: []*v1beta1.Rule_From{
					{
						Source: &v1beta1.Source{
							Principals: []string{
								"*",
								"test.namespace.onboarded/ra/test.namespace.onboarded:role.productpage-reader",
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
							MemberName: "user.expired",
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
			Name:     domainNameOnboardedNotOnboarded,
			Policies: &zms.SignedPolicies{
				Contents: &zms.DomainPolicies{
					Domain: domainNameOnboardedNotOnboarded,
					Policies: []*zms.Policy{
						{
							Assertions: []*zms.Assertion{
								{
									Role:     domainNameOnboardedNotOnboarded + ":role.admin",
									Resource: domainNameOnboardedNotOnboarded + ":*",
									Action:   "*",
									Effect:   &allow,
								},
								{
									Role:     domainNameOnboardedNotOnboarded + ":role.details",
									Resource: domainNameOnboardedNotOnboarded + ":svc.details",
									Action:   "get",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     domainNameOnboardedNotOnboarded + ":policy.admin",
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
					Name:     domainNameOnboardedNotOnboarded + ":role.admin",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: wildcardUsername,
						},
					},
				},
				{
					Members:  []zms.MemberName{"details"},
					Modified: &timestamp,
					Name:     domainNameOnboardedNotOnboarded + ":role.details",
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

func getOldCR() model.Config {
	var out model.Config
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	createTimestamp, _ := time.Parse("", "05/1/2017 12:00:00")
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
								"test.namespace.onboarded/ra/test.namespace.onboarded:role.random-reader",
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
									"test.namespace.onboarded/ra/test.namespace.onboarded:role.random-reader",
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

func getModifiedAuthzPolicyWithOverrideAnnotation() *authz.AuthorizationPolicy {
	return &authz.AuthorizationPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().Kind(),
			APIVersion: collections.IstioSecurityV1Beta1Authorizationpolicies.Resource().Version(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "test-namespace-onboarded",
			Name:        "onboarded-service",
			Annotations: map[string]string{"overrideAuthzPolicy": "true"},
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
									"test.namespace.onboarded/ra/test.namespace.onboarded:role.random-reader",
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

func getModifiedAuthzPolicyCRWithOverrideAnnotation() model.Config {
	var out model.Config
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	createTimestamp, _ := time.Parse("", "12/8/2015 12:00:00")
	out.ConfigMeta = model.ConfigMeta{
		Type:              schema.Resource().Kind(),
		Group:             schema.Resource().Group(),
		Version:           schema.Resource().Version(),
		Namespace:         "test-namespace-onboarded",
		Name:              "onboarded-service",
		CreationTimestamp: createTimestamp,
		Annotations:       map[string]string{"overrideAuthzPolicy": "true"},
	}
	out.Spec = &v1beta1.AuthorizationPolicy{
		Selector: &workloadv1beta1.WorkloadSelector{
			MatchLabels: map[string]string{"svc": "productpage"},
		},
		Rules: []*v1beta1.Rule{
			{
				From: []*v1beta1.Rule_From{
					{
						Source: &v1beta1.Source{
							Principals: []string{
								"*",
								"test.namespace.onboarded/ra/test.namespace.onboarded:role.productpage-reader",
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
	return out
}
