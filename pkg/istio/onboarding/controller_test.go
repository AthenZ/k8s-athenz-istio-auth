// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package onboarding

import (
	"log"
	"testing"
	"time"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/config/memory"
	"istio.io/istio/pilot/pkg/model"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	fcache "k8s.io/client-go/tools/cache/testing"
	"k8s.io/client-go/util/workqueue"

	"github.com/stretchr/testify/assert"
)

var (
	onboardedService = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "onboarded-service",
			Namespace: "test-namespace",
			Annotations: map[string]string{
				authzEnabledAnnotation: "true",
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
)

type fakeConfigStore struct {
	model.ConfigStore
}

func (cs *fakeConfigStore) ConfigDescriptor() model.ConfigDescriptor {
	return model.ConfigDescriptor{
		model.ClusterRbacConfig,
	}
}

func (cs *fakeConfigStore) Get(typ, name, namespace string) *model.Config {
	clusterRbacConfig := newClusterRbacConfig([]string{onboardedServiceName})
	return &clusterRbacConfig
}

func (cs *fakeConfigStore) Delete(typ, name, namespace string) error {
	return nil
}

func getClusterRbacConfig(c *Controller) (*model.Config, *v1alpha1.RbacConfig) {
	config := c.configStoreCache.Get(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, "")
	if config == nil {
		return nil, nil
	}

	clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
	if !ok {
		log.Panicln("cannot cast to rbac config")
	}
	return config, clusterRbacConfig
}

func newFakeController(services []*v1.Service, fake bool) *Controller {
	c := &Controller{}
	configDescriptor := model.ConfigDescriptor{
		model.ClusterRbacConfig,
	}

	configStore := memory.Make(configDescriptor)
	if fake {
		configStore = &fakeConfigStore{configStore}
	}
	c.configStoreCache = memory.NewController(configStore)

	source := fcache.NewFakeControllerSource()
	for _, service := range services {
		source.Add(service)
	}
	fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
	stopChan := make(chan struct{})
	go fakeIndexInformer.Run(stopChan)

	if !cache.WaitForCacheSync(stopChan, fakeIndexInformer.HasSynced) {
		log.Panicln("timed out waiting for cache to sync")
	}
	c.serviceIndexInformer = fakeIndexInformer
	c.dnsSuffix = dnsSuffix

	return c
}

func TestNewController(t *testing.T) {
	configDescriptor := model.ConfigDescriptor{
		model.ClusterRbacConfig,
	}

	source := fcache.NewFakeControllerSource()
	fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
	configStore := memory.Make(configDescriptor)
	configStoreCache := memory.NewController(configStore)

	c := NewController(configStoreCache, dnsSuffix, fakeIndexInformer, time.Second)
	assert.Equal(t, dnsSuffix, c.dnsSuffix, "dns suffix should be equal")
	assert.Equal(t, fakeIndexInformer, c.serviceIndexInformer, "service index informer pointer should be equal")
	assert.Equal(t, configStoreCache, c.configStoreCache, "config configStoreCache cache pointer should be equal")
	assert.Equal(t, time.Second, c.crcResyncInterval, "crc resync interval should be equal")
}

func TestAddService(t *testing.T) {
	tests := []struct {
		name              string
		inputServices     []string
		clusterRbacConfig *v1alpha1.RbacConfig
		expectedArray     []string
	}{
		{
			name:              "test adding new service to ClusterRbacConfig",
			inputServices:     []string{onboardedServiceName},
			clusterRbacConfig: newClusterRbacSpec(nil),
			expectedArray:     []string{onboardedServiceName},
		},
		{
			name:              "test adding existing service to ClusterRbacConfig",
			inputServices:     []string{onboardedServiceName},
			clusterRbacConfig: newClusterRbacSpec([]string{existingServiceName}),
			expectedArray:     []string{existingServiceName, onboardedServiceName},
		},
		{
			name:              "test adding nil ClusterRbacConfig",
			inputServices:     []string{onboardedServiceName},
			clusterRbacConfig: nil,
			expectedArray:     []string{},
		},
		{
			name:              "test adding with empty ClusterRbacConfig",
			inputServices:     []string{onboardedServiceName},
			clusterRbacConfig: newClusterRbacSpec(nil),
			expectedArray:     []string{onboardedServiceName},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addServices(tt.inputServices, tt.clusterRbacConfig)
			if tt.clusterRbacConfig != nil {
				assert.Equal(t, tt.expectedArray, tt.clusterRbacConfig.Inclusion.Services, "ClusterRbacConfig service list should contain expected services")
			}
		})
	}
}

func TestDeleteService(t *testing.T) {
	tests := []struct {
		name              string
		clusterRbacConfig *v1alpha1.RbacConfig
		inputArray        []string
		expectedArray     []string
	}{
		{
			name:              "test deleting service from ClusterRbacConfig",
			clusterRbacConfig: newClusterRbacSpec([]string{onboardedServiceName}),
			inputArray:        []string{onboardedServiceName},
			expectedArray:     []string{},
		},
		{
			name:              "test deleting existing service from ClusterRbacConfig",
			clusterRbacConfig: newClusterRbacSpec([]string{onboardedServiceName, existingServiceName}),
			inputArray:        []string{onboardedServiceName},
			expectedArray:     []string{existingServiceName},
		},
		{
			name:              "test deleting empty input array to ClusterRbacConfig",
			clusterRbacConfig: newClusterRbacSpec([]string{existingServiceName}),
			inputArray:        []string{},
			expectedArray:     []string{existingServiceName},
		},
		{
			name:              "test deleting empty service which does not exist in the ClusterRbacConfig",
			clusterRbacConfig: newClusterRbacSpec([]string{existingServiceName}),
			inputArray:        []string{onboardedServiceName},
			expectedArray:     []string{existingServiceName},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deleteServices(tt.inputArray, tt.clusterRbacConfig)
			assert.Equal(t, tt.expectedArray, tt.clusterRbacConfig.Inclusion.Services, "ClusterRbacConfig service list should contain expected services")
		})
	}
}

func TestCreateClusterRbacConfig(t *testing.T) {
	config := newClusterRbacConfig([]string{onboardedServiceName, existingServiceName})
	clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
	if !ok {
		log.Panicln("cannot cast to rbac config")
	}
	assert.Equal(t, model.ClusterRbacConfig.Type, config.Type, "ClusterRbacConfig type should be equal")
	assert.Equal(t, model.DefaultRbacConfigName, config.Name, "ClusterRbacConfig name should be equal")
	assert.Equal(t, model.ClusterRbacConfig.Group+model.IstioAPIGroupDomain, config.Group, "ClusterRbacConfig group should be equal")
	assert.Equal(t, model.ClusterRbacConfig.Version, config.Version, "ClusterRbacConfig version should be equal")
	assert.Equal(t, []string{onboardedServiceName, existingServiceName}, clusterRbacConfig.Inclusion.Services, "ClusterRbacConfig service list should be equal to expected")
}

func TestGetServiceList(t *testing.T) {
	onboardedServiceCopy := onboardedService.DeepCopy()
	onboardedServiceCopy.Name = "onboarded-service-copy"
	onboardedServiceCopyName := "onboarded-service-copy.test-namespace.svc.cluster.local"

	tests := []struct {
		name                 string
		inputServiceList     []*v1.Service
		expectedServiceArray []string
	}{
		{
			name:                 "test getting onboarded services",
			inputServiceList:     []*v1.Service{onboardedService},
			expectedServiceArray: []string{onboardedServiceName},
		},
		{
			name:                 "test getting mix of onboarded and not onboarded services",
			inputServiceList:     []*v1.Service{onboardedService, onboardedServiceCopy, notOnboardedService},
			expectedServiceArray: []string{onboardedServiceName, onboardedServiceCopyName},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(tt.inputServiceList, false)
			ret := c.getOnboardedServiceList()
			diff := compareServiceLists(tt.expectedServiceArray, ret)
			assert.Equal(t, []string{}, diff, "list should be equal to expected")
		})
	}
}

func createClusterRbacExclusionConfig(services []string) model.Config {
	return model.Config{
		ConfigMeta: model.ConfigMeta{
			Type:    model.ClusterRbacConfig.Type,
			Name:    model.DefaultRbacConfigName,
			Group:   model.ClusterRbacConfig.Group + model.IstioAPIGroupDomain,
			Version: model.ClusterRbacConfig.Version,
		},
		Spec: &v1alpha1.RbacConfig{
			Mode: v1alpha1.RbacConfig_ON_WITH_EXCLUSION,
			Exclusion: &v1alpha1.RbacConfig_Target{
				Services: services,
			},
			Inclusion: nil,
		},
	}
}

func TestSyncService(t *testing.T) {
	onboardedServiceCopy := onboardedService.DeepCopy()
	onboardedServiceCopy.Name = "onboarded-service-copy"
	onboardedServiceCopyName := "onboarded-service-copy.test-namespace.svc.cluster.local"

	notOnboardedServiceCopy := notOnboardedService.DeepCopy()
	notOnboardedServiceCopy.Name = "not-onboarded-service-copy"
	notOnboardedServiceCopy.Annotations = make(map[string]string)

	tests := []struct {
		name                   string
		inputServiceList       []*v1.Service
		inputClusterRbacConfig model.Config
		expectedServiceList    []string
		fake                   bool
	}{
		{
			name:                "Create: create ClusterRbacConfig when it does not exist with multiple new services",
			inputServiceList:    []*v1.Service{onboardedService, onboardedServiceCopy, notOnboardedService, notOnboardedServiceCopy},
			expectedServiceList: []string{onboardedServiceName, onboardedServiceCopyName},
		},
		{
			name:                   "Update: update ClusterRbacConfig when it exists with multiple services",
			inputServiceList:       []*v1.Service{onboardedService, onboardedServiceCopy, notOnboardedService, notOnboardedServiceCopy},
			inputClusterRbacConfig: newClusterRbacConfig([]string{onboardedServiceCopyName}),
			expectedServiceList:    []string{onboardedServiceCopyName, onboardedServiceName},
		},
		{
			name:                   "Update: update ClusterRbacConfig when it exists without an inclusion field",
			inputServiceList:       []*v1.Service{onboardedService, onboardedServiceCopy, notOnboardedService, notOnboardedServiceCopy},
			inputClusterRbacConfig: createClusterRbacExclusionConfig([]string{onboardedServiceCopyName}),
			expectedServiceList:    []string{onboardedServiceCopyName, onboardedServiceName},
		},
		{
			name:                   "Update: update ClusterRbacConfig when not onboarded service exists",
			inputServiceList:       []*v1.Service{onboardedService, notOnboardedService},
			inputClusterRbacConfig: newClusterRbacConfig([]string{onboardedServiceName, notOnboardedServiceName}),
			expectedServiceList:    []string{onboardedServiceName},
		},
		{
			name:                   "Delete: delete cluster rbacconfig if service is no longer onboarded",
			inputServiceList:       []*v1.Service{notOnboardedService},
			inputClusterRbacConfig: newClusterRbacConfig([]string{notOnboardedServiceName}),
			expectedServiceList:    []string{},
			fake:                   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(tt.inputServiceList, tt.fake)

			if tt.inputClusterRbacConfig.Spec != nil {
				_, err := c.configStoreCache.Create(tt.inputClusterRbacConfig)
				assert.Nil(t, err, "creating the ClusterRbacConfig should return nil")
			}

			err := c.sync()
			assert.Nil(t, err, "sync error should be nil")
			_, clusterRbacConfig := getClusterRbacConfig(c)
			diff := compareServiceLists(tt.expectedServiceList, clusterRbacConfig.Inclusion.Services)
			assert.Equal(t, []string{}, diff, "ClusterRbacConfig inclusion service list should be equal to the expected service list")
		})
	}
}

func TestResync(t *testing.T) {
	c := &Controller{
		queue:             workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		crcResyncInterval: time.Second * 1,
	}

	stopCh := make(chan struct{})
	go c.resync(stopCh)
	time.Sleep(time.Second * 2)
	close(stopCh)

	assert.Equal(t, 1, c.queue.Len(), "queue length should be 1")
	item, shutdown := c.queue.Get()
	assert.False(t, shutdown, "shutdown should be false")
	assert.Equal(t, 0, c.queue.Len(), "queue length should be 0")
	assert.Equal(t, queueKey, item, "key should be equal")
}

func TestCompareServiceLists(t *testing.T) {
	tests := []struct {
		name         string
		inputListA   []string
		inputListB   []string
		expectedList []string
	}{
		{
			name:         "test one item difference between arrays",
			inputListA:   []string{"one", "two", "three"},
			inputListB:   []string{"one", "three"},
			expectedList: []string{"two"},
		},
		{
			name:         "test array equality",
			inputListA:   []string{"one", "two", "three"},
			inputListB:   []string{"one", "two", "three"},
			expectedList: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list := compareServiceLists(tt.inputListA, tt.inputListB)
			assert.Equal(t, tt.expectedList, list, "expected array to equal expected")
		})
	}
}

func TestRemoveIndexElement(t *testing.T) {
	tests := []struct {
		name          string
		inputList     []string
		indexToRemove int
		expectedList  []string
	}{
		{
			name:          "test removing index from array",
			inputList:     []string{"one", "two", "three"},
			indexToRemove: 1,
			expectedList:  []string{"one", "three"},
		},
		{
			name:          "test removing from empty array",
			inputList:     []string{},
			indexToRemove: 1,
			expectedList:  []string{},
		},
		{
			name:          "test removing negative index",
			inputList:     []string{"one"},
			indexToRemove: -1,
			expectedList:  []string{"one"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list := removeIndexElement(tt.inputList, tt.indexToRemove)
			assert.Equal(t, tt.expectedList, list, "expected array to equal expected")
		})
	}
}
