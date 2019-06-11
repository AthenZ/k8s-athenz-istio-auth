package onboarding

import (
	"log"
	"testing"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	fcache "k8s.io/client-go/tools/cache/testing"
	"k8s.io/client-go/util/workqueue"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/config/memory"
	"istio.io/istio/pilot/pkg/model"

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
	return createClusterRbacConfigModel(onboardedServiceName)
}

func (cs *fakeConfigStore) Delete(typ, name, namespace string) error {
	return nil
}

func createClusterRbacConfig(services ...string) *v1alpha1.RbacConfig {
	return &v1alpha1.RbacConfig{
		Inclusion: &v1alpha1.RbacConfig_Target{
			Services: services,
		},
	}
}

func createClusterRbacConfigModel(services ...string) *model.Config {
	return &model.Config{
		ConfigMeta: model.ConfigMeta{
			Type:    model.ClusterRbacConfig.Type,
			Name:    model.DefaultRbacConfigName,
			Group:   model.ClusterRbacConfig.Group + model.IstioAPIGroupDomain,
			Version: model.ClusterRbacConfig.Version,
		},
		Spec: createClusterRbacConfig(services...),
	}
}

func getClusterRbacConfig(crcMgr *Controller) *v1alpha1.RbacConfig {
	config := crcMgr.store.Get(model.ClusterRbacConfig.Type, "default", "")
	if config == nil {
		return nil
	}

	clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
	if !ok {
		log.Panicln("cannot cast to rbac config")
	}
	return clusterRbacConfig
}

func newFakeController(services []*v1.Service, fakeStore bool) *Controller {
	c := &Controller{}
	configDescriptor := model.ConfigDescriptor{
		model.ClusterRbacConfig,
	}

	store := memory.Make(configDescriptor)
	if fakeStore {
		store = &fakeConfigStore{store}
	}
	c.store = memory.NewController(store)

	source := fcache.NewFakeControllerSource()
	for _, service := range services {
		source.Add(service)
	}
	fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
	stopChan := make(chan struct{})
	go fakeIndexInformer.Run(stopChan)

	if !cache.WaitForCacheSync(stopChan, fakeIndexInformer.HasSynced) {
		panic("timed out waiting for cache to sync")
	}
	c.serviceIndexInformer = fakeIndexInformer
	c.dnsSuffix = "svc.cluster.local"

	return c
}

func TestNewController(t *testing.T) {
	configDescriptor := model.ConfigDescriptor{
		model.ClusterRbacConfig,
	}

	source := fcache.NewFakeControllerSource()
	fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
	store := memory.Make(configDescriptor)
	cache := memory.NewController(store)

	c := NewController(cache, "svc.cluster.local", fakeIndexInformer)
	assert.Equal(t, "svc.cluster.local", c.dnsSuffix, "should be equal")
	assert.Equal(t, fakeIndexInformer, c.serviceIndexInformer, "should be equal")
	assert.Equal(t, cache, c.store, "should be equal")
}

func TestProcessEvent(t *testing.T) {
	c := &Controller{queue: workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())}

	tests := []struct {
		name             string
		inputObject      interface{}
		expectedQueueLen int
		expectedKeyName  string
	}{
		{
			name:             "test adding new service",
			inputObject:      onboardedService,
			expectedQueueLen: 1,
			expectedKeyName:  "test-namespace/onboarded-service",
		},
		{
			name:             "test adding existing service",
			inputObject:      nil,
			expectedQueueLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c.processEvent(cache.MetaNamespaceKeyFunc, onboardedService)
			assert.Equal(t, tt.expectedQueueLen, c.queue.Len(), "should be equal")
			if tt.expectedQueueLen > 0 {
				item, shutdown := c.queue.Get()
				assert.Equal(t, tt.expectedKeyName, item, "key should be equal")
				assert.Equal(t, false, shutdown, "should not be shutdown")
			}
		})
	}

	c.queue.ShutDown()
}

func TestAddService(t *testing.T) {
	c := &Controller{}

	tests := []struct {
		name              string
		inputServices     []string
		clusterRbacConfig *v1alpha1.RbacConfig
		expectedArray     []string
	}{
		{
			name:              "test adding new service",
			inputServices:     []string{onboardedServiceName},
			clusterRbacConfig: createClusterRbacConfig(),
			expectedArray:     []string{onboardedServiceName},
		},
		{
			name:              "test adding existing service",
			inputServices:     []string{onboardedServiceName},
			clusterRbacConfig: createClusterRbacConfig(existingServiceName),
			expectedArray:     []string{existingServiceName, onboardedServiceName},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c.addServices(tt.inputServices, tt.clusterRbacConfig)
			assert.Equal(t, tt.expectedArray, tt.clusterRbacConfig.Inclusion.Services, "ClusterRbacConfig service list should contain expected services")
		})
	}
}

func TestDeleteService(t *testing.T) {
	c := &Controller{}

	tests := []struct {
		name              string
		clusterRbacConfig *v1alpha1.RbacConfig
		inputArray        []string
		expectedArray     []string
	}{
		{
			name:              "test deleting service",
			clusterRbacConfig: createClusterRbacConfig(onboardedServiceName),
			inputArray:        []string{onboardedServiceName},
			expectedArray:     []string{},
		},
		{
			name:              "test deleting existing service",
			clusterRbacConfig: createClusterRbacConfig(onboardedServiceName, existingServiceName),
			inputArray:        []string{onboardedServiceName},
			expectedArray:     []string{existingServiceName},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c.deleteServices(tt.inputArray, tt.clusterRbacConfig)
			assert.Equal(t, tt.expectedArray, tt.clusterRbacConfig.Inclusion.Services, "ClusterRbacConfig service list should contain expected services")
		})
	}
}

// Status: In progress, use Mock for the error Create case
func TestCreateClusterRbacConfig(t *testing.T) {
	tests := []struct {
		name                  string
		inputAndExpectedArray []string
		expectedErr           error
	}{
		{
			name:                  "test deleting service",
			inputAndExpectedArray: []string{onboardedServiceName, existingServiceName},
			expectedErr:           nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(nil, false)
			err := c.createClusterRbacConfig(tt.inputAndExpectedArray)
			assert.Equal(t, tt.expectedErr, err, "error")

			if err == nil {
				config := c.store.Get(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, "")
				assert.Equal(t, model.ClusterRbacConfig.Type, config.Type, "type should be equal")
				assert.Equal(t, model.DefaultRbacConfigName, config.Name, "name")
				assert.Equal(t, model.ClusterRbacConfig.Group+model.IstioAPIGroupDomain, config.Group, "group")
				assert.Equal(t, model.ClusterRbacConfig.Version, config.Version)

				clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
				if !ok {
					t.Error("could not cast to clusterRbacConfig")
				}
				assert.Equal(t, tt.inputAndExpectedArray, clusterRbacConfig.Inclusion.Services, "services")
			}
		})
	}
}

func TestGetServiceList(t *testing.T) {
	secondService := onboardedService.DeepCopy()
	secondService.Name = "second-service"

	tests := []struct {
		name                 string
		inputServiceList     []*v1.Service
		expectedServiceArray []string
	}{
		{
			name:                 "test get service list",
			inputServiceList:     []*v1.Service{onboardedService},
			expectedServiceArray: []string{onboardedServiceName},
		},
		{
			name:                 "test get service list 2",
			inputServiceList:     []*v1.Service{onboardedService, secondService, notOnboardedService},
			expectedServiceArray: []string{onboardedServiceName, "second-service.test-namespace.svc.cluster.local"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(tt.inputServiceList, false)
			ret := c.getServiceList()
			diff := findArrayDiff(tt.expectedServiceArray, ret)
			assert.Equal(t, []string{}, diff, "list should be equal")
		})
	}
}

// TODO, add error cases as well
// Sync test case
// Create (cluster rbac config does not exist:
//   1. Mix of services with and without annotation set to true
//
// Update (cluster rbac config exists with multiple services in it):
//   1. Mix of services with and without annotation set to true
//
// Delete:
//   1. No more services exists
//   2. No more services which are onboarded
//

func TestSyncService(t *testing.T) {
	existingServiceTwo := onboardedService.DeepCopy()
	existingServiceTwo.Name = "service-two"

	existingServiceFour := onboardedService.DeepCopy()
	existingServiceFour.Name = "service-four"
	existingServiceFour.Annotations = make(map[string]string)

	tests := []struct {
		name                   string
		inputServiceList       []*v1.Service
		inputClusterRbacConfig *model.Config
		expectedServiceList    []string
		fake                   bool
	}{
		{
			name:                   "Create: create cluster rbacconfig when it does not exist with multiple new services",
			inputServiceList:       []*v1.Service{onboardedService, existingServiceTwo, notOnboardedService, existingServiceFour},
			inputClusterRbacConfig: nil,
			expectedServiceList:    []string{onboardedServiceName, "service-two.test-namespace.svc.cluster.local"},
			fake:                   false,
		},
		{
			name:                   "update cluster rbacconfig if service exists",
			inputServiceList:       []*v1.Service{onboardedService, existingServiceTwo, notOnboardedService, existingServiceFour},
			inputClusterRbacConfig: createClusterRbacConfigModel("service-two.test-namespace.svc.cluster.local"),
			expectedServiceList:    []string{"service-two.test-namespace.svc.cluster.local", onboardedServiceName},
			fake:                   false,
		},
		{
			name:                   "delete cluster rbacconfig if service exists",
			inputServiceList:       []*v1.Service{notOnboardedService},
			inputClusterRbacConfig: createClusterRbacConfigModel(notOnboardedServiceName),
			expectedServiceList:    []string{},
			fake:                   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(tt.inputServiceList, tt.fake)

			if tt.inputClusterRbacConfig != nil {
				_, err := c.store.Create(*tt.inputClusterRbacConfig)
				assert.Nil(t, err, "create should be nil")
			}

			// TODO, add tests for error cases
			err := c.sync()
			assert.Equal(t, nil, err)

			if len(tt.expectedServiceList) > 0 {
				clusterRbacConfig := getClusterRbacConfig(c)
				diff := findArrayDiff(tt.expectedServiceList, clusterRbacConfig.Inclusion.Services)
				assert.Equal(t, []string{}, diff, "diff should be equal")
			}
		})
	}
}

func TestFindArrayDiff(t *testing.T) {
	tests := []struct {
		name         string
		inputListA   []string
		inputListB   []string
		expectedList []string
	}{
		{
			name:         "test list difference",
			inputListA:   []string{"one", "two", "three"},
			inputListB:   []string{"one", "three"},
			expectedList: []string{"two"},
		},
		{
			name:         "test list difference 2",
			inputListA:   []string{"one", "two", "three"},
			inputListB:   []string{"one", "two", "three"},
			expectedList: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list := findArrayDiff(tt.inputListA, tt.inputListB)
			assert.Equal(t, tt.expectedList, list, "expected list to match")
		})
	}
}
