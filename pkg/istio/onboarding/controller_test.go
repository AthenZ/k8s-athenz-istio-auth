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

func getClusterRbacConfig(c *Controller) (*model.Config, *v1alpha1.RbacConfig) {
	config := c.store.Get(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, "")
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

	store := memory.Make(configDescriptor)
	if fake {
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

	c := NewController(configStoreCache, dnsSuffix, fakeIndexInformer)
	assert.Equal(t, dnsSuffix, c.dnsSuffix, "dns suffix should be equal")
	assert.Equal(t, fakeIndexInformer, c.serviceIndexInformer, "service index informer pointer should be equal")
	assert.Equal(t, configStoreCache, c.store, "config store cache pointer should be equal")
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
			name:             "test processing a service object",
			inputObject:      onboardedService,
			expectedQueueLen: 1,
			expectedKeyName:  "test-namespace/onboarded-service",
		},
		{
			name:             "test processing a non service object",
			inputObject:      nil,
			expectedQueueLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c.processEvent(cache.MetaNamespaceKeyFunc, onboardedService)
			assert.Equal(t, tt.expectedQueueLen, c.queue.Len(), "expected queue length should be equal")

			if tt.expectedQueueLen > 0 {
				item, shutdown := c.queue.Get()
				assert.Equal(t, tt.expectedKeyName, item, "expected key name should be equal")
				assert.Equal(t, false, shutdown, "shutdown should be false")
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
			name:              "test adding new service to ClusterRbacConfig",
			inputServices:     []string{onboardedServiceName},
			clusterRbacConfig: createClusterRbacConfig(),
			expectedArray:     []string{onboardedServiceName},
		},
		{
			name:              "test adding existing service to ClusterRbacConfig",
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
			name:              "test deleting service from ClusterRbacConfig",
			clusterRbacConfig: createClusterRbacConfig(onboardedServiceName),
			inputArray:        []string{onboardedServiceName},
			expectedArray:     []string{},
		},
		{
			name:              "test deleting existing service from ClusterRbacConfig",
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

func TestCreateClusterRbacConfig(t *testing.T) {
	c := newFakeController(nil, false)
	err := c.createClusterRbacConfig([]string{onboardedServiceName, existingServiceName})
	assert.Nil(t, err, "error should be equal")

	config, clusterRbacConfig := getClusterRbacConfig(c)
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
			ret := c.getServiceList()
			diff := findArrayDiff(tt.expectedServiceArray, ret)
			assert.Equal(t, []string{}, diff, "list should be equal")
		})
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
		inputClusterRbacConfig *model.Config
		expectedServiceList    []string
		fake                   bool
	}{
		{
			name:                   "Create: create ClusterRbacConfig when it does not exist with multiple new services",
			inputServiceList:       []*v1.Service{onboardedService, onboardedServiceCopy, notOnboardedService, notOnboardedServiceCopy},
			inputClusterRbacConfig: nil,
			expectedServiceList:    []string{onboardedServiceName, onboardedServiceCopyName},
		},
		{
			name:                   "Update: update ClusterRbacConfig when it exists with multiple services",
			inputServiceList:       []*v1.Service{onboardedService, onboardedServiceCopy, notOnboardedService, notOnboardedServiceCopy},
			inputClusterRbacConfig: createClusterRbacConfigModel(onboardedServiceCopyName),
			expectedServiceList:    []string{onboardedServiceCopyName, onboardedServiceName},
		},
		{
			name:                   "Delete: delete cluster rbacconfig if service is no longer onboarded",
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
				assert.Nil(t, err, "creating the ClusterRbacConfig should return nil")
			}

			err := c.sync()
			assert.Nil(t, err, "sync error should be nil")
			_, clusterRbacConfig := getClusterRbacConfig(c)
			diff := findArrayDiff(tt.expectedServiceList, clusterRbacConfig.Inclusion.Services)
			assert.Equal(t, []string{}, diff, "ClusterRbacConfig inclusion service list should be equal to the expected service list")
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
			list := findArrayDiff(tt.inputListA, tt.inputListB)
			assert.Equal(t, tt.expectedList, list, "expected array to equal expected")
		})
	}
}
