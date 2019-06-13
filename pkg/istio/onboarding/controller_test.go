package onboarding

import (
	"log"
	"testing"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/config/memory"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	fcache "k8s.io/client-go/tools/cache/testing"

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
	clusterRbacConfig := createClusterRbacConfig([]string{onboardedServiceName})
	return &clusterRbacConfig
}

func (cs *fakeConfigStore) Delete(typ, name, namespace string) error {
	return nil
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
			clusterRbacConfig: createClusterRbacSpec(nil),
			expectedArray:     []string{onboardedServiceName},
		},
		{
			name:              "test adding existing service to ClusterRbacConfig",
			inputServices:     []string{onboardedServiceName},
			clusterRbacConfig: createClusterRbacSpec([]string{existingServiceName}),
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
			clusterRbacConfig: createClusterRbacSpec(nil),
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
			clusterRbacConfig: createClusterRbacSpec([]string{onboardedServiceName}),
			inputArray:        []string{onboardedServiceName},
			expectedArray:     []string{},
		},
		{
			name:              "test deleting existing service from ClusterRbacConfig",
			clusterRbacConfig: createClusterRbacSpec([]string{onboardedServiceName, existingServiceName}),
			inputArray:        []string{onboardedServiceName},
			expectedArray:     []string{existingServiceName},
		},
		{
			name:              "test deleting empty input array to ClusterRbacConfig",
			clusterRbacConfig: createClusterRbacSpec([]string{existingServiceName}),
			inputArray:        []string{},
			expectedArray:     []string{existingServiceName},
		},
		{
			name:              "test deleting empty service which does not exist in the ClusterRbacConfig",
			clusterRbacConfig: createClusterRbacSpec([]string{existingServiceName}),
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
	config := createClusterRbacConfig([]string{onboardedServiceName, existingServiceName})
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
			inputClusterRbacConfig: createClusterRbacConfig([]string{onboardedServiceCopyName}),
			expectedServiceList:    []string{onboardedServiceCopyName, onboardedServiceName},
		},
		{
			name:                   "Update: update ClusterRbacConfig when it exists without an inclusion field",
			inputServiceList:       []*v1.Service{onboardedService, onboardedServiceCopy, notOnboardedService, notOnboardedServiceCopy},
			inputClusterRbacConfig: createClusterRbacExclusionConfig([]string{onboardedServiceCopyName}),
			expectedServiceList:    []string{onboardedServiceCopyName, onboardedServiceName},
		},
		{
			name:                   "Delete: delete cluster rbacconfig if service is no longer onboarded",
			inputServiceList:       []*v1.Service{notOnboardedService},
			inputClusterRbacConfig: createClusterRbacConfig([]string{notOnboardedServiceName}),
			expectedServiceList:    []string{},
			fake:                   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(tt.inputServiceList, tt.fake)

			if tt.inputClusterRbacConfig.Spec != nil {
				_, err := c.store.Create(tt.inputClusterRbacConfig)
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
