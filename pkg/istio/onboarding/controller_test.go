package onboarding

import (
	"log"
	"testing"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	fcache "k8s.io/client-go/tools/cache/testing"

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

func createClusterRbacConfig(services ...string) *v1alpha1.RbacConfig {
	if services[0] == "" {
		return &v1alpha1.RbacConfig{
			Inclusion: &v1alpha1.RbacConfig_Target{},
		}
	}

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

func TestAddService(t *testing.T) {
	crcMgr := &Controller{}

	tests := []struct {
		name              string
		inputServices     []string
		clusterRbacConfig *v1alpha1.RbacConfig
		expectedArray     []string
	}{
		{
			name:              "test adding new service",
			inputServices:     []string{onboardedServiceName},
			clusterRbacConfig: createClusterRbacConfig(""),
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
			crcMgr.addServices(tt.inputServices, tt.clusterRbacConfig)
			assert.Equal(t, tt.expectedArray, tt.clusterRbacConfig.Inclusion.Services, "ClusterRbacConfig service list should contain expected services")
		})
	}
}

func TestDeleteService(t *testing.T) {
	crcMgr := &Controller{}

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
			clusterRbacConfig: createClusterRbacConfig(onboardedServiceName, "service-two.test-namespace.svc.cluster.local"),
			inputArray:        []string{onboardedServiceName},
			expectedArray:     []string{"service-two.test-namespace.svc.cluster.local"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crcMgr.deleteServices(tt.inputArray, tt.clusterRbacConfig)
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
			inputAndExpectedArray: []string{onboardedServiceName, "service-two.test-namespace.svc.cluster.local"},
			expectedErr:           nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crcMgr := newFakeController(nil, false)
			err := crcMgr.createClusterRbacConfig(tt.inputAndExpectedArray)
			assert.Equal(t, tt.expectedErr, err, "error")

			if err == nil {
				config := crcMgr.store.Get(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, "")
				assert.Equal(t, model.ClusterRbacConfig.Type, config.Type, "type should be equal")
				assert.Equal(t, model.DefaultRbacConfigName, config.Name, "name")
				//assert.Equal(t, model.ClusterRbacConfig.Group, config.Group, "group")
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

func TestFindDiff(t *testing.T) {
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
			crcMgr := newFakeController(tt.inputServiceList, false)
			ret := crcMgr.getServiceList()
			diff := findArrayDiff(tt.expectedServiceArray, ret)
			assert.Equal(t, []string{}, diff, "list should be equal")
		})
	}
}

func newFakeController(services []*v1.Service, fakeStore bool) *Controller {
	c := &Controller{}
	if fakeStore {
		c.store = GetFakeStub()
	} else {
		configDescriptor := model.ConfigDescriptor{
			model.ClusterRbacConfig,
		}

		configStore := memory.Make(configDescriptor)
		ctrl := memory.NewController(configStore)
		c.store = ctrl
	}

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

func TestSyncServiceTwo(t *testing.T) {
	existingServiceTwo := onboardedService.DeepCopy()
	existingServiceTwo.Name = "service-two"

	existingServiceThree := onboardedService.DeepCopy()
	existingServiceThree.Name = "service-three"
	existingServiceThree.Annotations[authzEnabledAnnotation] = "false"

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
			inputServiceList:       []*v1.Service{onboardedService, existingServiceTwo, existingServiceThree, existingServiceFour},
			inputClusterRbacConfig: nil,
			expectedServiceList:    []string{onboardedServiceName, "service-two.test-namespace.svc.cluster.local"},
			fake:                   false,
		},
		{
			name:                   "update cluster rbacconfig if service exists",
			inputServiceList:       []*v1.Service{onboardedService, existingServiceTwo, existingServiceThree, existingServiceFour},
			inputClusterRbacConfig: createClusterRbacConfigModel("service-two.test-namespace.svc.cluster.local"),
			expectedServiceList:    []string{"service-two.test-namespace.svc.cluster.local", onboardedServiceName},
			fake:                   false,
		},
		{
			name:                   "delete cluster rbacconfig if service exists",
			inputServiceList:       []*v1.Service{existingServiceThree},
			inputClusterRbacConfig: createClusterRbacConfigModel("service-three.test-namespace.svc.cluster.local"),
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

type StubAdapter struct {
	model.ConfigStore
}

func (cr *StubAdapter) ConfigDescriptor() model.ConfigDescriptor {
	return model.ConfigDescriptor{
		model.ServiceRole,
		model.ServiceRoleBinding,
		model.ClusterRbacConfig,
	}
}

func (cr *StubAdapter) Get(typ, name, namespace string) *model.Config {
	log.Println("inside get")
	return createClusterRbacConfigModel(onboardedServiceName)
}

func (cr *StubAdapter) Delete(typ, name, namespace string) error {
	log.Println("inside of custom delete")
	return nil
}

func GetFakeStub() model.ConfigStoreCache {
	configDescriptor := model.ConfigDescriptor{
		model.ServiceRole,
		model.ServiceRoleBinding,
		model.ClusterRbacConfig,
	}
	store := memory.Make(configDescriptor)

	foo := &StubAdapter{store}
	foo.Delete("", "", "")
	controller := memory.NewController(foo)
	return controller
}
