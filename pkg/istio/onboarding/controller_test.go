package onboarding

import (
	"log"
	"testing"

	"fmt"
	"github.com/stretchr/testify/assert"
	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/config/memory"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	fcache "k8s.io/client-go/tools/cache/testing"
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

// Status: Done
func TestAddService(t *testing.T) {
	crcMgr := &Controller{}

	newService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-service",
			Namespace: "test-namespace",
		},
	}
	existingService := newService.DeepCopy()
	existingService.Name = "existing-service"

	emptyClusterRbacConfig := createClusterRbacConfig("")
	existingClusterRbacConfigTwo := createClusterRbacConfig("existing-service.test-namespace.svc.cluster.local")

	tests := []struct {
		name              string
		inputServices     []string
		clusterRbacConfig *v1alpha1.RbacConfig
		expectedArray     []string
	}{
		{
			name:              "test adding new service",
			inputServices:     []string{"new-service.test-namespace.svc.cluster.local"},
			clusterRbacConfig: emptyClusterRbacConfig,
			expectedArray:     []string{"new-service.test-namespace.svc.cluster.local"},
		},
		{
			name:              "test adding existing service",
			inputServices:     []string{"new-service.test-namespace.svc.cluster.local"},
			clusterRbacConfig: existingClusterRbacConfigTwo,
			expectedArray:     []string{"existing-service.test-namespace.svc.cluster.local", "new-service.test-namespace.svc.cluster.local"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crcMgr.addServices(tt.inputServices, tt.clusterRbacConfig)
			assert.Equal(t, tt.expectedArray, tt.clusterRbacConfig.Inclusion.Services, "ClusterRbacConfig service list should contain expected services")
		})
	}
}

// Status: Done
func TestDeleteService(t *testing.T) {
	crcMgr := &Controller{}

	initialClusterRbacConfig := createClusterRbacConfig("service.test-namespace.svc.cluster.local")
	existingClusterRbacConfig := createClusterRbacConfig("service.test-namespace.svc.cluster.local", "service-two.test-namespace.svc.cluster.local")
	//clusterRbacConfigTwo := createClusterRbacConfig("service-two.test-namespace.svc.cluster.local")

	tests := []struct {
		name              string
		clusterRbacConfig *v1alpha1.RbacConfig
		inputArray        []string
		expectedArray     []string
	}{
		{
			name:              "test deleting service",
			clusterRbacConfig: initialClusterRbacConfig,
			inputArray:        []string{"service.test-namespace.svc.cluster.local"},
			expectedArray:     []string{},
		},
		{
			name:              "test deleting existing service",
			clusterRbacConfig: existingClusterRbacConfig,
			inputArray:        []string{"service.test-namespace.svc.cluster.local"},
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
			inputAndExpectedArray: []string{"service.test-namespace.svc.cluster.local", "service-two.test-namespace.svc.cluster.local"},
			expectedErr:           nil,
		},
		//{
		//	name:              "test deleting existing service",
		//},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crcMgr := getNewController()
			err := crcMgr.createClusterRbacConfig(tt.inputAndExpectedArray)
			assert.Equal(t, tt.expectedErr, err, "error")

			if err == nil {
				config := crcMgr.store.Get(model.ClusterRbacConfig.Type, "default", "")
				assert.Equal(t, model.ClusterRbacConfig.Type, config.Type, "type should be equal")
				assert.Equal(t, model.DefaultRbacConfigName, config.Name, "name")
				assert.Equal(t, model.ClusterRbacConfig.Group, config.Group, "group")
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

func getNewController() *Controller {
	configDescriptor := model.ConfigDescriptor{
		model.ClusterRbacConfig,
	}

	configStore := memory.Make(configDescriptor)
	ctrl := memory.NewController(configStore)
	crcMgr := &Controller{store: ctrl}
	return crcMgr
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
			list := findDiff(tt.inputListA, tt.inputListB)
			assert.Equal(t, tt.expectedList, list, "expected list to match")
		})
	}
}

func TestGetServiceList(t *testing.T) {
	newService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-service",
			Namespace: "test-namespace",
			Annotations: map[string]string{
				authzEnabledAnnotation: "true",
			},
		},
	}
	secondService := newService.DeepCopy()
	secondService.Name = "second-service"

	notOnboardedService := newService.DeepCopy()
	notOnboardedService.Name = "not-onboarded"
	notOnboardedService.Annotations[authzEnabledAnnotation] = "false"

	tests := []struct {
		name                 string
		inputServiceList     []*v1.Service
		expectedServiceArray []string
	}{
		{
			name:                 "test get service list",
			inputServiceList:     []*v1.Service{newService},
			expectedServiceArray: []string{"new-service.test-namespace.svc.cluster.local"},
		},
		{
			name:                 "test get service list 2",
			inputServiceList:     []*v1.Service{newService, secondService, notOnboardedService},
			expectedServiceArray: []string{"new-service.test-namespace.svc.cluster.local", "second-service.test-namespace.svc.cluster.local"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crcMgr := NewFakeIndexInformerController(tt.inputServiceList)
			ret := crcMgr.getServiceList()
			assert.Equal(t, tt.expectedServiceArray, ret, "list should be equal")
		})
	}
}

func NewFakeIndexInformerController(services []*v1.Service) *Controller {
	crcMgr := getNewController()
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
	crcMgr.serviceIndexInformer = fakeIndexInformer
	crcMgr.dnsSuffix = "svc.cluster.local"
	return crcMgr
}

// Service create
// 1. If service annotation exists and is set to true:
//    - Create onboarding if it does exist - done
//    - Update onboarding with new service if it is not already there - done
// 2. If service annotation exists and is set to false OR it does not have annotation:
//    - Delete service from clusterrbaccconfig
//    - Delete onboarding if no services left - done

// Service Update - Same as create

// Service Delete
// 1. If service annotation exists and is set to true:
// - Delete service from clusterrbaccconfig
// - Delete onboarding if no services left

func TestSyncServiceTwo(t *testing.T) {
	existingService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "test-namespace",
			Annotations: map[string]string{
				authzEnabledAnnotation: "true",
			},
		},
	}
	existingServiceTwo := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service-two",
			Namespace: "test-namespace",
			Annotations: map[string]string{
				authzEnabledAnnotation: "true",
			},
		},
	}

	inputClusterRbacConfig := createClusterRbacConfigModel("service-two.test-namespace.svc.cluster.local")

	tests := []struct {
		name                   string
		inputServiceList       []*v1.Service
		inputClusterRbacConfig *model.Config
	}{
		{
			name:                   "create cluster rbacconfig when store is empty",
			inputServiceList:       []*v1.Service{existingService, existingServiceTwo},
			inputClusterRbacConfig: inputClusterRbacConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crcMgr := NewFakeIndexInformerController(tt.inputServiceList)

			if tt.inputClusterRbacConfig != nil {
				_, err := crcMgr.store.Create(*tt.inputClusterRbacConfig)
				assert.Nil(t, err, "create should be nil")
			}

			err := crcMgr.sync()
			log.Println("err:", err)
			assert.Equal(t, nil, err)

			fmt.Println(crcMgr.store.Get(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, ""))
		})
	}
}

// TODO, look into istio library
func TestSyncService(t *testing.T) {
	existingService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "test-namespace",
			Annotations: map[string]string{
				"authz.istio.io/enabled": "true",
			},
		},
	}

	existingServiceTwo := existingService.DeepCopy()
	existingServiceTwo.Name = "service-two"

	existingServiceThree := existingService.DeepCopy()
	existingServiceThree.Annotations = map[string]string{
		"authz.istio.io/enabled": "false",
	}

	//inputClusterRbacConfig := createClusterRbacConfigModel("service.test-namespace.svc.cluster.local")

	inputClusterRbacConfigTwo := createClusterRbacConfigModel("service.test-namespace.svc.cluster.local")
	//inputClusterRbacConfigTwo.Namespace = "default"

	//inputClusterRbacConfigThree := createClusterRbacConfigModel("service.test-namespace.svc.cluster.local", "service-two.test-namespace.svc.cluster.local")

	tests := []struct {
		name         string
		inputService *v1.Service
		//inputDelta             cache.DeltaType
		inputClusterRbacConfig *model.Config
		expectedError          error
		expectedArray          []string
	}{
		//{
		//	name:                   "add a service with authz annotation set to true when cluster rbac config does not exist",
		//	inputServices:           existingService,
		//	inputDelta:             cache.Added,
		//	inputClusterRbacConfig: nil,
		//	expectedError:          nil,
		//	expectedArray:          []string{"service.test-namespace.svc.cluster.local"},
		//},
		//{
		//	name:                   "add a service with authz annotation set to true when cluster rbac config exists",
		//	inputServices:           existingServiceTwo,
		//	inputDelta:             cache.Added,
		//	inputClusterRbacConfig: inputClusterRbacConfig,
		//	expectedError:          nil,
		//	expectedArray:          []string{"service.test-namespace.svc.cluster.local", "service-two.test-namespace.svc.cluster.local"},
		//},
		{
			name:         "delete a service with authz annotation set to false when cluster rbac config exists with one entry, delete cluster rbac config",
			inputService: existingServiceThree,
			//inputDelta:             cache.Added,
			inputClusterRbacConfig: inputClusterRbacConfigTwo,
			expectedError:          nil,
			expectedArray:          []string{},
		},
		//{
		//	name:                   "delete a service with authz annotation set to false when cluster rbac config exists",
		//	inputServices:           existingServiceThree,
		//	inputDelta:             cache.Added,
		//	inputClusterRbacConfig: inputClusterRbacConfigThree,
		//	expectedError:          nil,
		//	expectedArray:          []string{"service-two.test-namespace.svc.cluster.local"},
		//},

		//{
		//	name:                   "add a service when there is only one entry in the cluster rbac config",
		//	inputServices:           existingService,
		//	inputDelta:             cache.Deleted,
		//	inputClusterRbacConfig: inputClusterRbacConfig,
		//	expectedError:          nil,
		//	expectedArray:          []string{""},
		//},
		//{
		//	name:                   "test delete a service when cluster rbac config already exists",
		//	inputServices:           existingServiceTwo,
		//	inputDelta:             cache.Deleted,
		//	inputClusterRbacConfig: inputClusterRbacConfigTwo,
		//	expectedError:          nil,
		//	expectedArray:          []string{"service.test-namespace.svc.cluster.local"},
		//},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//crcMgr := initCrcMgr(tt.inputClusterRbacConfig)
			//
			//err := crcMgr.syncClusterRbacConfig(tt.inputDelta, tt.inputService)
			//assert.Equal(t, tt.expectedError, err)
			//
			//clusterRbacConfig := getClusterRbacConfig(crcMgr)
			//
			//if len(tt.expectedArray) == 0 {
			//	assert.Nil(t, clusterRbacConfig, "should be nil")
			//} else {
			//	assert.Equal(t, tt.expectedArray, clusterRbacConfig.Inclusion.Services, "clusterRbacConfig service list should contain expected services")
			//}
		})
	}
}

func createClusterRbacConfigModel(services ...string) *model.Config {
	return &model.Config{
		ConfigMeta: model.ConfigMeta{
			Type: model.ClusterRbacConfig.Type,
			Name: "default",
			//Namespace: "default",
			Group:   model.ClusterRbacConfig.Group + model.IstioAPIGroupDomain,
			Version: model.ClusterRbacConfig.Version,
		},
		Spec: &v1alpha1.RbacConfig{
			Inclusion: &v1alpha1.RbacConfig_Target{
				Services: services,
			},
		},
	}
}

//
//func initCrcMgr(clusterRbacConfig *model.Config) *Controller {
//	//configDescriptor := model.ConfigDescriptor{
//	//	model.ServiceRole,
//	//	model.ServiceRoleBinding,
//	//	model.ClusterRbacConfig,
//	//}
//
//	//store := memory.Make(configDescriptor)
//	foo := &StubAdapter{}
//	controller := memory.NewController(foo)
//	log.Println("foo")
//	foo.Delete("", "", "")
//	log.Println("controller")
//	controller.Delete("", "", "")
//
//	crcMgr := NewClusterRbacConfigMgr(controller, "svc.cluster.local")
//
//	log.Println("crc", clusterRbacConfig)
//
//	//if clusterRbacConfig != nil {
//	//	_, err := crcMgr.store.Create(*clusterRbacConfig)
//	//	if err != nil {
//	//		log.Panicln("err creating:", err)
//	//	}
//	//}
//	return crcMgr
//}
//
//func getClusterRbacConfig(crcMgr *Controller) *v1alpha1.RbacConfig {
//	config := crcMgr.store.Get(model.ClusterRbacConfig.Type, "default", "")
//	if config == nil {
//		return nil
//	}
//
//	clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
//	if !ok {
//		log.Panicln("cannot cast to rbac config")
//	}
//	return clusterRbacConfig
//}
//
////type Foo struct {
////	adapter model.ConfigStore
////}
////
////func NewFoo(a model.ConfigStore) *Foo {
////	return &Foo{adapter: a}
////}
//
//type StubAdapter struct {
//	model.ConfigStore
//}
//
//func (cr *StubAdapter) ConfigDescriptor() model.ConfigDescriptor {
//	return model.ConfigDescriptor{
//		model.ServiceRole,
//		model.ServiceRoleBinding,
//		model.ClusterRbacConfig,
//	}
//}
//
//func (cr *StubAdapter) Get(typ, name, namespace string) *model.Config {
//	log.Println("inside get")
//	return createClusterRbacConfigModel("service.test-namespace.svc.cluster.local")
//}
//
//func (cr *StubAdapter) Delete(typ, name, namespace string) error {
//	log.Println("inside of custom delete")
//	return nil
//}
//
//func TestFooBar(t *testing.T) {
//	configDescriptor := model.ConfigDescriptor{
//		model.ServiceRole,
//		model.ServiceRoleBinding,
//		model.ClusterRbacConfig,
//	}
//	store := memory.Make(configDescriptor)
//
//	foo := &StubAdapter{store}
//	foo.Delete("", "", "")
//	controller := memory.NewController(foo)
//	controller.Delete("", "", "")
//}
