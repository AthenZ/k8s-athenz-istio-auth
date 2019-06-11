package onboarding

import (
	"log"
	"testing"

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
	existingService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "test-namespace",
			Annotations: map[string]string{
				authzEnabledAnnotation: "true",
			},
		},
	}
	existingServiceTwo := existingService.DeepCopy()
	existingServiceTwo.Name = "service-two"

	existingServiceThree := existingService.DeepCopy()
	existingServiceThree.Name = "service-three"
	existingServiceThree.Annotations[authzEnabledAnnotation] = "false"

	existingServiceFour := existingService.DeepCopy()
	existingServiceFour.Name = "service-four"
	existingServiceFour.Annotations = make(map[string]string)

	inputClusterRbacConfig := createClusterRbacConfigModel("service-two.test-namespace.svc.cluster.local")
	inputClusterRbacConfigTwo := createClusterRbacConfigModel("service-three.test-namespace.svc.cluster.local")

	tests := []struct {
		name                   string
		inputServiceList       []*v1.Service
		inputClusterRbacConfig *model.Config
		expectedServiceList    []string
		fake                   bool
	}{
		{
			name:                   "Create: create cluster rbacconfig when it does not exist with multiple new services",
			inputServiceList:       []*v1.Service{existingService, existingServiceTwo, existingServiceThree, existingServiceFour},
			inputClusterRbacConfig: nil,
			expectedServiceList:    []string{"service.test-namespace.svc.cluster.local", "service-two.test-namespace.svc.cluster.local"},
			fake:                   false,
		},
		{
			name:                   "update cluster rbacconfig if service exists",
			inputServiceList:       []*v1.Service{existingService, existingServiceTwo, existingServiceThree, existingServiceFour},
			inputClusterRbacConfig: inputClusterRbacConfig,
			expectedServiceList:    []string{"service-two.test-namespace.svc.cluster.local", "service.test-namespace.svc.cluster.local"},
			fake:                   false,
		},
		{
			name:                   "delete cluster rbacconfig if service exists",
			inputServiceList:       []*v1.Service{existingServiceThree},
			inputClusterRbacConfig: inputClusterRbacConfigTwo,
			expectedServiceList:    []string{},
			fake:                   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crcMgr := NewFakeIndexInformerController(tt.inputServiceList)

			if tt.fake {
				crcMgr.store = GetFakeStub()
			}

			if tt.inputClusterRbacConfig != nil {
				_, err := crcMgr.store.Create(*tt.inputClusterRbacConfig)
				assert.Nil(t, err, "create should be nil")
			}

			err := crcMgr.sync()
			log.Println("err:", err)
			assert.Equal(t, nil, err)

			if len(tt.expectedServiceList) > 0 {
				clusterRbacConfig := getClusterRbacConfig(crcMgr)
				diff := findDiff(tt.expectedServiceList, clusterRbacConfig.Inclusion.Services)
				assert.Equal(t, []string{}, diff, "diff should be equal")
			}
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
//	//crcMgr := NewClusterRbacConfigMgr(controller, "svc.cluster.local")
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
	return createClusterRbacConfigModel("service.test-namespace.svc.cluster.local")
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

func TestFooBar(t *testing.T) {
	configDescriptor := model.ConfigDescriptor{
		model.ServiceRole,
		model.ServiceRoleBinding,
		model.ClusterRbacConfig,
	}
	store := memory.Make(configDescriptor)

	foo := &StubAdapter{store}
	foo.Delete("", "", "")
	controller := memory.NewController(foo)
	controller.Delete("", "", "")
}
