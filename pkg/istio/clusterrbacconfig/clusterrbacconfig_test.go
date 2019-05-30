package clusterrbacconfig

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/config/memory"
	"istio.io/istio/pilot/pkg/model"
)

func TestAddService(t *testing.T) {
	crcMgr := NewClusterRbacConfigMgr(nil, nil, "svc.cluster.local")

	newService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-service",
			Namespace: "test-namespace",
		},
	}

	existingService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-service",
			Namespace: "test-namespace",
		},
	}

	clusterRbacConfig := &v1alpha1.RbacConfig{
		Inclusion: &v1alpha1.RbacConfig_Target{
			Services: []string{"existing-service.test-namespace.svc.cluster.local"},
		},
	}

	clusterRbacConfigTwo := &v1alpha1.RbacConfig{
		Inclusion: &v1alpha1.RbacConfig_Target{
			Services: []string{"existing-service.test-namespace.svc.cluster.local"},
		},
	}

	tests := []struct {
		name              string
		inputService      *v1.Service
		clusterRbacConfig *v1alpha1.RbacConfig
		expectedUpdate    bool
		expectedArray     []string
	}{
		{
			name:              "test adding new service",
			inputService:      newService,
			clusterRbacConfig: clusterRbacConfig,
			expectedUpdate:    true,
			expectedArray:     []string{"existing-service.test-namespace.svc.cluster.local", "new-service.test-namespace.svc.cluster.local"},
		},
		{
			name:              "test adding existing service",
			inputService:      existingService,
			clusterRbacConfig: clusterRbacConfigTwo,
			expectedUpdate:    false,
			expectedArray:     []string{"existing-service.test-namespace.svc.cluster.local"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updated := crcMgr.addService(tt.inputService, tt.clusterRbacConfig)
			assert.Equal(t, tt.expectedUpdate, updated, "return value for addService call should be equal to expected")
			assert.Equal(t, tt.expectedArray, tt.clusterRbacConfig.Inclusion.Services, "clusterRbacConfig service list should contain expected services")
		})
	}
}

func TestDeleteService(t *testing.T) {
	crcMgr := NewClusterRbacConfigMgr(nil, nil, "svc.cluster.local")

	existingService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "test-namespace",
		},
	}

	clusterRbacConfig := &v1alpha1.RbacConfig{
		Inclusion: &v1alpha1.RbacConfig_Target{
			Services: []string{"service.test-namespace.svc.cluster.local", "service-two.test-namespace.svc.cluster.local"},
		},
	}

	clusterRbacConfigTwo := &v1alpha1.RbacConfig{
		Inclusion: &v1alpha1.RbacConfig_Target{
			Services: []string{"service-two.test-namespace.svc.cluster.local"},
		},
	}

	tests := []struct {
		name              string
		inputService      *v1.Service
		clusterRbacConfig *v1alpha1.RbacConfig
		expectedUpdate    bool
		expectedArray     []string
	}{
		{
			name:              "test deleting service",
			inputService:      existingService,
			clusterRbacConfig: clusterRbacConfig,
			expectedUpdate:    true,
			expectedArray:     []string{"service-two.test-namespace.svc.cluster.local"},
		},
		{
			name:              "test deleting existing service",
			inputService:      existingService,
			clusterRbacConfig: clusterRbacConfigTwo,
			expectedUpdate:    false,
			expectedArray:     []string{"service-two.test-namespace.svc.cluster.local"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updated := crcMgr.deleteService(tt.inputService, tt.clusterRbacConfig)
			assert.Equal(t, tt.expectedUpdate, updated, "return value for addService call should be equal to expected")
			assert.Equal(t, tt.expectedArray, tt.clusterRbacConfig.Inclusion.Services, "clusterRbacConfig service list should contain expected services")
		})
	}
}

// Service create
// 1. If service annotation exists and is set to true:
//    - Create clusterrbacconfig if it does exist - done
//    - Update clusterrbacconfig with new service if it is not already there - done
// 2. If service annotation exists and is set to false OR it does not have annotation:
//    - Delete service from clusterrbaccconfig
//    - Delete clusterrbacconfig if no services left - done

// Service Update - Same as create

// Service Delete
// 1. If service annotation exists and is set to true:
// - Delete service from clusterrbaccconfig
// - Delete clusterrbacconfig if no services left

// TODO, look into istio library
func TestSyncService(t *testing.T) {
	existingService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "test-namespace",
			Annotations: map[string]string{
				"authz.istio.io/enable": "true",
			},
		},
	}

	existingServiceTwo := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service-two",
			Namespace: "test-namespace",
			Annotations: map[string]string{
				"authz.istio.io/enable": "true",
			},
		},
	}

	existingServiceThree := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "test-namespace",
			Annotations: map[string]string{
				"authz.istio.io/enable": "false",
			},
		},
	}

	inputClusterRbacConfig := &model.Config{
		ConfigMeta: model.ConfigMeta{
			Type:    model.ClusterRbacConfig.Type,
			Name:    "default",
			Group:   model.ClusterRbacConfig.Group + model.IstioAPIGroupDomain,
			Version: model.ClusterRbacConfig.Version,
		},
		Spec: &v1alpha1.RbacConfig{
			Inclusion: &v1alpha1.RbacConfig_Target{
				Services: []string{"service.test-namespace.svc.cluster.local"},
			},
		},
	}

	//inputClusterRbacConfigTwo := &model.Config{
	//	ConfigMeta: model.ConfigMeta{
	//		Type:      model.ClusterRbacConfig.Type,
	//		Name:      "default",
	//		Group:     model.ClusterRbacConfig.Group + model.IstioAPIGroupDomain,
	//		Version:   model.ClusterRbacConfig.Version,
	//	},
	//	Spec: &v1alpha1.RbacConfig{
	//		Inclusion: &v1alpha1.RbacConfig_Target{
	//			Services: []string{"service.test-namespace.svc.cluster.local"},
	//		},
	//	},
	//}

	inputClusterRbacConfigThree := &model.Config{
		ConfigMeta: model.ConfigMeta{
			Type:    model.ClusterRbacConfig.Type,
			Name:    "default",
			Group:   model.ClusterRbacConfig.Group + model.IstioAPIGroupDomain,
			Version: model.ClusterRbacConfig.Version,
		},
		Spec: &v1alpha1.RbacConfig{
			Inclusion: &v1alpha1.RbacConfig_Target{
				Services: []string{"service.test-namespace.svc.cluster.local", "service-two.test-namespace.svc.cluster.local"},
			},
		},
	}

	tests := []struct {
		name                   string
		inputService           *v1.Service
		inputDelta             cache.DeltaType
		inputClusterRbacConfig *model.Config
		expectedError          error
		expectedArray          []string
	}{
		{
			name:                   "add a service with authz annotation set to true when cluster rbac config does not exist",
			inputService:           existingService,
			inputDelta:             cache.Added,
			inputClusterRbacConfig: nil,
			expectedError:          nil,
			expectedArray:          []string{"service.test-namespace.svc.cluster.local"},
		},
		{
			name:                   "add a service with authz annotation set to true when cluster rbac config exists",
			inputService:           existingServiceTwo,
			inputDelta:             cache.Added,
			inputClusterRbacConfig: inputClusterRbacConfig,
			expectedError:          nil,
			expectedArray:          []string{"service.test-namespace.svc.cluster.local", "service-two.test-namespace.svc.cluster.local"},
		},
		//{
		//	name:                   "delete a service with authz annotation set to false when cluster rbac config exists with one entry, delete cluster rbac config",
		//	inputService:           existingServiceThree,
		//	inputDelta:             cache.Added,
		//	inputClusterRbacConfig: inputClusterRbacConfigTwo,
		//	expectedError:          nil,
		//	expectedArray:          []string{},
		//},
		{
			name:                   "delete a service with authz annotation set to false when cluster rbac config exists",
			inputService:           existingServiceThree,
			inputDelta:             cache.Added,
			inputClusterRbacConfig: inputClusterRbacConfigThree,
			expectedError:          nil,
			expectedArray:          []string{"service-two.test-namespace.svc.cluster.local"},
		},

		//{
		//	name:                   "add a service when there is only one entry in the cluster rbac config",
		//	inputService:           existingService,
		//	inputDelta:             cache.Deleted,
		//	inputClusterRbacConfig: inputClusterRbacConfig,
		//	expectedError:          nil,
		//	expectedArray:          []string{""},
		//},
		//{
		//	name:                   "test delete a service when cluster rbac config already exists",
		//	inputService:           existingServiceTwo,
		//	inputDelta:             cache.Deleted,
		//	inputClusterRbacConfig: inputClusterRbacConfigTwo,
		//	expectedError:          nil,
		//	expectedArray:          []string{"service.test-namespace.svc.cluster.local"},
		//},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crcMgr := initCrcMgr(tt.inputClusterRbacConfig)

			err := crcMgr.syncClusterRbacConfig(tt.inputDelta, tt.inputService)
			assert.Equal(t, tt.expectedError, err)

			clusterRbacConfig := getClusterRbacConfig(crcMgr)
			assert.Equal(t, tt.expectedArray, clusterRbacConfig.Inclusion.Services, "clusterRbacConfig service list should contain expected services")
		})
	}
}

func initCrcMgr(clusterRbacConfig *model.Config) *ClusterRbacConfigMgr {
	configDescriptor := model.ConfigDescriptor{
		model.ServiceRole,
		model.ServiceRoleBinding,
		model.ClusterRbacConfig,
	}

	store := memory.Make(configDescriptor)
	controller := memory.NewController(store)
	crcMgr := NewClusterRbacConfigMgr(nil, controller, "svc.cluster.local")

	log.Println("crc", clusterRbacConfig)

	if clusterRbacConfig != nil {
		_, err := crcMgr.store.Create(*clusterRbacConfig)
		if err != nil {
			log.Panicln("err creating:", err)
		}
	}
	return crcMgr
}

func getClusterRbacConfig(crcMgr *ClusterRbacConfigMgr) *v1alpha1.RbacConfig {
	log.Println(crcMgr.store.List(model.ClusterRbacConfig.Type, ""))
	config := crcMgr.store.Get(model.ClusterRbacConfig.Type, "default", "")
	clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
	if !ok {
		log.Panicln("cannot cast to rbac config")
	}
	return clusterRbacConfig
}
