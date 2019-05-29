package clusterrbacconfig

import (
	"github.com/stretchr/testify/assert"
	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/config/memory"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"log"
	"testing"
)

var crcMgr *ClusterRbacConfigMgr

func init() {
	configDescriptor := model.ConfigDescriptor{
		model.ClusterRbacConfig,
	}

	c, err := crd.NewClient("", "", configDescriptor, "svc.cluster.local")
	if err != nil {
		log.Panicln(err)
	}

	store := memory.Make(model.IstioConfigTypes)
	controller := memory.NewController(store)

	//crc := model.Config{
	//	ConfigMeta: model.ConfigMeta{
	//		Type:      model.ClusterRbacConfig.Type,
	//		Name:      "default",
	//		Group:     model.ClusterRbacConfig.Group + model.IstioAPIGroupDomain,
	//		Version:   model.ClusterRbacConfig.Version,
	//	},
	//	Spec: &v1alpha1.RbacConfig{},
	//}
	//_, err = store.Create(crc)
	//log.Println("err:", err)
	//log.Println(controller.List(model.ClusterRbacConfig.Type, ""))
	crcMgr = NewClusterRbacConfigMgr(c, controller, "svc.yahoo.local")

	//stopChan := make(chan struct{})
	//go crcMgr.store.Run(stopChan)
}

func TestAddService(t *testing.T) {
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
			Services: []string{"existing-service.test-namespace.svc.yahoo.local"},
		},
	}

	clusterRbacConfigTwo := &v1alpha1.RbacConfig{
		Inclusion: &v1alpha1.RbacConfig_Target{
			Services: []string{"existing-service.test-namespace.svc.yahoo.local"},
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
			expectedArray:     []string{"existing-service.test-namespace.svc.yahoo.local", "new-service.test-namespace.svc.yahoo.local"},
		},
		{
			name:              "test adding existing service",
			inputService:      existingService,
			clusterRbacConfig: clusterRbacConfigTwo,
			expectedUpdate:    false,
			expectedArray:     []string{"existing-service.test-namespace.svc.yahoo.local"},
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
	existingService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "test-namespace",
		},
	}

	clusterRbacConfig := &v1alpha1.RbacConfig{
		Inclusion: &v1alpha1.RbacConfig_Target{
			Services: []string{"service.test-namespace.svc.yahoo.local", "service-two.test-namespace.svc.yahoo.local"},
		},
	}

	clusterRbacConfigTwo := &v1alpha1.RbacConfig{
		Inclusion: &v1alpha1.RbacConfig_Target{
			Services: []string{"service-two.test-namespace.svc.yahoo.local"},
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
			expectedArray:     []string{"service-two.test-namespace.svc.yahoo.local"},
		},
		{
			name:              "test deleting existing service",
			inputService:      existingService,
			clusterRbacConfig: clusterRbacConfigTwo,
			expectedUpdate:    false,
			expectedArray:     []string{"service-two.test-namespace.svc.yahoo.local"},
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

	inputClusterRbacConfig := &model.Config{
		ConfigMeta: model.ConfigMeta{
			Type:    model.ClusterRbacConfig.Type,
			Name:    "default",
			Group:   model.ClusterRbacConfig.Group + model.IstioAPIGroupDomain,
			Version: model.ClusterRbacConfig.Version,
		},
		Spec: &v1alpha1.RbacConfig{
			Inclusion: &v1alpha1.RbacConfig_Target{
				Services: []string{"service.test-namespace.svc.yahoo.local"},
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
			name:                   "test adding a service when cluster rbac config does not exist",
			inputService:           existingService,
			inputDelta:             cache.Added,
			inputClusterRbacConfig: nil,
			expectedError:          nil,
			expectedArray:          []string{"service.test-namespace.svc.yahoo.local"},
		},
		{
			name:                   "test updating a service when cluster rbac config does not exist",
			inputService:           existingService,
			inputDelta:             cache.Updated,
			inputClusterRbacConfig: nil,
			expectedError:          nil,
			expectedArray:          []string{"service.test-namespace.svc.yahoo.local"},
		},
		{
			name:                   "test deleting a service when there is only one entry in the cluster rbac config",
			inputService:           existingService,
			inputDelta:             cache.Deleted,
			inputClusterRbacConfig: inputClusterRbacConfig,
			expectedError:          nil,
			expectedArray:          []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.Make(model.IstioConfigTypes)
			controller := memory.NewController(store)
			// TODO, remove client?
			crcMgr = NewClusterRbacConfigMgr(nil, controller, "svc.yahoo.local")

			if tt.inputClusterRbacConfig != nil {
				_, err := crcMgr.store.Create(*tt.inputClusterRbacConfig)
				if err != nil {
					log.Panicln("err creating:", err)
				}
			}

			err := crcMgr.syncClusterRbacConfig(tt.inputDelta, tt.inputService)
			assert.Equal(t, tt.expectedError, err)

			config := crcMgr.store.Get(model.ClusterRbacConfig.Type, "default", "")
			if config != nil && len(tt.expectedArray) > 0 {
				clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
				if !ok {
					log.Panicln("cannot cast to rbac config")
				}
				log.Println("config:", config)
				assert.Equal(t, tt.expectedArray, clusterRbacConfig.Inclusion.Services, "clusterRbacConfig service list should contain expected services")
			}
		})
	}
}

// Test cases
// 1. If annotation exists:
//    - Create clusterrbacconfig if it does exist
//    - Update clusterrbacconfig with new service if it is not already there
// 2. If annotation does not exist:
//    - Delete service from clusterrbaccconfig
//    - Delete clusterrbacconfig if no services left

// service created / updated / deleted with / without annotation
