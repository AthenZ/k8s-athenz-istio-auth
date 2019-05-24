package clusterrbacconfig

import (
	"github.com/stretchr/testify/assert"
	"istio.io/api/rbac/v1alpha1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"k8s.io/client-go/tools/cache"
)

var crcMgr = NewClusterRbacConfigMgr(nil, nil, "svc.yahoo.local")

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

func TestSyncService(t *testing.T) {
	existingService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "test-namespace",
		},
	}

	crcMgr.SyncService(cache.Added, existingService)
}
