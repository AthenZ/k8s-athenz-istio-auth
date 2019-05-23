package clusterrbacconfig

import (
	"k8s.io/api/core/v1"
	"log"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/client-go/tools/cache"
)

type ClusterRbacConfigMgr struct {
	client *crd.Client
	store  model.ConfigStoreCache
}

func NewClusterRbacConfigMgr(client *crd.Client, store model.ConfigStoreCache) *ClusterRbacConfigMgr {
	return &ClusterRbacConfigMgr{
		client: client,
		store:  store,
	}
}

func (crcMgr *ClusterRbacConfigMgr) addService(clusterRbacConfig *v1alpha1.RbacConfig, service *v1.Service) bool {
	for _, svc := range clusterRbacConfig.Inclusion.Services {
		if svc == service.Name {
			log.Println("service is already added, skipping")
			return false
		}
	}

	clusterRbacConfig.Inclusion.Services = append(clusterRbacConfig.Inclusion.Services, service.Name)
	return true
}

func (crcMgr *ClusterRbacConfigMgr) deleteService(clusterRbacConfig *v1alpha1.RbacConfig, service *v1.Service) bool {
	var indexToRemove = -1
	for i, svc := range clusterRbacConfig.Inclusion.Services {
		if svc == service.Name {
			indexToRemove = i
			break
		}
	}

	if indexToRemove == -1 {
		log.Println("entry not found, skipping...")
		return false
	}

	clusterRbacConfig.Inclusion.Services = remove(clusterRbacConfig.Inclusion.Services, indexToRemove)
	return true
}

func (crcMgr *ClusterRbacConfigMgr) SyncService(delta cache.DeltaType, obj interface{}) {
	service, ok := obj.(*v1.Service)
	if !ok {
		log.Println("failed to cast to service")
		return
	}
	log.Printf("service: %+v", service)

	config := crcMgr.store.Get(model.ClusterRbacConfig.Type, "default", "")
	clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
	if !ok {
		log.Println("Could not cast to ClusterRbacConfig")
		return
	}

	updated := false
	// TODO, test all combinations
	key, exists := service.Annotations["authz.istio.io/enable"]
	if !exists || key != "true" || delta == cache.Deleted {
		log.Println("authz.istio.io/enable not set, skipping...")
		updated = crcMgr.deleteService(clusterRbacConfig, service)
	} else {
		updated = crcMgr.addService(clusterRbacConfig, service)
	}

	if updated {
		_, err := crcMgr.client.Update(model.Config{
			ConfigMeta: config.ConfigMeta,
			Spec:       clusterRbacConfig,
		})

		if err != nil {
			log.Println("error creating clusterrbaconfig", err)
			return
		}
		log.Println("udpated clusterrbacconfig")
	}
}

func remove(s []string, i int) []string {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]
	return s[:len(s)-1]
}

// TODO, handle create or update
