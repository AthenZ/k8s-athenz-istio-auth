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
	client    *crd.Client
	store     model.ConfigStoreCache
	dnsSuffix string
}

func NewClusterRbacConfigMgr(client *crd.Client, store model.ConfigStoreCache, dnsSuffix string) *ClusterRbacConfigMgr {
	return &ClusterRbacConfigMgr{
		client:    client,
		store:     store,
		dnsSuffix: dnsSuffix,
	}
}

func (crcMgr *ClusterRbacConfigMgr) addService(service *v1.Service, clusterRbacConfig *v1alpha1.RbacConfig) bool {
	dns := service.Name + "." + service.Namespace + "." + crcMgr.dnsSuffix
	for _, svc := range clusterRbacConfig.Inclusion.Services {
		if svc == dns {
			log.Println("service is already added, skipping")
			return false
		}
	}

	clusterRbacConfig.Inclusion.Services = append(clusterRbacConfig.Inclusion.Services, dns)
	return true
}

func (crcMgr *ClusterRbacConfigMgr) deleteService(service *v1.Service, clusterRbacConfig *v1alpha1.RbacConfig) bool {
	var indexToRemove = -1
	dns := service.Name + "." + service.Namespace + "." + crcMgr.dnsSuffix
	for i, svc := range clusterRbacConfig.Inclusion.Services {
		// TODO, add cluster dns suffix here
		if svc == dns {
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

func (crcMgr *ClusterRbacConfigMgr) createClusterRbacConfig(service *v1.Service) error {
	modelConfig := model.Config{
		ConfigMeta: model.ConfigMeta{
			Type:    model.ClusterRbacConfig.Type,
			Name:    "default",
			Group:   model.ClusterRbacConfig.Group + model.IstioAPIGroupDomain,
			Version: model.ClusterRbacConfig.Version,
		},
		Spec: &v1alpha1.RbacConfig{
			Mode: v1alpha1.RbacConfig_ON_WITH_INCLUSION,
			Inclusion: &v1alpha1.RbacConfig_Target{
				Services: []string{service.Name + "." + service.Namespace + "." + crcMgr.dnsSuffix},
			},
		},
	}
	_, err := crcMgr.store.Create(modelConfig)
	return err
}

func (crcMgr *ClusterRbacConfigMgr) SyncService(delta cache.DeltaType, obj interface{}) {
	service, ok := obj.(*v1.Service)
	if !ok {
		log.Println("failed to cast to service")
		return
	}
	log.Printf("service: %+v", service)

	config := crcMgr.store.Get(model.ClusterRbacConfig.Type, "default", "")
	key, exists := service.Annotations["authz.istio.io/enable"]
	if config == nil && exists && key == "true" {
		err := crcMgr.createClusterRbacConfig(service)
		if err != nil {
			log.Println(err)
		}
		return
	} else if config == nil {
		log.Println("config doesn't exist and annotation is not set")
		return
	}

	clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
	if !ok {
		log.Println("Could not cast to ClusterRbacConfig")
		return
	}

	updated := false
	// TODO, test all combinations
	key, exists = service.Annotations["authz.istio.io/enable"]
	if !exists || key != "true" || delta == cache.Deleted {
		log.Println("authz.istio.io/enable not set, skipping...")
		updated = crcMgr.deleteService(service, clusterRbacConfig)
	} else {
		updated = crcMgr.addService(service, clusterRbacConfig)
	}

	if updated {
		var err error
		if len(clusterRbacConfig.Inclusion.Services) == 0 {
			err = crcMgr.store.Delete(model.ClusterRbacConfig.Type, "default", "")
		} else {
			log.Println("updating")
			_, err = crcMgr.store.Update(model.Config{
				ConfigMeta: config.ConfigMeta,
				Spec:       clusterRbacConfig,
			})
		}

		if err != nil {
			log.Println("error creating clusterrbaconfig", err)
			return
		}
		log.Println("updated clusterrbacconfig")
	}
}

func remove(s []string, i int) []string {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]
	return s[:len(s)-1]
}

// TODO, handle create or update
