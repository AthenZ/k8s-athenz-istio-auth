package clusterrbacconfig

import (
	"errors"
	"log"

	"k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
)

const authzEnabledAnnotation = "authz.istio.io/enabled"

type ClusterRbacConfigMgr struct {
	store     model.ConfigStoreCache
	dnsSuffix string
}

// NewClusterRbacConfigMgr initializes the ClusterRbacConfigMgr object
func NewClusterRbacConfigMgr(store model.ConfigStoreCache, dnsSuffix string) *ClusterRbacConfigMgr {
	return &ClusterRbacConfigMgr{
		store:     store,
		dnsSuffix: dnsSuffix,
	}
}

// addService will add a service to the ClusterRbacConfig object
func (crcMgr *ClusterRbacConfigMgr) addService(service *v1.Service, clusterRbacConfig *v1alpha1.RbacConfig) bool {
	dns := service.Name + "." + service.Namespace + "." + crcMgr.dnsSuffix
	for _, svc := range clusterRbacConfig.Inclusion.Services {
		if svc == dns {
			return false
		}
	}
	clusterRbacConfig.Inclusion.Services = append(clusterRbacConfig.Inclusion.Services, dns)
	return true
}

// deleteService will delete a service from the ClusterRbacConfig object
func (crcMgr *ClusterRbacConfigMgr) deleteService(service *v1.Service, clusterRbacConfig *v1alpha1.RbacConfig) bool {
	var indexToRemove = -1
	dns := service.Name + "." + service.Namespace + "." + crcMgr.dnsSuffix
	for i, svc := range clusterRbacConfig.Inclusion.Services {
		if svc == dns {
			indexToRemove = i
			break
		}
	}

	if indexToRemove == -1 {
		return false
	}

	clusterRbacConfig.Inclusion.Services = remove(clusterRbacConfig.Inclusion.Services, indexToRemove)
	return true
}

// createClusterRbacConfig creates the ClusterRbacConfig object
func (crcMgr *ClusterRbacConfigMgr) createClusterRbacConfig(service *v1.Service) model.Config {
	return model.Config{
		ConfigMeta: model.ConfigMeta{
			Type:    model.ClusterRbacConfig.Type,
			Name:    model.DefaultRbacConfigName,
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
}

// syncClusterRbacConfig decides whether to create / update / delete the ClusterRbacConfig
// object based on a service create / update / delete action and if it has the authz enabled
// annotation set.
func (crcMgr *ClusterRbacConfigMgr) syncClusterRbacConfig(delta cache.DeltaType, service *v1.Service) error {
	config := crcMgr.store.Get(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, "")
	key, exists := service.Annotations[authzEnabledAnnotation]
	if config == nil && exists && key == "true" && delta != cache.Deleted {
		log.Println("creating cluster rbac config")
		clusterRbacConfig := crcMgr.createClusterRbacConfig(service)
		_, err := crcMgr.store.Create(clusterRbacConfig)
		return err
	} else if config == nil {
		return errors.New("config doesn't exist and annotation is not set")
	}

	clusterRbacConfig, ok := config.Spec.(*v1alpha1.RbacConfig)
	if !ok {
		return errors.New("Could not cast to ClusterRbacConfig")
	}

	updated := false
	if exists && key == "true" && delta != cache.Deleted {
		updated = crcMgr.addService(service, clusterRbacConfig)
	} else {
		updated = crcMgr.deleteService(service, clusterRbacConfig)
	}

	if updated {
		var err error
		if len(clusterRbacConfig.Inclusion.Services) == 0 {
			log.Println("deleting cluster rbac config")
			return crcMgr.store.Delete(model.ClusterRbacConfig.Type, model.DefaultRbacConfigName, "default")
		}

		log.Println("updating cluster rbac config")
		_, err = crcMgr.store.Update(model.Config{
			ConfigMeta: config.ConfigMeta,
			Spec:       clusterRbacConfig,
		})
		return err
	}

	return nil
}

// SyncService will cast the service object and call syncClusterRbacConfig
func (crcMgr *ClusterRbacConfigMgr) SyncService(delta cache.DeltaType, obj interface{}) {
	service, ok := obj.(*v1.Service)
	if !ok {
		log.Println("failed to cast to service")
		return
	}
	log.Printf("service: %+v", service)

	err := crcMgr.syncClusterRbacConfig(delta, service)
	if err != nil {
		log.Println(err)
	}
}

// remove removes an element from an array at the given index
func remove(s []string, i int) []string {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]
	return s[:len(s)-1]
}
