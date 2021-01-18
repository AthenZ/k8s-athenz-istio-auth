package authzpolicy

import (
	"github.com/ardielle/ardielle-go/rdl"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	m "github.com/yahoo/k8s-athenz-istio-auth/pkg/athenz"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"
	adv1 "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	fakev1 "github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned/fake"
	adInformer "github.com/yahoo/k8s-athenz-syncer/pkg/client/informers/externalversions/athenz/v1"
	"istio.io/api/security/v1beta1"
	authz "istio.io/client-go/pkg/apis/security/v1beta1"
	workloadv1beta1 "istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/config/memory"
	"istio.io/istio/pilot/pkg/model"

	"istio.io/istio/pkg/config/schema/collection"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/istio/pkg/config/schema/resource"
	v1 "k8s.io/api/core/v1"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	fcache "k8s.io/client-go/tools/cache/testing"
	"k8s.io/client-go/util/workqueue"
	"sync"
	"testing"
	"time"
)

const (
	DomainName = "test.namespace"
	username   = "user.name"
	username1  = "user.*"
)

var (
	onboardedService = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "onboarded-service",
			Namespace: "test-namespace",
			Annotations: map[string]string{
				authzEnabledAnnotation: "true",
			},
			Labels: map[string]string{
				"app": "productpage",
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

	ad1 = &adv1.AthenzDomain{
		ObjectMeta: k8sv1.ObjectMeta{
			Name:      DomainName,
			Namespace: "",
		},
		Spec: adv1.AthenzDomainSpec{
			SignedDomain: getFakeDomain(),
		},
	}
)

func init() {
	log.InitLogger("", "debug")
}

// fakeConfigStore a wrapper around a passed-in config store that does mutex lock on all store operations
type fakeConfigStore struct {
	model.ConfigStore
	m sync.Mutex
}

func (cs *fakeConfigStore) Get(typ resource.GroupVersionKind, name, namespace string) *model.Config {
	cs.m.Lock()
	defer cs.m.Unlock()
	return cs.ConfigStore.Get(typ, name, namespace)
}
func (cs *fakeConfigStore) List(typ resource.GroupVersionKind, namespace string) ([]model.Config, error) {
	cs.m.Lock()
	defer cs.m.Unlock()
	return cs.ConfigStore.List(typ, namespace)
}

func (cs *fakeConfigStore) Create(cfg model.Config) (string, error) {
	cs.m.Lock()
	defer cs.m.Unlock()
	return cs.ConfigStore.Create(cfg)
}

func (cs *fakeConfigStore) Update(cfg model.Config) (string, error) {
	cs.m.Lock()
	defer cs.m.Unlock()
	return cs.ConfigStore.Update(cfg)
}

func (cs *fakeConfigStore) Delete(typ resource.GroupVersionKind, name, namespace string) error {
	cs.m.Lock()
	defer cs.m.Unlock()
	return cs.ConfigStore.Delete(typ, name, namespace)
}

func newFakeController(services []*v1.Service, fake bool, stopCh <-chan struct{}) *Controller {
	c := &Controller{}
	configDescriptor := collection.SchemasFor(collections.IstioSecurityV1Beta1Authorizationpolicies)

	configStore := memory.Make(configDescriptor)
	if fake {
		configStore = &fakeConfigStore{
			configStore,
			sync.Mutex{},
		}
	}
	c.configStoreCache = memory.NewController(configStore)

	source := fcache.NewFakeControllerSource()
	for _, service := range services {
		source.Add(service)
	}
	fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
	go fakeIndexInformer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, fakeIndexInformer.HasSynced) {
		log.Panicln("timed out waiting for cache to sync")
	}
	c.serviceIndexInformer = fakeIndexInformer

	fakeClientset := fakev1.NewSimpleClientset()
	adIndexInformer := adInformer.NewAthenzDomainInformer(fakeClientset, 0, cache.Indexers{})
	adIndexInformer.GetStore().Add(ad1.DeepCopy())
	c.adIndexInformer = adIndexInformer

	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	c.queue = queue

	c.enableOriginJwtSubject=true

	return c
}

func TestNewController(t *testing.T) {
	configDescriptor := collection.SchemasFor(collections.IstioSecurityV1Beta1Authorizationpolicies)
	source := fcache.NewFakeControllerSource()
	fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
	athenzclientset := fakev1.NewSimpleClientset()
	fakeAthenzInformer := adInformer.NewAthenzDomainInformer(athenzclientset, 0, cache.Indexers{})
	authzpolicyIndexInformer := cache.NewSharedIndexInformer(source, &authz.AuthorizationPolicy{}, 0, nil)
	configStore := memory.Make(configDescriptor)
	configStoreCache := memory.NewController(configStore)
	c := NewController(configStoreCache, fakeIndexInformer, fakeAthenzInformer, authzpolicyIndexInformer, true, true)
	assert.Equal(t, fakeIndexInformer, c.serviceIndexInformer, "service index informer pointer should be equal")
	assert.Equal(t, configStoreCache, c.configStoreCache, "config configStoreCache cache pointer should be equal")
	assert.Equal(t, fakeAthenzInformer, c.adIndexInformer, "athenz index informer cache should be equal")
	assert.Equal(t, true, c.enableOriginJwtSubject, "enableOriginJwtSubject bool should be equal")
}

func TestConvertAthenzModelIntoIstioAuthzPolicy(t *testing.T) {
	configDescriptor := collection.SchemasFor(collections.IstioSecurityV1Beta1Authorizationpolicies)
	source := fcache.NewFakeControllerSource()
	fakeIndexInformer := cache.NewSharedIndexInformer(source, &v1.Service{}, 0, nil)
	athenzclientset := fakev1.NewSimpleClientset()
	fakeAthenzInformer := adInformer.NewAthenzDomainInformer(athenzclientset, 0, cache.Indexers{})
	configStore := memory.Make(configDescriptor)
	configStoreCache := memory.NewController(configStore)
	authzpolicyIndexInformer := cache.NewSharedIndexInformer(source, &authz.AuthorizationPolicy{}, 0, nil)
	c := NewController(configStoreCache, fakeIndexInformer, fakeAthenzInformer, authzpolicyIndexInformer, true, false)

	signedDomain := getFakeDomain()
	labels := onboardedService.GetLabels()
	domainRBAC := m.ConvertAthenzPoliciesIntoRbacModel(signedDomain.Domain, &c.adIndexInformer)
	spew.Println("labels looks like: ", labels)
	convertedCR := c.convertAthenzModelIntoIstioAuthzPolicy(domainRBAC, onboardedService.Namespace, onboardedService.Name, labels["app"])
	//fmt.Println("convertCR looks like: ", convertedCR.ConfigMeta.CreationTimestamp)
	expectedCR := getExpectedCR();
	assert.Equal(t, expectedCR, convertedCR, "converted authz policy should be equal")
}

func getExpectedCR() model.Config{
	var out model.Config
	schema := collections.IstioSecurityV1Beta1Authorizationpolicies
	createTimestamp, _ := time.Parse("", "12/8/2015 12:00:00")
	out.ConfigMeta = model.ConfigMeta{
		Type:      schema.Resource().Kind(),
		Group:     schema.Resource().Group(),
		Version:   schema.Resource().Version(),
		Namespace: "test-namespace",
		Name:      "onboarded-service",
		CreationTimestamp: createTimestamp,
	}
	out.Spec = &v1beta1.AuthorizationPolicy{
		Selector: &workloadv1beta1.WorkloadSelector{
			MatchLabels: map[string]string{"svc": "productpage"},
		},
		Rules: []*v1beta1.Rule{
			{
				To: []*v1beta1.Rule_To{
					{
						Operation: &v1beta1.Operation{
							Methods: []string{
								"GET",
							},
						},
					},
				},
			},
			{
				From: []*v1beta1.Rule_From{
					{
						Source: &v1beta1.Source{
							Principals: []string{
								"*",
								"test.namespace/ra/test.namespace:role.productpage-reader",
							},
						},
					},
					{
						Source: &v1beta1.Source{
							RequestPrincipals: []string{
								"*",
							},
						},
					},
				},
			},
		},
	}
	return out
}

func getFakeDomain() zms.SignedDomain {
	allow := zms.ALLOW
	timestamp, err := rdl.TimestampParse("2019-07-22T20:29:10.305Z")
	if err != nil {
		panic(err)
	}

	return zms.SignedDomain{
		Domain: &zms.DomainData{
			Modified: timestamp,
			Name:     DomainName,
			Policies: &zms.SignedPolicies{
				Contents: &zms.DomainPolicies{
					Domain: DomainName,
					Policies: []*zms.Policy{
						{
							Assertions: []*zms.Assertion{
								{
									Role:     DomainName + ":role.admin",
									Resource: DomainName + ":*",
									Action:   "*",
									Effect:   &allow,
								},
								{
									Role:     DomainName + ":role.productpage-reader",
									Resource: DomainName + ":svc.productpage",
									Action:   "get",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     DomainName + ":policy.admin",
						},
					},
				},
				KeyId:     "col-env-1.1",
				Signature: "signature-policy",
			},
			Roles: []*zms.Role{
				{
					Members:  []zms.MemberName{username},
					Modified: &timestamp,
					Name:     DomainName + ":role.admin",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: username,
						},
					},
				},
				{
					Members:  []zms.MemberName{"productpage-reader"},
					Modified: &timestamp,
					Name:     DomainName + ":role.productpage-reader",
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: username1,
						},
					},
				},
			},
			Services: []*zms.ServiceIdentity{},
			Entities: []*zms.Entity{},
		},
		KeyId:     "colo-env-1.1",
		Signature: "signature",
	}
}
