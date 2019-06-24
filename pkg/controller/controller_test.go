package controller

import (
	"testing"
	"time"

	"istio.io/istio/pilot/pkg/model"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	adv1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/apis/athenz/v1"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/client/clientset/versioned/fake"
	adInformer "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/informers/externalversions/athenz/v1"

	"github.com/stretchr/testify/assert"
)

var ad = &adv1.AthenzDomain{
	ObjectMeta: v1.ObjectMeta{
		Name:      "test.namespace",
		Namespace: "test-namespace",
	},
}

func TestProcessEvent(t *testing.T) {
	c := &Controller{
		queue: workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}

	c.processEvent(cache.MetaNamespaceKeyFunc, ad.DeepCopy())

	assert.Equal(t, 1, c.queue.Len(), "queue length should be 1")
	item, shutdown := c.queue.Get()
	assert.False(t, shutdown, "shutdown should be false")
	assert.Equal(t, 0, c.queue.Len(), "queue length should be 0")
	assert.Equal(t, "test-namespace/test.namespace", item, "key should be equal")
}

func TestProcessConfigEvent(t *testing.T) {
	c := &Controller{
		queue: workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}

	config := model.Config{
		ConfigMeta: model.ConfigMeta{
			Name:      "test",
			Namespace: "test-namespace",
		},
	}

	c.processConfigEvent(config, model.EventAdd)

	assert.Equal(t, 1, c.queue.Len(), "queue length should be 1")
	item, shutdown := c.queue.Get()
	assert.False(t, shutdown, "shutdown should be false")
	assert.Equal(t, 0, c.queue.Len(), "queue length should be 0")
	assert.Equal(t, "test-namespace/test.namespace", item, "key should be equal")
}

func TestResync(t *testing.T) {
	fakeClientset := fake.NewSimpleClientset()
	adIndexInformer := adInformer.NewAthenzDomainInformer(fakeClientset, v1.NamespaceAll, 0, cache.Indexers{})
	adIndexInformer.GetStore().Add(ad.DeepCopy())

	c := &Controller{
		queue:            workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		adIndexInformer:  adIndexInformer,
		adResyncInterval: time.Second * 1,
	}

	stopCh := make(chan struct{})
	go c.resync(stopCh)
	time.Sleep(time.Second * 2)
	close(stopCh)

	assert.Equal(t, 1, c.queue.Len(), "queue length should be 1")
	item, shutdown := c.queue.Get()
	assert.False(t, shutdown, "shutdown should be false")
	assert.Equal(t, 0, c.queue.Len(), "queue length should be 0")
	assert.Equal(t, "test-namespace/test.namespace", item, "key should be equal")
}
