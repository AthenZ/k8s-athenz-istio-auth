package controller

import (
	"fmt"
	"testing"
	"time"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/model"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	adv1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/apis/athenz/v1"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/client/clientset/versioned/fake"
	adInformer "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/informers/externalversions/athenz/v1"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/processor"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"

	"github.com/stretchr/testify/assert"
)

var ad = &adv1.AthenzDomain{
	ObjectMeta: v1.ObjectMeta{
		Name:      "test.namespace",
		Namespace: "test-namespace",
	},
}

func init() {
	log.InitLogger("", "debug")
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
	assert.Equal(t, "test.namespace", item, "key should be equal")
}

func newSr(ns, role string) model.Config {
	srSpec := &v1alpha1.ServiceRole{
		Rules: []*v1alpha1.AccessRule{
			{
				Services: []string{common.WildCardAll},
				Methods:  []string{"GET"},
				Constraints: []*v1alpha1.AccessRule_Constraint{
					{
						Key:    common.ConstraintSvcKey,
						Values: []string{"test-svc"},
					},
				},
			},
		},
	}
	return common.NewConfig(model.ServiceRole.Type, ns, role, srSpec)
}

func newSrb(ns, role string) model.Config {
	srbSpec := &v1alpha1.ServiceRoleBinding{
		RoleRef: &v1alpha1.RoleRef{
			Kind: common.ServiceRoleKind,
			Name: role,
		},
		Subjects: []*v1alpha1.Subject{
			{
				User: "test-user",
			},
		},
	}
	return common.NewConfig(model.ServiceRoleBinding.Type, ns, role, srbSpec)
}

func updatedSr(ns, role string) model.Config {
	srSpec := &v1alpha1.ServiceRole{
		Rules: []*v1alpha1.AccessRule{
			{
				Services: []string{common.WildCardAll},
				Methods:  []string{"GET"},
				Constraints: []*v1alpha1.AccessRule_Constraint{
					{
						Key:    common.ConstraintSvcKey,
						Values: []string{"test-svc"},
					},
				},
			},
			{
				Services: []string{common.WildCardAll},
				Methods:  []string{"POST"},
				Constraints: []*v1alpha1.AccessRule_Constraint{
					{
						Key:    common.ConstraintSvcKey,
						Values: []string{"test-svc"},
					},
				},
			},
		},
	}
	return common.NewConfig(model.ServiceRole.Type, ns, role, srSpec)
}

func updatedSrb(ns, role string) model.Config {
	srbSpec := &v1alpha1.ServiceRoleBinding{
		RoleRef: &v1alpha1.RoleRef{
			Kind: common.ServiceRoleKind,
			Name: role,
		},
		Subjects: []*v1alpha1.Subject{
			{
				User: "test-user",
			},
			{
				User: "another.client.user",
			},
		},
	}
	return common.NewConfig(model.ServiceRoleBinding.Type, ns, role, srbSpec)
}

func TestConvertSliceToKeyedMap(t *testing.T) {
	tests := []struct {
		name     string
		in       []model.Config
		expected map[string]model.Config
	}{
		{
			name:     "should return empty map for empty slice",
			in:       []model.Config{},
			expected: map[string]model.Config{},
		},
		{
			name: "should return correctly keyed map",
			in: []model.Config{
				newSr("my-ns", "this-role"),
				newSrb("my-ns", "this-role"),
			},
			expected: map[string]model.Config{
				"service-role/my-ns/this-role":         newSr("my-ns", "this-role"),
				"service-role-binding/my-ns/this-role": newSrb("my-ns", "this-role"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := convertSliceToKeyedMap(tt.in)
			assert.Equal(t, tt.expected, actual, "returned map should match the expected map")
		})
	}
}

func TestEqual(t *testing.T) {
	tests := []struct {
		name     string
		in1      model.Config
		in2      model.Config
		expected bool
	}{
		{
			name:     "should return true for empty model.Config items",
			in1:      model.Config{},
			in2:      model.Config{},
			expected: true,
		},
		{
			name:     "should return false for different model.Config item names but same spec",
			in1:      newSr("test-ns", "my-role"),
			in2:      newSr("test-ns", "another-role"),
			expected: false,
		},
		{
			name:     "should return false for different model.Config item names and different spec",
			in1:      newSr("test-ns", "my-role"),
			in2:      updatedSr("test-ns", "another-role"),
			expected: false,
		},
		{
			name:     "should return false for same model.Config item names but different spec",
			in1:      newSr("test-ns", "my-role"),
			in2:      updatedSr("test-ns", "my-role"),
			expected: false,
		},
		{
			name:     "should return false for different model.Config item types but same names",
			in1:      newSr("test-ns", "my-role"),
			in2:      newSrb("test-ns", "my-role"),
			expected: false,
		},
		{
			name:     "should return true for same model.Config item names and spec",
			in1:      newSr("test-ns", "my-role"),
			in2:      newSr("test-ns", "my-role"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := equal(tt.in1, tt.in2)
			assert.Equal(t, tt.expected, actual, "comparison result should be equal to expected")
		})
	}
}

func TestComputeChangeList(t *testing.T) {

	errHandler := func(err error, item *processor.Item) error {
		return err
	}

	type input struct {
		current    []model.Config
		desired    []model.Config
		errHandler processor.OnErrorFunc
	}
	tests := []struct {
		name           string
		input          input
		expectedOutput []*processor.Item
	}{
		{
			name:           "should return empty change list for empty current and desired list",
			input:          input{},
			expectedOutput: make([]*processor.Item, 0),
		},
		{
			name: "should add create operations for new items on the desired list",
			input: input{
				current: []model.Config{},
				desired: []model.Config{
					newSr("test-ns", "svc-role"),
					newSrb("test-ns", "svc-role"),
				},
				errHandler: errHandler,
			},
			expectedOutput: []*processor.Item{
				{
					Operation:    model.EventAdd,
					Resource:     newSr("test-ns", "svc-role"),
					ErrorHandler: errHandler,
				},
				{
					Operation:    model.EventAdd,
					Resource:     newSrb("test-ns", "svc-role"),
					ErrorHandler: errHandler,
				},
			},
		},
		{
			name: "should add update operations for changed items on the desired list",
			input: input{
				current: []model.Config{
					newSr("test-ns", "svc-role"),
					newSrb("test-ns", "svc-role"),
					newSr("another-ns", "backend-writer"),
					newSrb("another-ns", "backend-writer"),
				},
				desired: []model.Config{
					updatedSr("test-ns", "svc-role"),
					updatedSrb("test-ns", "svc-role"),
					newSr("another-ns", "backend-writer"),
					newSrb("another-ns", "backend-writer"),
				},
				errHandler: errHandler,
			},
			expectedOutput: []*processor.Item{
				{
					Operation:    model.EventUpdate,
					Resource:     updatedSr("test-ns", "svc-role"),
					ErrorHandler: errHandler,
				},
				{
					Operation:    model.EventUpdate,
					Resource:     updatedSrb("test-ns", "svc-role"),
					ErrorHandler: errHandler,
				},
			},
		},
		{
			name: "should add delete operation for deleted items on the desired list",
			input: input{
				current: []model.Config{
					newSr("test-ns", "svc-role"),
					newSrb("test-ns", "svc-role"),
				},
				desired:    []model.Config{},
				errHandler: errHandler,
			},
			expectedOutput: []*processor.Item{
				{
					Operation:    model.EventDelete,
					Resource:     newSr("test-ns", "svc-role"),
					ErrorHandler: errHandler,
				},
				{
					Operation:    model.EventDelete,
					Resource:     newSrb("test-ns", "svc-role"),
					ErrorHandler: errHandler,
				},
			},
		},
		{
			name: "should add create,update and delete operations based on the desired list",
			input: input{
				current: []model.Config{
					newSr("test-ns", "svc-role"),
					newSrb("test-ns", "svc-role"),
					newSr("some-ns", "frontend-reader"),
					newSrb("some-ns", "frontend-reader"),
				},
				desired: []model.Config{
					updatedSr("test-ns", "svc-role"),
					updatedSrb("test-ns", "svc-role"),
					newSr("another-ns", "backend-writer"),
					newSrb("another-ns", "backend-writer"),
				},
				errHandler: errHandler,
			},
			expectedOutput: []*processor.Item{
				{
					Operation:    model.EventUpdate,
					Resource:     updatedSr("test-ns", "svc-role"),
					ErrorHandler: errHandler,
				},
				{
					Operation:    model.EventUpdate,
					Resource:     updatedSrb("test-ns", "svc-role"),
					ErrorHandler: errHandler,
				},
				{
					Operation:    model.EventAdd,
					Resource:     updatedSr("another-ns", "backend-writer"),
					ErrorHandler: errHandler,
				},
				{
					Operation:    model.EventAdd,
					Resource:     updatedSrb("another-ns", "backend-writer"),
					ErrorHandler: errHandler,
				},
				{
					Operation:    model.EventDelete,
					Resource:     newSr("some-ns", "frontend-reader"),
					ErrorHandler: errHandler,
				},
				{
					Operation:    model.EventDelete,
					Resource:     newSrb("some-ns", "frontend-reader"),
					ErrorHandler: errHandler,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualChangeList := computeChangeList(tt.input.current, tt.input.desired, tt.input.errHandler)
			assert.Equal(t, len(tt.expectedOutput), len(actualChangeList), "len(expectedChangeList) and len(actualChangeList) should match")
			for i, expectedItem := range tt.expectedOutput {
				assert.Equal(t, expectedItem.Operation, actualChangeList[i].Operation, fmt.Sprintf("operation on changelist[%d] does not match with expected", i))
				assert.Equal(t, expectedItem.Operation, actualChangeList[i].Operation, fmt.Sprintf("operation on changelist[%d] does not match with expected", i))
			}
		})
	}
}

func TestResync(t *testing.T) {
	fakeClientset := fake.NewSimpleClientset()
	adIndexInformer := adInformer.NewAthenzDomainInformer(fakeClientset, 0, cache.Indexers{})
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
