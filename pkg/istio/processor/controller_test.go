package processor

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/istio/rbac/common"
	"github.com/yahoo/k8s-athenz-istio-auth/pkg/log"

	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/pilot/pkg/config/memory"
	"istio.io/istio/pilot/pkg/model"

	"k8s.io/api/core/v1"
)

func init() {
	log.InitLogger("", "debug")
}

func newSrSpec() *v1alpha1.ServiceRole {
	return &v1alpha1.ServiceRole{
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
}

func newSr(ns, role string) model.Config {
	return common.NewConfig(model.ServiceRole.Type, ns, role, newSrSpec())
}

func newSrbSpec(role string) *v1alpha1.ServiceRoleBinding {
	return &v1alpha1.ServiceRoleBinding{
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
}

func newSrb(ns, role string) model.Config {
	return common.NewConfig(model.ServiceRoleBinding.Type, ns, role, newSrbSpec(role))
}

func cacheWithItems() (model.ConfigStoreCache, error) {
	configDescriptor := model.ConfigDescriptor{
		model.ClusterRbacConfig,
		model.ServiceRole,
		model.ServiceRoleBinding,
	}

	c := memory.NewController(memory.Make(configDescriptor))
	_, err := c.Create(newSr("test-ns", "test-svc"))
	if err != nil {
		return nil, err
	}
	_, err = c.Create(newSrb("test-ns", "test-svc"))
	if err != nil {
		return nil, err
	}
	return c, nil
}

func TestSync(t *testing.T) {

	configDescriptor := model.ConfigDescriptor{
		model.ClusterRbacConfig,
		model.ServiceRole,
		model.ServiceRoleBinding,
	}

	errHandler := func(err error, i *Item) error {
		assert.Fail(t, "CallbackHandler should not be called")
		return nil
	}

	updateTestCache, err := cacheWithItems()
	assert.Nil(t, err, "error should be nil while setting up cache")

	tests := []struct {
		name          string
		input         *Item
		startingCache model.ConfigStoreCache
		expectedCache model.ConfigStoreCache
		expectedErr   error
	}{
		{
			name:          "should not perfom any cache op on nil item",
			input:         nil,
			startingCache: memory.NewController(memory.Make(configDescriptor)),
			expectedCache: memory.NewController(memory.Make(configDescriptor)),
			expectedErr:   nil,
		},
		{
			name: "should perfom valid create operation",
			input: &Item{
				Operation:       model.EventAdd,
				Resource:        newSr("test-ns", "test-role"),
				CallbackHandler: errHandler,
			},
			startingCache: memory.NewController(memory.Make(configDescriptor)),
			expectedCache: func() model.ConfigStoreCache {
				c := memory.NewController(memory.Make(configDescriptor))
				_, err := c.Create(newSr("test-ns", "test-role"))
				assert.Nil(t, err, fmt.Sprintf("unexpected error while setting up expectedCache: %s", err))
				return c
			}(),
			expectedErr: nil,
		},
		{
			name: "should perform valid update operation",
			input: &Item{
				Operation: model.EventUpdate,
				Resource: func() model.Config {
					obj := updateTestCache.Get(model.ServiceRole.Type, "test-svc", "test-ns")
					assert.NotNil(t, obj, "cache should return the ServiceRole resource")
					srSpec, ok := (obj.Spec).(*v1alpha1.ServiceRole)
					assert.True(t, ok, "cache should return a ServiceRole resource")
					srSpec.Rules = append(srSpec.Rules, &v1alpha1.AccessRule{
						Services: []string{common.WildCardAll},
						Methods:  []string{"POST"},
						Constraints: []*v1alpha1.AccessRule_Constraint{
							{
								Key:    common.ConstraintSvcKey,
								Values: []string{"test-svc"},
							},
						},
					})
					return *obj
				}(),
				CallbackHandler: errHandler,
			},
			startingCache: updateTestCache,
			expectedCache: func() model.ConfigStoreCache {
				c := memory.NewController(memory.Make(configDescriptor))
				srSpec := newSrSpec()
				srSpec.Rules = append(srSpec.Rules, &v1alpha1.AccessRule{
					Services: []string{common.WildCardAll},
					Methods:  []string{"POST"},
					Constraints: []*v1alpha1.AccessRule_Constraint{
						{
							Key:    common.ConstraintSvcKey,
							Values: []string{"test-svc"},
						},
					},
				})
				_, err := c.Create(common.NewConfig(model.ServiceRole.Type, "test-ns", "test-svc", srSpec))
				assert.Nil(t, err, fmt.Sprintf("unexpected error while setting up expectedCache: %s", err))
				_, err = c.Create(newSrb("test-ns", "test-svc"))
				assert.Nil(t, err, fmt.Sprintf("unexpected error while setting up expectedCache: %s", err))

				return c
			}(),
			expectedErr: nil,
		},
		{
			name: "should perfom valid delete operation",
			input: &Item{
				Operation:       model.EventDelete,
				Resource:        newSr("test-ns", "test-svc"),
				CallbackHandler: errHandler,
			},
			startingCache: func() model.ConfigStoreCache {
				c, err := cacheWithItems()
				assert.Nil(t, err, "error should be nil while setting up cache")
				return c
			}(),
			expectedCache: func() model.ConfigStoreCache {
				c := memory.NewController(memory.Make(configDescriptor))
				_, err := c.Create(newSrb("test-ns", "test-svc"))
				assert.Nil(t, err, fmt.Sprintf("unexpected error while setting up expectedCache: %s", err))
				return c
			}(),
			expectedErr: nil,
		},
		{
			name: "should return error if valid update operation",
			input: &Item{
				Operation:       model.EventUpdate,
				Resource:        newSr("test-ns", "test-svc"),
				CallbackHandler: errHandler,
			},
			startingCache: updateTestCache,
			expectedCache: updateTestCache,
			expectedErr:   fmt.Errorf("old revision"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configStoreCache := tt.startingCache
			c := NewController(configStoreCache)

			err := c.sync(tt.input)
			assert.Equal(t, tt.expectedErr, err, "sync err should match expected error")

			for _, typ := range configDescriptor.Types() {
				actualItemsT, err := configStoreCache.List(typ, v1.NamespaceAll)
				assert.Nil(t, err, fmt.Sprintf("error should be nil while fetching %s resources: %s", typ, err))

				expectedItemsT, err := tt.expectedCache.List(typ, v1.NamespaceAll)
				assert.Nil(t, err, fmt.Sprintf("error should be nil whil efetching %s resources: %s", typ, err))

				assert.Equal(t, len(expectedItemsT), len(actualItemsT), fmt.Sprintf("len(list) of %s resources on the cache should match", typ))
				if len(expectedItemsT) == len(actualItemsT) {
					for i, expItem := range expectedItemsT {
						assert.Equal(t, expItem.Type, actualItemsT[i].Type, "type should match")
						assert.Equal(t, expItem.Namespace, actualItemsT[i].Namespace, "namespace should match")
						assert.Equal(t, expItem.Name, actualItemsT[i].Name, "name should match")
						assert.Equal(t, expItem.Spec, actualItemsT[i].Spec, "spec should match")
					}
				}
			}
		})
	}
}
