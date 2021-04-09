package integration

import (
	"github.com/ardielle/ardielle-go/rdl"
	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/fixtures"
	"github.com/yahoo/k8s-athenz-istio-auth/test/integration/framework"
	athenzdomain "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	"istio.io/api/security/v1beta1"
	"istio.io/istio/pilot/pkg/model"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"reflect"
	"testing"
	"time"
)

// rolloutAndValidateAuthorizationPolicyScenario will perform the specified actions for the Athenz Domain and k8s services
// and then validate that the AuthroizationPolicy's Spec created is same as the expected
func rolloutAndValidateAuthorizationPolicyScenario(t *testing.T, e *fixtures.ExpectedV2Rbac, athenzAction action, serviceAction action) {
	applyAthenzDomain(t, e.AD, athenzAction)
	applyServices(t, e.Services, serviceAction)
	validateAuthorizationPolicy(t, e.AuthorizationPolicies)
}

// createServiceObjects - Creates the list of kubernetes service objects as passed in
func createServiceObjects(t *testing.T, services []*v1.Service) {
	for _, service := range services {
		_, err := framework.Global.K8sClientset.CoreV1().Services(service.Namespace).Create(service)
		assert.Nil(t, err, "service create error should be nil")
	}
}

// updateServiceObjects - Updates the list of Kubernetes serivce objects as passed in
func updateServiceObjects(t *testing.T, services []*v1.Service) {
	for _, service := range services {
		currentService, err := framework.Global.K8sClientset.CoreV1().Services(service.Namespace).Get(service.Name, metav1.GetOptions{})
		assert.Nil(t, err, "service get error should be nil")
		service.ResourceVersion = currentService.ResourceVersion
		service.Spec.ClusterIP = currentService.Spec.ClusterIP
		_, err = framework.Global.K8sClientset.CoreV1().Services(service.Namespace).Update(service)
		assert.Nil(t, err, "service update error should be nil")
	}
}

// deleteServiceObjects - Delete the list of kubernetes services passed in
func deleteServiceObjects(t *testing.T, services []*v1.Service) {
	for _, service := range services {
		err := framework.Global.K8sClientset.CoreV1().Services(service.Namespace).Delete(service.Name, &metav1.DeleteOptions{})
		assert.Nil(t, err, "service delete error should be nil")
	}
	services = []*v1.Service{}
}

// cleanupAuthorizationRbac Deletes the Athenz domains and deletes the services
func cleanupAuthorizationRbac(t *testing.T, e *fixtures.ExpectedV2Rbac) {
	applyAthenzDomain(t, e.AD, delete)
	deleteServiceObjects(t, e.Services)
}

// applyAthenzDomain Based on the action specified - creates, updates or deletes athenzDomain
func applyAthenzDomain(t *testing.T, athenzDomain *athenzdomain.AthenzDomain, a action) {
	switch a {
	case create:
		_, err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Create(athenzDomain, metav1.CreateOptions{})
		assert.Nil(t, err, "athenz domain create error should be nil")
	case update:
		currentAD, err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Get(athenzDomain.Name, metav1.GetOptions{})
		assert.Nil(t, err, "athenz domain get error should be nil")
		athenzDomain.ResourceVersion = currentAD.ResourceVersion
		_, err = framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Update(athenzDomain, metav1.UpdateOptions{})
		assert.Nil(t, err, "athenz domain update error should be nil")
	case delete:
		err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().Delete(athenzDomain.Name, metav1.DeleteOptions{})
		assert.Nil(t, err, "athenz domain delete error should be nil")
	}
}

// applyServices Based on the action specified creates, updates or deletes services
func applyServices(t *testing.T, services []*v1.Service, a action) {
	switch a {
	case create:
		createServiceObjects(t, services)
	case update:
		updateServiceObjects(t, services)
	case delete:
		deleteServiceObjects(t, services)
	}
}

// validateAuthorizationPolicy - validates that the authorizationPolicies's spec generated is same as the one passed in
func validateAuthorizationPolicy(t *testing.T, authorizationPolicies []*model.Config) {
	err := wait.PollImmediate(time.Second, time.Second*5, func() (bool, error) {
		for _, policy := range authorizationPolicies {
			got := framework.Global.IstioClientset.Get(policy.GroupVersionKind(), policy.ConfigMeta.Name, policy.ConfigMeta.Namespace)
			if got == nil {
				return false, nil
			}

			if !reflect.DeepEqual(got.Spec, policy.Spec) {
				return false, nil
			}
		}
		return true, nil
	})
	assert.Nil(t, err, "Failed to validate AuthorizationPolicy")
}

// verifyAuthorizationPolicyIsRemoved - makes sure that AuthorizationPolicy with namespace is not present.
func verifyAuthorizationPolicyIsRemoved(t *testing.T, authPolicy *model.Config) {
	err := wait.PollImmediate(time.Second, time.Second*5, func() (bool, error) {
		authPolicyList, err := framework.Global.IstioClientset.List(authPolicy.GroupVersionKind(), authPolicy.Namespace)
		if err != nil {
			return false, err
		}
		if len(authPolicyList) != 0 {
			return false, nil
		}
		return true, nil
	})
	assert.Nil(t, err, "Authorization policy list not empty")
}

// Basic test case
// 1. Athenz Domain exists, created service, checked for Authorization Policy
// Initial: No services, existing AD
// Input Actions: create service with annotation
// Output: AP created
func TestCreateAuthorizationPolicy(t *testing.T) {
	e := fixtures.GetBasicRbacV2Case(nil)
	rolloutAndValidateAuthorizationPolicyScenario(t, e, create, create)
	cleanupAuthorizationRbac(t, e)
}

// Manual update AP
// Initial: Existing service, AP, AD
// Input Actions: edit AP resource with rule addition/deletion
// Output: AP updated to match with existing AD
func TestUpdatedAuthorizationPolicyRestoresOriginal(t *testing.T) {
	// Basic setup
	// Creates Athenz Domain, Service verifies Authorization Policy
	e := fixtures.GetBasicRbacV2Case(nil)
	rolloutAndValidateAuthorizationPolicyScenario(t, e, create, create)

	// Retrieve a modified authorization policy
	modifiedResources := fixtures.GetBasicRbacV2Case(&fixtures.RbacV2Modifications{
		ModifyAthenzDomain: []func(sginedDomain *zms.SignedDomain){},
		ModifyServices:     [][]func(service *v1.Service){},
		ModifyAuthorizationPolicies: [][]func(policy *v1beta1.AuthorizationPolicy){
			[]func(policy *v1beta1.AuthorizationPolicy){
				func(policy *v1beta1.AuthorizationPolicy) {
					policy.Action = v1beta1.AuthorizationPolicy_DENY
				},
			},
		},
	})

	// Update the Authorization policy with modified value
	ap := modifiedResources.AuthorizationPolicies[0]
	authorizationPolicy := framework.Global.IstioClientset.Get(ap.GroupVersionKind(), ap.Name, ap.Namespace)
	assert.NotNil(t, authorizationPolicy, "Already set authorization policy cannot be nil")
	updatedValue := authorizationPolicy.DeepCopy()
	updatedValue.Spec = ap.Spec
	_, err := framework.Global.IstioClientset.Update(updatedValue)
	assert.Nil(t, err, "Update to Authorization policy must not fail")

	// Check that the original authorization policy is restored.
	time.Sleep(2 * time.Second)
	rolloutAndValidateAuthorizationPolicyScenario(t, e, noop, noop)
	cleanupAuthorizationRbac(t, e)
}

// Manual delete AP
// Initial: Existing service, AP, AD
// Input Actions: delete AP resource
// Output: AP recreated to match with existing AD
func TestDeleteAuthorizationPolicyRestoresOriginal(t *testing.T) {
	// Initial set up
	e := fixtures.GetBasicRbacV2Case(nil)
	rolloutAndValidateAuthorizationPolicyScenario(t, e, create, create)

	// Delete the Authorization policy created
	ap := e.AuthorizationPolicies[0]
	err := framework.Global.IstioClientset.Delete(ap.GroupVersionKind(), ap.Name, ap.Namespace)
	assert.Nil(t, err, "Delete of authorization policy should not fail")

	time.Sleep(5 * time.Second)

	// Verification and cleanup
	rolloutAndValidateAuthorizationPolicyScenario(t, e, noop, noop)
	cleanupAuthorizationRbac(t, e)
}

// Update AP
// Initial: Existing service with annotation, AP
// Input Actions: update athenz domain with service related role, or policies associated to the role
// Output: AP updated
func TestUpdateAuthorizationPolicyUpdatesAuthorizationPolicy(t *testing.T) {
	// Initial set up
	e := fixtures.GetBasicRbacV2Case(nil)
	rolloutAndValidateAuthorizationPolicyScenario(t, e, create, create)

	// Get updated fixtures
	newUserName := "user.bar"
	modified := fixtures.GetBasicRbacV2Case(&fixtures.RbacV2Modifications{
		ModifyAthenzDomain: []func(signedDomain *zms.SignedDomain){
			func(signedDomain *zms.SignedDomain) {
				signedDomain.Domain.Roles[0].Members = append(signedDomain.Domain.Roles[0].Members, zms.MemberName(newUserName))
				signedDomain.Domain.Roles[0].RoleMembers = append(signedDomain.Domain.Roles[0].RoleMembers, &zms.RoleMember{MemberName: zms.MemberName(newUserName)})
			},
		},
		ModifyAuthorizationPolicies: [][]func(policy *v1beta1.AuthorizationPolicy){
			[]func(policy *v1beta1.AuthorizationPolicy){
				func(policy *v1beta1.AuthorizationPolicy) {
					policy.Rules[0].From[0].Source.Principals = append(policy.Rules[0].From[0].Source.Principals, "user/sa/bar")
					principals := policy.Rules[0].From[0].Source.Principals
					principals[1], principals[2] = principals[2], principals[1]
					requestPrincipals := []string{policy.Rules[0].From[1].Source.RequestPrincipals[0], "athenz/user.bar"}
					policy.Rules[0].From[1].Source.RequestPrincipals = requestPrincipals
				},
			},
		},
	})

	rolloutAndValidateAuthorizationPolicyScenario(t, modified, update, noop)
	cleanupAuthorizationRbac(t, modified)
}

// Initial: Existing service with annotation, AP
// Input Actions: delete athenz domain which matches service’s namespace
// Output: AP not deleted
func TestDeleteAthenzDomainShouldDeleteAuthorizationPolicy(t *testing.T) {
	// Initial set up
	e := fixtures.GetBasicRbacV2Case(nil)
	rolloutAndValidateAuthorizationPolicyScenario(t, e, create, create)

	// Delete athenz Domain
	applyAthenzDomain(t, e.AD, delete)

	time.Sleep(2 * time.Second)

	// Validate Athenz Domain has been removed
	err := wait.PollImmediate(time.Second, time.Second*5, func() (bool, error) {
		athenzDomainList, err := framework.Global.AthenzDomainClientset.AthenzV1().AthenzDomains().List(metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		if len(athenzDomainList.Items) != 0 {
			return false, nil
		}
		return true, nil
	})
	assert.Nil(t, err, "Athenz domain should be removed without errors")

	time.Sleep(30 * time.Second)

	// Validate Authorization Policy has been removed
	rolloutAndValidateAuthorizationPolicyScenario(t, e, noop, noop)

	// Cleanup
	deleteServiceObjects(t, e.Services)
}

// Initial: Existing service with annotation, AP
// Input Actions: delete service with annotation
// Output: AP deleted
func TestDeleteServiceShouldDeleteAuthorizationPolicy(t *testing.T) {
	// Initial set up
	e := fixtures.GetBasicRbacV2Case(nil)
	rolloutAndValidateAuthorizationPolicyScenario(t, e, create, create)

	// Delete athenz Domain
	applyServices(t, e.Services, delete)

	time.Sleep(2 * time.Second)

	// Validate Athenz Domain has been removed
	namespace := e.Services[0].Namespace
	err := wait.PollImmediate(time.Second, time.Second*5, func() (bool, error) {
		servicesList, err := framework.Global.K8sClientset.CoreV1().Services(namespace).List(metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		if len(servicesList.Items) != 0 {
			return false, nil
		}
		return true, nil
	})

	// Validate Authorization Policy has been removed
	verifyAuthorizationPolicyIsRemoved(t, e.AuthorizationPolicies[0])

	assert.Nil(t, err, "Authorization policy list not empty")

	// Cleanup
	// Service is already removed
	// Only remove the athenz domain now
	applyAthenzDomain(t, e.AD, delete)
}

// Initial: Existing service with annotation, AP
// Input Actions: delete service annotation
// Output: AP deleted
func TestRemoveAnnotationFromServiceShouldDeleteAuthorizationPolicy(t *testing.T) {
	// Initial set up
	e := fixtures.GetBasicRbacV2Case(nil)
	rolloutAndValidateAuthorizationPolicyScenario(t, e, create, create)

	// Remove the annotation from the service
	updatedValues := fixtures.GetBasicRbacV2Case(&fixtures.RbacV2Modifications{
		ModifyServices: [][]func(service *v1.Service){
			{
				func(service *v1.Service) {
					service.Annotations = make(map[string]string)
				},
			},
		},
	})
	// Apply the updated service
	applyServices(t, updatedValues.Services, update)

	// Verify that the Authorization policy is removed
	verifyAuthorizationPolicyIsRemoved(t, e.AuthorizationPolicies[0])

	// Cleanup resources
	cleanupAuthorizationRbac(t, e)
}

// Initial: Existing service with annotation, AP
// Input Actions: add an athenz role member with expiry
// Output: after member expired, AP update with this member removal
func TestUpdateAuthorizationPolicyRemovingExpiredMembers(t *testing.T) {
	// Initial set up
	e := fixtures.GetBasicRbacV2Case(nil)
	rolloutAndValidateAuthorizationPolicyScenario(t, e, create, create)

	// Update Athenz Domain with an expiring member
	// Get updated fixtures
	newUserName := "user.bar"
	value := time.Now().Add(time.Second * time.Duration(30))
	expiringTimestamp := rdl.NewTimestamp(value)
	modified := fixtures.GetBasicRbacV2Case(&fixtures.RbacV2Modifications{
		ModifyAthenzDomain: []func(signedDomain *zms.SignedDomain){
			func(signedDomain *zms.SignedDomain) {
				newRoleMember := &zms.RoleMember{
					MemberName: zms.MemberName(newUserName),
					Expiration: &expiringTimestamp,
				}
				signedDomain.Domain.Roles[0].Members = append(signedDomain.Domain.Roles[0].Members, zms.MemberName(newUserName))
				signedDomain.Domain.Roles[0].RoleMembers = append(signedDomain.Domain.Roles[0].RoleMembers, newRoleMember)
			},
		},
		ModifyAuthorizationPolicies: [][]func(policy *v1beta1.AuthorizationPolicy){
			[]func(policy *v1beta1.AuthorizationPolicy){
				func(policy *v1beta1.AuthorizationPolicy) {
					policy.Rules[0].From[0].Source.Principals = append(policy.Rules[0].From[0].Source.Principals, "user/sa/bar")
					principals := policy.Rules[0].From[0].Source.Principals
					principals[1], principals[2] = principals[2], principals[1]
					requestPrincipals := []string{policy.Rules[0].From[1].Source.RequestPrincipals[0], "athenz/user.bar"}
					policy.Rules[0].From[1].Source.RequestPrincipals = requestPrincipals
				},
			},
		},
	})

	// Rollout the modified Athenz domain and validate Authorization policy
	rolloutAndValidateAuthorizationPolicyScenario(t, modified, update, noop)

	// Wait for some time to ensure that the member expires
	time.Sleep(1 * time.Minute)

	// Now the role member should have been expired
	// So validate that the user has been removed from the Authorization policy
	rolloutAndValidateAuthorizationPolicyScenario(t, e, noop, noop)
	cleanupAuthorizationRbac(t, e)
}

// Initial: Existing service with annotation, AP
// Input Actions: add an athenz role member with systemDisabled property set to true
// Output: AP remained same without this role being added
func TestUpdateAthenzWithDisabledRoleMemberDoesNotEffectAuthorizationPolicy(t *testing.T) {
	// Initial set up
	e := fixtures.GetBasicRbacV2Case(nil)
	rolloutAndValidateAuthorizationPolicyScenario(t, e, create, create)

	// Update Athenz domain added user with system disabled property set
	newUserName := "user.bar"
	var disabled int32 = 1
	modified := fixtures.GetBasicRbacV2Case(&fixtures.RbacV2Modifications{
		ModifyAthenzDomain: []func(signedDomain *zms.SignedDomain){
			func(signedDomain *zms.SignedDomain) {
				newRoleMember := &zms.RoleMember{
					MemberName:     zms.MemberName(newUserName),
					SystemDisabled: &disabled,
				}
				signedDomain.Domain.Roles[0].Members = append(signedDomain.Domain.Roles[0].Members, zms.MemberName(newUserName))
				signedDomain.Domain.Roles[0].RoleMembers = append(signedDomain.Domain.Roles[0].RoleMembers, newRoleMember)
			},
		},
	})

	// Update Athenz domain
	rolloutAndValidateAuthorizationPolicyScenario(t, modified, update, noop)

	// Wait to ensure that domain update is picked up
	time.Sleep(30 * time.Second)

	// Validate Authorization policy
	rolloutAndValidateAuthorizationPolicyScenario(t, modified, noop, noop)

	// cleanup
	cleanupAuthorizationRbac(t, modified)
}
