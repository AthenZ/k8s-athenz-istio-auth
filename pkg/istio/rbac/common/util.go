// Copyright 2021, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package common

import (
	"fmt"
	"github.com/gogo/protobuf/proto"
	"github.com/yahoo/athenz/clients/go/zms"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/collection"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	allUsers                     = "user.*"
	WildCardAll                  = "*"
	ServiceRoleKind              = "ServiceRole"
	AthenzJwtPrefix              = "athenz/"
	RequestAuthPrincipalProperty = "request.auth.principal"
)

var supportedMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodPost:    true,
	http.MethodPut:     true,
	http.MethodPatch:   true,
	http.MethodDelete:  true,
	http.MethodConnect: true,
	http.MethodOptions: true,
	http.MethodTrace:   true,
	"*":                true,
}

type Item struct {
	Operation model.Event
	Resource  model.Config
	// Handler function that should be invoked with the status of the current sync operation on the item
	// If the handler returns an error, the operation is retried up to `queueNumRetries`
	CallbackHandler OnCompleteFunc
}

type OnCompleteFunc func(err error, item *Item) error
type checkAnnotaion func(model.Config) bool

var resourceRegex = regexp.MustCompile(`\A(?P<domain>.*):svc.(?P<svc>[^:]*)[:]?(?P<path>.*)\z`)

// MemberToSpiffe parses the Athenz role member into a SPIFFE compliant name.
// Example: example.domain/sa/service
func MemberToSpiffe(member *zms.RoleMember) (string, error) {

	if member == nil {
		return "", fmt.Errorf("member is nil")
	}

	memberStr := string(member.MemberName)

	// special condition: if member == 'user.*', return '*'
	if memberStr == allUsers {
		return WildCardAll, nil
	}

	return PrincipalToSpiffe(memberStr)
}

// MemberToOriginSubject parses the Athenz role member into the request.auth.principal
// jwt format. Example: athenz/example.domain.service
func MemberToOriginJwtSubject(member *zms.RoleMember) (string, error) {

	if member == nil {
		return "", fmt.Errorf("member is nil")
	}

	memberStr := string(member.MemberName)

	// special condition: if member == 'user.*', return '*'
	if memberStr == allUsers {
		return WildCardAll, nil
	}

	requestAuthPrincipal := AthenzJwtPrefix + memberStr
	return requestAuthPrincipal, nil
}

// RoleToSpiffe reads athenz role name string, and generates the SPIFFE name of it
// SPIFFE name format: <athenz domain name>/ra/<role name>
func RoleToSpiffe(athenzDomainName string, roleName string) (string, error) {
	if len(athenzDomainName) == 0 {
		return "", fmt.Errorf("athenzDomainName is empty")
	}
	if len(roleName) == 0 {
		return "", fmt.Errorf("roleName is empty")
	}
	spiffeName := fmt.Sprintf("%s/ra/%s", athenzDomainName, roleName)
	return spiffeName, nil
}

// PrincipalToSpiffe converts the Athenz principal into a SPIFFE compliant format
// e.g. client-domain.frontend.some-app -> client-domain.frontend/sa/some-app
func PrincipalToSpiffe(principal string) (string, error) {
	if len(principal) == 0 {
		return "", fmt.Errorf("principal is empty")
	}
	i := strings.LastIndex(principal, ".")
	if i < 0 {
		return "", fmt.Errorf("principal:%s is not of the format <Athenz-domain>.<Athenz-service>", principal)
	}
	memberDomain, memberService := principal[:i], principal[i+1:]
	spiffeName := fmt.Sprintf("%s/sa/%s", memberDomain, memberService)
	return spiffeName, nil
}

// ParseAssertionEffect parses the effect of an assertion into a supported Istio RBAC action
func ParseAssertionEffect(assertion *zms.Assertion) (string, error) {
	if assertion == nil {
		return "", fmt.Errorf("assertion is nil")
	}
	effect := assertion.Effect
	if effect == nil {
		return "", fmt.Errorf("assertion effect is nil")
	}
	if strings.ToUpper(effect.String()) != zms.ALLOW.String() {
		return "", fmt.Errorf("effect: %s is not a supported assertion effect", effect)
	}
	return zms.ALLOW.String(), nil
}

// ParseAssertionAction parses the action of an assertion into a supported Istio RBAC HTTP method
func ParseAssertionAction(assertion *zms.Assertion) (string, error) {
	if assertion == nil {
		return "", fmt.Errorf("assertion is nil")
	}
	method := strings.ToUpper(assertion.Action)
	if !supportedMethods[method] {
		return "", fmt.Errorf("method: %s is not a supported HTTP method", assertion.Action)
	}
	return method, nil
}

// ParseAssertionResource parses the resource of an action into the service name (AccessRule constraint) and the
// HTTP paths if specified (suffix :<path>)
func ParseAssertionResource(domainName zms.DomainName, assertion *zms.Assertion) (string, string, error) {
	if assertion == nil {
		return "", "", fmt.Errorf("assertion is nil")
	}
	var svc string
	var path string
	resource := assertion.Resource
	parts := resourceRegex.FindStringSubmatch(resource)
	names := resourceRegex.SubexpNames()
	results := map[string]string{}
	for i, part := range parts {
		results[names[i]] = part
	}

	for name, match := range results {
		switch name {
		case "domain":
			if match != string(domainName) {
				return "", "", fmt.Errorf("resource: %s does not belong to the Athenz domain: %s", resource, domainName)
			}
		case "svc":
			svc = match
		case "path":
			path = match
		}
	}

	if svc == "" {
		return "", "", fmt.Errorf("resource: %s does not specify the service using svc.<service-name> format", resource)
	}
	return svc, path, nil
}

// CheckAthenzSystemDisabled checks if athenz domain is systematically disabled, if so, controller skips processing current
// role member
func CheckAthenzSystemDisabled(roleMember *zms.RoleMember) (bool, error) {
	if roleMember == nil {
		return false, fmt.Errorf("got an empty role Member: %s, skipping", roleMember.MemberName)
	}
	if roleMember.SystemDisabled != nil && *roleMember.SystemDisabled != 0 {
		return false, fmt.Errorf("member %s is system disabled", roleMember.MemberName)
	}
	return true, nil
}

// CheckAthenzMemberExpiry checks if Expiration field (timezone UTC) is set in the roleMember object, and then
// checks if expiration date surpasses current time
func CheckAthenzMemberExpiry(roleMember *zms.RoleMember) (bool, error) {
	if roleMember == nil {
		return false, fmt.Errorf("got an empty role Member: %s, skipping", roleMember.MemberName)
	}
	// check if roleMember has expiration field set
	if roleMember.Expiration != nil && roleMember.Expiration.Before(time.Now()) {
		return false, fmt.Errorf("member %s is expired", roleMember.MemberName)
	}
	return true, nil
}

// ParseRoleFQDN parses the Athenz role full name in the format <domainName>:role.<roleName> to roleName
// e.g. app-domain:role.reader -> reader
func ParseRoleFQDN(domainName zms.DomainName, roleFQDN string) (string, error) {
	roleName := strings.TrimPrefix(roleFQDN, fmt.Sprintf("%s:role.", domainName))
	if strings.Contains(roleName, ":") {
		return "", fmt.Errorf("role: %s does not belong to the Athenz domain: %s", roleFQDN, domainName)
	}
	return roleName, nil
}

// NewConfig returns a new model.Config resource for the passed-in type with the given namespace/name and spec
func NewConfig(schema collection.Schema, namespace string, name string, spec proto.Message) model.Config {
	meta := model.ConfigMeta{
		Type:      schema.Resource().Kind(),
		Group:     schema.Resource().Group(),
		Version:   schema.Resource().Version(),
		Namespace: namespace,
		Name:      name,
	}
	return model.Config{
		ConfigMeta: meta,
		Spec:       spec,
	}
}

// ConvertSliceToKeyedMap converts the input model.Config slice into a map with (type/namespace/name) formatted key
func ConvertSliceToKeyedMap(in []model.Config) map[string]model.Config {
	out := make(map[string]model.Config, len(in))
	for _, c := range in {
		key := c.Key()
		out[key] = c
	}
	return out
}

// Equal compares the Spec of two model.Config items
func Equal(c1, c2 model.Config) bool {
	return c1.Key() == c2.Key() && proto.Equal(c1.Spec, c2.Spec)
}

// ComputeChangeList checks if two set of config models have any differences, and return its changeList
// Controller which calls this function is required to pass its own callback handler
// checkFn is optional, can be set to nil if nothing needs to be checked
func ComputeChangeList(currentCRs []model.Config, desiredCRs []model.Config, cbHandler OnCompleteFunc, checkFn checkAnnotaion) []*Item {
	currMap := ConvertSliceToKeyedMap(currentCRs)
	desiredMap := ConvertSliceToKeyedMap(desiredCRs)

	changeList := make([]*Item, 0)

	// loop through the desired slice of model.Config and add the items that need to be created or updated
	for _, desiredConfig := range desiredCRs {
		key := desiredConfig.Key()
		existingConfig, exists := currMap[key]
		// case 1: current CR is empty, desired CR is not empty, results in resource creation
		if !exists {
			item := Item{
				Operation:       model.EventAdd,
				Resource:        desiredConfig,
				CallbackHandler: cbHandler,
			}
			changeList = append(changeList, &item)
			continue
		}

		if !Equal(existingConfig, desiredConfig) {
			// case 2: current CR is not empty, desired CR is not empty, current CR != desired CR, no overrideAnnotation set in current CR, results in resource update
			if checkFn != nil && checkFn(existingConfig) {
				continue
			}
			// copy metadata(for resource version) from current config to desired config
			desiredConfig.ConfigMeta = existingConfig.ConfigMeta
			item := Item{
				Operation:       model.EventUpdate,
				Resource:        desiredConfig,
				CallbackHandler: cbHandler,
			}
			changeList = append(changeList, &item)
			continue
		}
		// case 3: current CR is not empty, desired CR is not empty, current CR == desired CR, results in no action
	}

	// loop through the current slice of model.Config and add the items that needs to be deleted
	for _, currConfig := range currentCRs {
		key := currConfig.Key()
		_, exists := desiredMap[key]
		if checkFn != nil && checkFn(currConfig) {
			continue
		}
		// case 4: current CR is not empty, desired CR is empty, results in resource deletion
		if !exists {
			item := Item{
				Operation:       model.EventDelete,
				Resource:        currConfig,
				CallbackHandler: cbHandler,
			}
			changeList = append(changeList, &item)
		}
	}

	return changeList
}
