// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package v1

import (
	"github.com/mohae/deepcopy"
	"github.com/yahoo/athenz/clients/go/zms"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AthenzDomain is a top-level type
type AthenzDomain struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Status AthenzDomainStatus `json:"status,omitempty"`

	// Athenz Domain Spec
	Spec AthenzDomainSpec `json:"spec,omitempty"`
}

// AthenzDomainSpec contains the SignedDomain object https://github.com/yahoo/athenz/clients/go/zms
type AthenzDomainSpec struct {
	zms.SignedDomain `json:",inline"`
}

// DeepCopy copies the object and returns a clone
func (in *AthenzDomainSpec) DeepCopy() *AthenzDomainSpec {
	if in == nil {
		return nil
	}
	outRaw := deepcopy.Copy(in)
	out, ok := outRaw.(*AthenzDomainSpec)
	if !ok {
		return nil
	}
	return out
}

// AthenzDomainStatus stores status information about the current resource
type AthenzDomainStatus struct {
	Message string `json:"message,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AthenzDomainList is a list of AthenzDomain items
type AthenzDomainList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AthenzDomain `json:"items"`
}
