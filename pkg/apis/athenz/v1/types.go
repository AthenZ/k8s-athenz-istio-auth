package v1

import (
	"github.com/jinzhu/copier"
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
	out := new(AthenzDomainSpec)
	*out = *in
	if err := copier.Copy(&out.SignedDomain, &in.SignedDomain); err != nil {
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
