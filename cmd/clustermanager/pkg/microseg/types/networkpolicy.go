package types

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

type NodeEndpoint struct {
	NodeName string
	Address  string
}

type NodeRule struct {
	PolicyName  string
	NodeName    string
	Priority    int
	Protocol    string
	Direction   string
	Action      string
	Ports       []v1alpha1.NetworkPolicyPort
	ToAddresses []v1alpha1.Address
	ToIPBlock   string
	FromAddress []v1alpha1.Address
	FromIPBlock string
}
type NetwokPolicy struct {
	Name           string
	AppliedAddress []v1alpha1.Address
	Rules          []NetwokPolicyRule
}

type NetwokPolicyRule struct {
	PolicyID  string
	NodeNames sets.String
	// UID unique id of rule
	UID         types.UID
	Priority    int
	Protocol    string
	Direction   string
	Ports       []v1alpha1.NetworkPolicyPort
	ToAddresses []v1alpha1.Address
	FromAddress []v1alpha1.Address
}

type AddressGroup struct {
	Name      string
	Addresses sets.String
}

type LabelsGroup struct {
	v1.LabelSelector
	labels.Selector
}

type GroupSelector struct {
	PodSeletor   labels.Selector
	NameSelector labels.Selector
	NodeSelector labels.Selector
}

func NewGroupSelector(podSelector *v1.LabelSelector, namespaceSelector *v1.LabelSelector) *GroupSelector {
	groupSelector := GroupSelector{}
	if podSelector != nil {
		groupSelector.PodSeletor, _ = v1.LabelSelectorAsSelector(podSelector)
	}
	if namespaceSelector != nil {
		groupSelector.NameSelector, _ = v1.LabelSelectorAsSelector(namespaceSelector)
	}
	return &groupSelector
}

type IngressRule struct {
	Address string
	From    sets.String
}

type EgressRule struct {
	Address string
	To      sets.String
}
