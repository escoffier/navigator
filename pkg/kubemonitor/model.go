package kubemonitor

import (
	rbacv1 "k8s.io/api/rbac/v1"
)

type Priority string
type RoleType string
type Kind string

const (
	PriorityNone     Priority = "NONE"
	PriorityLow      Priority = "LOW"
	PriorityMedium   Priority = "MEDIUM"
	PriorityHigh     Priority = "HIGH"
	PriorityCritical Priority = "CRITICAL"

	RoleTypeRole        RoleType = "Role"
	RoleTypeClusterRole RoleType = "ClusterRole"

	KindRole               Kind = "Role"
	KindClusterRole        Kind = "ClusterRole"
	KindRoleBinding        Kind = "RoleBinding"
	KindClusterRoleBinding Kind = "ClusterRoleBinding"
	KindUser               Kind = "User"
	KindGroup              Kind = "Group"
	KindServiceAccount     Kind = "ServiceAccount"
)

type RiskyRoleItem struct {
	Kind     Kind     `yaml:"kind"`
	Metadata MetaData `yaml:"metadata" json:"metadata"`
	Rules    []Rule   `yaml:"rules" json:"rules"`
}

type Rule struct {
	APIGroups     []string `yaml:"apiGroups" json:"apiGroups"`
	Resources     []string `yaml:"resources" json:"resources"`
	ResourceNames []string `yaml:"resourceNames" json:"resourceNames"`
	Verbs         []string `yaml:"verbs" json:"verbs"`
}

type MetaData struct {
	Namespace   string   `yaml:"namespace" json:"namespace"`
	Name        string   `yaml:"name" json:"name"`
	Priority    Priority `yaml:"priority"`
	Description struct {
		Risk      string `yaml:"risk" json:"risk"`
		RiskCN    string `yaml:"riskCN" json:"riskCN"`
		Verb      string `yaml:"verb" json:"verb"`
		Resources string `yaml:"resources" json:"resources"`
		Example   string `yaml:"example" json:"example"`
	} `yaml:"description" json:"description"`
}

type KubeMonitorEvent struct {
	Cluster                  string
	RiskyItems               []*RiskyRoleItem
	Kind                     Kind
	TargetRole               *rbacv1.Role
	TargetClusterRole        *rbacv1.ClusterRole
	TargetRoleBinding        *rbacv1.RoleBinding
	TargetClusterRoleBinding *rbacv1.ClusterRoleBinding
	targetObject             KubeObject
}

type KubeObject interface {
	GetName() string
	GetNamespace() string
}

func (e KubeMonitorEvent) GetTargetName() string {
	if e.targetObject == nil {
		return "unknown"
	}
	return e.targetObject.GetName()
}
func (e KubeMonitorEvent) GetTargetNamespace() string {
	if e.targetObject == nil {
		return "unknown"
	}
	return e.targetObject.GetNamespace()
}
