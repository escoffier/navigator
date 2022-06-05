package kubemonitor

import (
	"context"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	name = "kubiscanMonitor"
)

type KubeStorageFactory func(clusterName string) KubeStorage

type KubeStorage interface {
	SetRoleRisky(name, namespace string) error
	SetClusterRoleRisky(name string) error
	RemoveRole(name, namespace string) (existed bool, err error)
	RemoveClusterRole(name string) (existed bool, err error)
	IsRoleRisky(name, namespace string) bool
	IsClusterRoleRisky(name string) bool
}

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

type RiskSignal struct {
	Ctxs          []ContextKV
	CtxIdentifier string
}
type ContextKV struct {
	Key          string
	KeyMulti     map[string]string
	ValueMulti   map[string]string
	DefaultValue string
}

type ResourceMonitorRule interface {
	RuleName() string
	Description() map[string]string // supports multi-lang
	KVs() []ContextKV
	Severity() uint32 // 0~10
	// Match could generate multiple events by multiple []ContextKV
	Match(ctx context.Context, resource *assets.TensorResource) ([]RiskSignal, error)
}

type Configuration struct {
	RBRules       []*RiskyRoleItem
	ResourceRules []ResourceMonitorRule
}
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

type ResourceIdentifier struct {
	Name       string
	Kind       string
	Namespace  string
	ClusterKey string
}
type KubeMonitorEvent struct {
	ClusterKey    string
	TargetObject  ResourceIdentifier
	ContextKVs    []ContextKV
	RuleName      string
	identity      string
	ctxIdentifier string
}

func (e *KubeMonitorEvent) Identity() string {
	if e.identity == "" {
		fixedID := strings.Join([]string{
			e.ClusterKey,
			e.TargetObject.Namespace,
			e.TargetObject.Kind,
			e.TargetObject.Name,
		}, "/")

		sb := strings.Builder{}
		sb.WriteString(fixedID)
		sb.WriteRune('-')
		sb.WriteString(e.RuleName)
		if e.ctxIdentifier != "" {
			sb.WriteRune('-')
			sb.WriteString(e.ctxIdentifier)
		}
		e.identity = sb.String()
		logging.Get().Info().Msgf("kb event id: %s", e.identity)
	}
	return e.identity
}
