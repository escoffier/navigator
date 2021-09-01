package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	TypeAssertErr = errors.New("type cast error")
)

type MatchExpression struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}
type LabelSelector struct {
	MatchLabels      map[string]string                 `json:"matchLabels"`
	MatchExpressions []metav1.LabelSelectorRequirement `json:"matchExpressions"`
}

func (ls *LabelSelector) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &ls)
}
func (ls *LabelSelector) Value() (driver.Value, error) {
	return json.Marshal(ls)
}

type OwnerReference struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}
type OwnerRefs []OwnerReference

func (or OwnerRefs) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &or)
}
func (or OwnerRefs) Value() (driver.Value, error) {
	return json.Marshal(or)
}

type Labels map[string]string

func (l Labels) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &l)
}
func (l Labels) Value() (driver.Value, error) {
	return json.Marshal(l)
}

type PodTemplate struct {
	InitContainers     []corev1.Container         `json:"initContainers"`
	Containers         []corev1.Container         `json:"containers"`
	ServiceAccountName string                     `json:"serviceAccountName"`
	NodeName           string                     `json:"nodeName"`
	HostNetwork        bool                       `json:"hostNetwork"`
	HostPID            bool                       `json:"hostPID"`
	HostIPC            bool                       `json:"hostIPC"`
	ImagePullSecrets   []string                   `json:"imagePullSecrets,omitempty"`
	SecurityContext    *corev1.SecurityContext    `json:"securityContext,omitempty"`
	PodSecurityContext *corev1.PodSecurityContext `json:"podSecurityContext,omitempty"`
}

func (pt *PodTemplate) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &pt)
}
func (l *PodTemplate) Value() (driver.Value, error) {
	return json.Marshal(l)
}

type TensorResource struct {
	TableBase                      // id: cluster_key/namespace/kind/resource_name
	Name            string         `gorm:"column:name"`
	Namespace       string         `gorm:"column:namespace;index:idx_list_q,priority:2"`
	ClusterKey      string         `gorm:"column:cluster_key;index:idx_list_q,priority:1"`
	UID             string         `gorm:"column:uid"`
	Kind            string         `gorm:"column:kind;index:idx_list_q,priority:3"`
	LabelSelector   *LabelSelector `gorm:"column:label_selector;type:jsonb"`
	OwnerReferences OwnerRefs      `gorm:"column:owner_references;type:jsonb"`
	Labels          Labels         `gorm:"column:labels;type:jsonb"`
	PodTemplate     *PodTemplate   `gorm:"column:pod_template;type:jsonb"`
}

func (TensorResource) TableName() string {
	return "tensor_resources"
}

type ContainerPorts []corev1.ContainerPort

func (p ContainerPorts) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &p)
}
func (p ContainerPorts) Value() (driver.Value, error) {
	return json.Marshal(p)
}

type SecurityContext corev1.SecurityContext

func (sc *SecurityContext) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &sc)
}
func (sc *SecurityContext) Value() (driver.Value, error) {
	return json.Marshal(sc)
}

type ContainerSpec corev1.Container

func (sc *ContainerSpec) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &sc)
}
func (sc *ContainerSpec) Value() (driver.Value, error) {
	return json.Marshal(sc)
}

type TensorContainer struct {
	TableBase                         // id: cluster_key/namespace/kind/resource_name/container_name
	Name            string            `gorm:"column:name"`
	ResourceName    string            `gorm:"column:resource_name;index:idx_list_q,priority:4"`
	Namespace       string            `gorm:"column:namespace;index:idx_list_q,priority:2"`
	ClusterKey      string            `gorm:"column:cluster_key;index:idx_list_q,priority:1"`
	ResourceKind    string            `gorm:"column:resource_kind;index:idx_list_q,priority:3"`
	Image           string            `gorm:"column:image"`
	Spec            *ContainerSpec    `gorm:"column:spec;type:jsonb"`
	Ports           ContainerPorts    `gorm:"column:ports;type:jsonb"`
	ImagePullPolicy corev1.PullPolicy `gorm:"column:image_pull_policy;type:jsonb"`
	SecurityContext *SecurityContext  `gorm:"column:security_context;type:jsonb"`
}

func (TensorContainer) TableName() string {
	return "tensor_containers"
}

type TensorNamespace struct {
	TableBase                 // id: cluster_key/namespace
	Name            string    `gorm:"column:name"`
	ClusterKey      string    `gorm:"column:cluster_key;index:idx_list_q"`
	UID             string    `gorm:"column:uid"`
	OwnerReferences OwnerRefs `gorm:"column:owner_references;type:jsonb"`
	Labels          Labels    `gorm:"column:labels;type:jsonb"`
}

func (TensorNamespace) TableName() string {
	return "tensor_namespaces"
}

type PodResourceRelation struct {
	TableBase              // id: cluster_key/namespace/resKind/resName/podUID
	ClusterKey      string `json:"ClusterKey" gorm:"column:cluster_key;index:idx_res,priority:1"`
	PodIP           string `json:"PodIP,omitempty"`
	PodUID          string `json:"PodUID" gorm:"column:pod_uid"`
	HostIP          string `json:"HostIP,omitempty"`
	Namespace       string `json:"Namespace" gorm:"column:namespace;index:idx_res,priority:2"`
	PodName         string `json:"PodName"`
	ResourceName    string `json:"ResourceName" gorm:"column:resource_name;index:idx_res,priority:4"`
	ResourceKind    string `json:"ResourceKind" gorm:"column:resource_kind;index:idx_res,priority:3"`
	CreateTimestamp int64  `json:"CreateTimestamp" gorm:"-"`
}

func (PodResourceRelation) TableName() string {
	return "tensor_pod_res_relations"
}

type ClusterType string

const (
	HostCluster   ClusterType = "host_cluster"
	MemberCluster ClusterType = "member_cluster"
)

type TensorCluster struct {
	Key                 string      `gorm:"column:key;primaryKey" json:"key"`
	Name                string      `gorm:"column:name" json:"name"`
	Description         string      `gorm:"column:description" json:"description"`
	ClusterType         ClusterType `gorm:"column:cluster_type" json:"cluster_type"`
	APIServerAddr       string      `gorm:"column:api_server_addr" json:"apiServerAddr"`
	CertificateAuthData string      `gorm:"column:certificate_auth_data" json:"certificateAuthData"`
	SecretToken         string      `gorm:"column:secret_token" json:"secretToken"`
	SecretNamespace     string      `gorm:"column:secret_namespace" json:"secretNamespace"`
	Creator             string      `gorm:"column:creator" json:"creator"`
	CreatedAt           time.Time   `gorm:"column:created_at" json:"createdAt"`
	Updater             string      `gorm:"column:updater" json:"updater"`
	UpdatedAt           time.Time   `gorm:"column:updated_at" json:"updatedAt"`
	Status              int32       `gorm:"column:status"`
}

func (TensorCluster) TableName() string {
	return "tensor_clusters"
}
