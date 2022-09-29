package model

import (
	"database/sql/driver"
	"errors"
	"strings"
	"time"

	json "github.com/json-iterator/go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	TypeAssertErr = errors.New("type cast error")
)

const (
	WebTypeNginx      = "nginx"
	WebTypeApache     = "httpd"
	WebTypeApacheName = "apache"
	WebTypeTomcat     = "tomcat"
	WebTypeKong       = "kong"
	WebTypeOpenResty  = "openresty"
	WebTypeTraefik    = "traefik"
	WebTypeApisix     = "apisix"

	DBTypeRedis       = "redis"
	DBTypePostgres    = "postgres"
	DBTypeMysql       = "mysql"
	DBTypeMariadb     = "mariadb"
	DBTypeMemcached   = "memcached"
	DBTypeMongo       = "mongo"
	DBTypeMsSQLServer = "mssql"
	DBTypeTiDB        = "tidb"
)

var (
	AppTypeWeb = "web" // Don't change: needs to refer by pointer, so it's a variable not constant
	AppTypeDB  = "database"
)

func GetDatabaseType(imageID string) (bool, string, string, error) {
	if len(imageID) == 0 {
		return false, "", "", errors.New("empty input")
	}
	idx := strings.Index(imageID, ":")
	if idx <= 0 || idx >= len(imageID)-1 {
		return false, "", "", nil
	}
	version := imageID[idx+1:]
	fullRepoName := imageID[0:idx]
	idx = strings.IndexByte(fullRepoName, '/')
	if idx <= 0 || idx >= len(fullRepoName)-1 {
		return false, "", "", nil
	}
	repoName := fullRepoName[idx+1:]
	repoName = strings.ToLower(repoName)

	if strings.Index(repoName, DBTypeRedis) >= 0 {
		return true, DBTypeRedis, version, nil
	} else if strings.Index(repoName, DBTypePostgres) >= 0 {
		return true, DBTypePostgres, version, nil
	} else if strings.Index(repoName, DBTypeMysql) >= 0 {
		return true, DBTypeMysql, version, nil
	} else if strings.Index(repoName, DBTypeMariadb) >= 0 {
		return true, DBTypeMariadb, version, nil
	} else if strings.Index(repoName, DBTypeMemcached) >= 0 {
		return true, DBTypeMemcached, version, nil
	} else if strings.Index(repoName, DBTypeMongo) >= 0 {
		return true, DBTypeMongo, version, nil
	} else if strings.Index(repoName, DBTypeMsSQLServer) >= 0 {
		return true, DBTypeMsSQLServer, version, nil
	} else if strings.Index(repoName, DBTypeTiDB) >= 0 {
		return true, DBTypeTiDB, version, nil
	}
	return false, "", "", nil
}
func GetWebType(imageID string) (bool, string, string, error) {
	if len(imageID) == 0 {
		return false, "", "", errors.New("empty input")
	}
	idx := strings.Index(imageID, ":")
	if idx <= 0 || idx >= len(imageID)-1 {
		return false, "", "", nil
	}
	version := imageID[idx+1:]
	fullRepoName := imageID[0:idx]
	idx = strings.IndexByte(fullRepoName, '/')
	if idx <= 0 || idx >= len(fullRepoName)-1 {
		return false, "", "", nil
	}
	repoName := fullRepoName[idx+1:]
	repoName = strings.ToLower(repoName)

	if strings.Index(repoName, WebTypeNginx) >= 0 {
		return true, WebTypeNginx, version, nil
	} else if strings.Index(repoName, WebTypeTomcat) >= 0 {
		return true, WebTypeTomcat, version, nil
	} else if strings.Index(repoName, WebTypeKong) >= 0 {
		return true, WebTypeKong, version, nil
	} else if strings.Index(repoName, WebTypeOpenResty) >= 0 {
		return true, WebTypeOpenResty, version, nil
	} else if strings.Index(repoName, WebTypeTraefik) >= 0 {
		return true, WebTypeTraefik, version, nil
	} else if strings.Index(repoName, WebTypeApisix) >= 0 {
		return true, WebTypeApisix, version, nil
	} else if strings.Index(repoName, WebTypeApache) >= 0 {
		return true, WebTypeApacheName, version, nil
	}
	return false, "", "", nil
}

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

func (or *OwnerRefs) Scan(value interface{}) error {
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

func (l *Labels) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &l)
}
func (l *Labels) Value() (driver.Value, error) {
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

type Managers []string

func (m *Managers) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &m)
}

func (m *Managers) Value() (driver.Value, error) {
	return json.Marshal(m)
}

type TensorResource struct {
	TableBase                      // id: cluster_key/namespace/kind/resource_name
	Name            string         `gorm:"column:name"`
	Namespace       string         `gorm:"column:namespace;index:idx_tr_list_q,priority:2"`
	ClusterKey      string         `gorm:"column:cluster_key;index:idx_tr_list_q,priority:1"`
	UID             string         `gorm:"column:uid"`
	Kind            string         `gorm:"column:kind;index:idx_tr_list_q,priority:3"`
	LabelSelector   *LabelSelector `gorm:"column:label_selector;type:varchar(256)"`
	OwnerReferences OwnerRefs      `gorm:"column:owner_references;type:varchar(256)"`
	Labels          []byte         `gorm:"column:labels;type:blob"`
	PodTemplate     *PodTemplate   `gorm:"column:pod_template;type:text"`
	Alias           string         `gorm:"column:alias"`
	Managers        Managers       `gorm:"column:managers;type:varchar(256)"`
	Authority       string         `gorm:"column:authority"`
	IsSupportDrift  bool           `gorm:"column:is_support_drift;type:boolean"`
	Reason          string         `gorm:"column:reason;type:varchar(16)"`
}

func (TensorResource) TableName() string {
	return "ivan_assets_resources"
}

type ContainerPorts []corev1.ContainerPort

func (p *ContainerPorts) Scan(value interface{}) error {
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
	TableBase                          // id: cluster_key/namespace/kind/resource_name/container_name
	Name             string            `gorm:"column:name"`
	ResourceName     string            `gorm:"column:resource_name;index:idx_tc_list_q,priority:4"`
	Namespace        string            `gorm:"column:namespace;index:idx_tc_list_q,priority:2"`
	ClusterKey       string            `gorm:"column:cluster_key;index:idx_tc_list_q,priority:1"`
	ResourceKind     string            `gorm:"column:resource_kind;index:idx_tc_list_q,priority:3"`
	Image            string            `gorm:"column:image"`
	Spec             *ContainerSpec    `gorm:"column:spec;type:varchar(4096)"`
	Ports            ContainerPorts    `gorm:"column:ports;type:varchar(512)"`
	ImagePullPolicy  corev1.PullPolicy `gorm:"column:image_pull_policy;type:varchar(64)"`
	SecurityContext  *SecurityContext  `gorm:"column:security_context;type:varchar(1024)"`
	Type             string            `gorm:"column:type"`
	ImageUUID        uint32            `gorm:"column:image_uuid"`
	AppType          *string
	AppTargetName    *string
	AppTargetVersion *string
}

func (TensorContainer) TableName() string {
	return "ivan_assets_containers"
}

type TensorNamespace struct {
	TableBase                 // id: cluster_key/namespace
	Name            string    `gorm:"column:name"`
	ClusterKey      string    `gorm:"column:cluster_key;index:idx_tn_list_q"`
	UID             string    `gorm:"column:uid"`
	OwnerReferences OwnerRefs `gorm:"column:owner_references;type:varchar(256)"`
	Labels          []byte    `gorm:"column:labels;type:blob"`
	Alias           string    `gorm:"column:alias"`
	Managers        Managers  `gorm:"column:managers;type:varchar(256)"`
	Authority       string    `gorm:"column:authority"`
}

func (TensorNamespace) TableName() string {
	return "ivan_assets_namespaces"
}

func (sc *PodContainerInfos) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &sc)
}
func (sc *PodContainerInfos) Value() (driver.Value, error) {
	return json.Marshal(sc)
}

type PodContainerInfos struct {
	InitContainerInfo []PodContainerInfo `json:"init_container_info"`
	ContainerInfo     []PodContainerInfo `json:"container_info"`
}

type PodContainerInfo struct {
	ImageID     string `json:"image_id"`
	ContainerID string `json:"container_id"`
}

type PodResourceRelation struct {
	TableBase                            // id: cluster_key/namespace/resKind/resName/podUID
	ClusterKey        string             `json:"ClusterKey" gorm:"column:cluster_key;index:idx_prr_res,priority:1"`
	PodIP             string             `json:"PodIP,omitempty"`
	PodUID            string             `json:"PodUID" gorm:"column:pod_uid"`
	HostIP            string             `json:"HostIP,omitempty"`
	Namespace         string             `json:"Namespace" gorm:"column:namespace;index:idx_prr_res,priority:2"`
	PodName           string             `json:"PodName"`
	NodeName          string             `json:"NodeName" gorm:"column:node_name"`
	ResourceName      string             `json:"ResourceName" gorm:"column:resource_name;index:idx_prr_res,priority:4"`
	ResourceKind      string             `json:"ResourceKind" gorm:"column:resource_kind;index:idx_prr_res,priority:3"`
	PodContainerInfos *PodContainerInfos `json:"pod_container_infos" gorm:"column:pod_container_infos;type:varchar(512)"`
	CreateTimestamp   int64              `json:"CreateTimestamp" gorm:"-"`
}

func (PodResourceRelation) TableName() string {
	return "ivan_assets_pod_res_relations"
}

type ClusterType string

const (
	HostCluster   ClusterType = "host_cluster"
	MemberCluster ClusterType = "member_cluster"
)

type TensorCluster struct {
	Key                 string      `gorm:"column:id;primaryKey" json:"key"`
	Name                string      `gorm:"column:name" json:"name"`
	Description         string      `gorm:"column:description" json:"description"`
	ClusterType         ClusterType `gorm:"column:cluster_type" json:"cluster_type"`
	APIServerAddr       string      `gorm:"column:api_server_addr" json:"apiServerAddr"`
	CertificateAuthData string      `gorm:"column:certificate_auth_data" json:"certificateAuthData"`
	SecretToken         string      `gorm:"column:secret_token" json:"secretToken"`
	ClientCertData      string      `gorm:"column:client_cert_data" json:"client_cert_data"`
	ClientKeyData       string      `gorm:"column:client_key_data" json:"client_key_data"`
	SecretNamespace     string      `gorm:"column:secret_namespace" json:"secretNamespace"`
	WorkerNamespace     string      `gorm:"column:worker_namespace" json:"worker_namespace"`
	LabelInited         bool        `gorm:"column:label_inited" json:"label_inited"`
	Creator             string      `gorm:"column:creator" json:"creator"`
	CreatedAt           time.Time   `gorm:"column:created_at" json:"createdAt"`
	Updater             string      `gorm:"column:updater" json:"updater"`
	UpdatedAt           time.Time   `gorm:"column:updated_at" json:"updatedAt"`
	Status              int32       `gorm:"column:status"`
	Platform            string      `gorm:"column:platform" json:"platform"`
	Version             string      `gorm:"column:version" json:"version"`
}

func (TensorCluster) TableName() string {
	return "ivan_assets_clusters"
}

type ContainerImages []corev1.ContainerImage

func (sc *ContainerImages) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &sc)
}
func (sc ContainerImages) Value() (driver.Value, error) {
	return json.Marshal(sc)
}

type NodeVolume struct {
	Type       string
	VolumeName string
	DevicePath string
}
type Volumes []NodeVolume

func (sc *Volumes) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &sc)
}
func (sc Volumes) Value() (driver.Value, error) {
	return json.Marshal(sc)
}

type TensorNode struct {
	ID                      uint32
	ClusterKey              string
	HostName                string
	NodeIP                  string
	KernelVersion           string
	OsInfo                  string
	OsImage                 string
	ContainerRuntimeVersion string
	KubeletVersion          string
	KubeProxyVersion        string
	Architecture            string
	Volumes                 Volumes         `gorm:"column:volumes;type:varchar(256)"`
	ContainerImages         ContainerImages `gorm:"column:container_images;type:text"`
	CreatedAt               time.Time
	UpdatedAt               time.Time
	Ready                   uint8
	Status                  int8
}

func (TensorNode) TableName() string { return "ivan_assets_nodes" }

type ContainerDetail map[string]string

func (cd *ContainerDetail) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &cd)
}
func (cd *ContainerDetail) Value() (driver.Value, error) {
	return json.Marshal(cd)
}

type EnvVars []corev1.EnvVar

func (ev *EnvVars) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &ev)
}
func (ev EnvVars) Value() (driver.Value, error) {
	return json.Marshal(ev)
}

type StringSlice []string

func (sl *StringSlice) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &sl)
}
func (sl StringSlice) Value() (driver.Value, error) {
	data, err := json.Marshal(sl)
	return data, err
}

type ContainerInfos struct {
	PodSecurityPolicy *corev1.PodSecurityContext `json:"podSecurityPolicy"`
}

func (ci *ContainerInfos) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &ci)
}
func (ci ContainerInfos) Value() (driver.Value, error) {
	data, err := json.Marshal(ci)
	return data, err
}

type TensorContainerRelation struct {
	ID            uint32          `gorm:"column:id;type:bigint;primaryKey" json:"id,omitempty"`
	CreatedAt     time.Time       `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt     time.Time       `gorm:"column:updated_at" json:"updatedAt"`
	Status        int32           `gorm:"column:status"`
	ContainerID   string          `gorm:"column:container_id" json:"containerID"`
	Name          string          `gorm:"column:name"`
	PodName       string          `gorm:"column:pod_name"`
	ResourceName  string          `gorm:"column:resource_name"`
	Namespace     string          `gorm:"column:namespace"`
	ClusterKey    string          `gorm:"column:cluster_key"`
	ResourceKind  string          `gorm:"column:resource_kind"`
	PodIP         string          `json:"PodIP,omitempty" gorm:"column:pod_ip"`
	PodUID        string          `json:"PodUID" gorm:"column:pod_uid"`
	HostIP        string          `json:"HostIP,omitempty" gorm:"column:host_ip"`
	NodeName      string          `json:"NodeName" gorm:"column:node_name"`
	Image         string          `json:"image" gorm:"column:image"`
	Library       string          `json:"library" gorm:"column:library"`
	ContainerInfo *ContainerInfos `json:"containerInfo" gorm:"column:container_info;type:blob"`
	Environment   EnvVars         `json:"environment" gorm:"column:environment"`
	Cmd           StringSlice     `json:"cmd" gorm:"column:cmd"`
	Arguments     StringSlice     `json:"arguments" gorm:"column:arguments;type:varchar(128)"`
	HostNetwork   bool            `json:"hostNetwork" gorm:"column:host_network"`
	Privileged    bool            `json:"privileged" gorm:"column:privileged"`
	PoolName      string          `json:"poolName" gorm:"column:pool_name"`
	PoolUID       string          `json:"poolUID" gorm:"column:pool_uid"`
	PoolPodName   string          `json:"poolPodName" gorm:"column:pool_pod_name"`
	PoolPodUID    string          `json:"poolPodUID" gorm:"column:pool_pod_uid"`
	TimeStamp     int64           `gorm:"column:time_stamp"`
}

func (r TensorContainerRelation) TableName() string {
	return "ivan_assets_container_relations"
}
