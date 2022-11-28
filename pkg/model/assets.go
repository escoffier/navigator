package model

import (
	"database/sql/driver"
	"errors"
	"github.com/google/go-containerregistry/pkg/name"
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
	WebTypeJboss      = "jboss"
	WebTypeWeblogic   = "weblogic"
	WebTypeWebsphere  = "websphere"

	DBTypeRedis       = "redis"
	DBTypePostgres    = "postgres"
	DBTypeMysql       = "mysql"
	DBTypeMariadb     = "mariadb"
	DBTypeMemcached   = "memcached"
	DBTypeMongo       = "mongo"
	DBTypeMsSQLServer = "mssql"
	DBTypeTiDB        = "tidb"
)

type matcheFunc func(repoName, version string) (bool, string, string, error)

var (
	AppTypeWeb = "web" // Don't change: needs to refer by pointer, so it's a variable not constant
	AppTypeDB  = "database"

	WebMatcher = func(repoName, version string) (bool, string, string, error) {
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
		} else if strings.Index(repoName, WebTypeJboss) >= 0 {
			return true, WebTypeJboss, version, nil
		} else if strings.Index(repoName, WebTypeWeblogic) >= 0 {
			return true, WebTypeWeblogic, version, nil
		} else if strings.Index(repoName, WebTypeWebsphere) >= 0 {
			return true, WebTypeWebsphere, version, nil
		}
		return false, "", "", nil
	}

	DBMatcher = func(repoName, version string) (bool, string, string, error) {
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
)

func GetAppType(image string, matcher matcheFunc) (bool, string, string, error) {
	if len(image) == 0 {
		return false, "", "", errors.New("empty input")
	}

	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)

	ref, err1 := name.ParseReference(image, nameOpts...)
	if err1 != nil {
		return false, "", "", err1
	}
	version := ref.Identifier()
	repoName := ref.Context().RepositoryStr()

	return matcher(repoName, version)
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
	IsSupportDrift  bool           `gorm:"column:is_support_drift;type:boolean;default:true"`
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

type Mounts struct {
	Type string
	// This must match the Name of a Volume.
	Name string `json:"name"`
	// Mounted read-only if true, read-write otherwise (false or unspecified).
	// Defaults to false.
	// +optional
	ReadOnly bool `json:"readOnly"`
	// Path within the container at which the volume should be mounted.  Must
	// not contain ':'.
	SourcePath string
	MountPath  string `json:"mountPath"`
	// Path within the volume from which the container's volume should be mounted.
	// Defaults to "" (volume's root).
	// +optional
	SubPath string `json:"subPath"`
	// mountPropagation determines how mounts are propagated from the host
	// to container and the other way around.
	// When not set, MountPropagationNone is used.
	// This field is beta in 1.10.
	// +optional
	MountPropagation string `json:"mountPropagation"`
	// Expanded path within the volume from which the container's volume should be mounted.
	// Behaves similarly to SubPath but environment variable references $(VAR_NAME) are expanded using the container's environment.
	// Defaults to "" (volume's root).
	// SubPathExpr and SubPath are mutually exclusive.
	// +optional
	SubPathExpr string `json:"subPathExpr"`
}

type VolumeMountSlice []Mounts

func (ev *VolumeMountSlice) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &ev)
}

func (ev VolumeMountSlice) Value() (driver.Value, error) {
	return json.Marshal(ev)
}

type ProcessData struct {
	HostPid      int    `json:"hostPid"`
	ContainerPid int    `json:"containerPid"`
	Comm         string `json:"comm"`
	UserName     string `json:"userName"`
	StartTime    string `json:"startTime"`
}

type ProcessSlice []ProcessData

func (ev *ProcessSlice) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &ev)
}

func (ev ProcessSlice) Value() (driver.Value, error) {
	return json.Marshal(ev)
}

type Port struct {
	Name          string
	ContainerPort int32
	HostPort      int32
	Proto         string
	ContainerIP   string
	HostIP        string
}

type PortSlice []Port

func (ev *PortSlice) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &ev)
}
func (ev PortSlice) Value() (driver.Value, error) {
	return json.Marshal(ev)
}

type TensorRawContainer struct {
	CreatedAt      time.Time        `json:"createdAt" gorm:"column:created_at"`
	UpdatedAt      time.Time        `json:"updatedAt" gorm:"column:updated_at"`
	Status         int32            `json:"status" gorm:"column:status;type:smallint"`
	ContainerID    string           `json:"id" gorm:"column:id;type:bigint;primaryKey"`
	NetworkMode    string           `json:"networkMode" gorm:"column:network_mode""`
	IP             string           `json:"ip" gorm:"column:ip"`
	IPV6           string           `json:"ipv6" gorm:"column:ipv6"`
	Gateway        string           `json:"gateway" gorm:"column:gateway"`
	Mac            string           `json:"mac" gorm:"column:mac"`
	Name           string           `json:"name" gorm:"column:name"`
	PodName        string           `json:"podName" gorm:"column:pod_name"`
	ResourceName   string           `json:"resourceName" gorm:"column:resource_name"`
	Namespace      string           `json:"namespace" gorm:"column:namespace"`
	ClusterKey     string           `json:"clusterKey" gorm:"column:cluster_key"`
	ResourceKind   string           `json:"resourceKind" gorm:"column:resource_kind"`
	NodeName       string           `json:"nodeName" gorm:"column:node_name"`
	NodeIP         string           `json:"nodeIP" gorm:"column:node_ip"`
	ImageName      string           `json:"image" gorm:"column:image_name"`
	ImageID        string           `json:"imageID" gorm:"column:image_id"`
	ImageDigest    string           `json:"imageDigest" gorm:"column:image_digest"`
	ImageSize      int64            `json:"imageSize" gorm:"column:image_size"`
	ImageCreated   string           `json:"imageCreated" gorm:"column:image_created"`
	Cmd            StringSlice      `json:"cmd" gorm:"column:cmd"`
	Arguments      StringSlice      `json:"arguments" gorm:"column:arguments;type:varchar(128)"`
	Environment    StringSlice      `json:"environment" gorm:"column:environment"`
	VolumeMounts   VolumeMountSlice `json:"volumeMounts" gorm:"column:volume_mounts;type:varchar(256)"`
	Path           string           `json:"path" gorm:"column:path"`
	ReservedCPU    int64            `json:"reservedCPU" gorm:"column:reserved_cpu"`
	ReservedMemory int64            `json:"reservedMemory" gorm:"reserved_memory"`
	Pid            int              `json:"pid" gorm:"column:pid"`
	K8sManaged     bool             `json:"k8sManaged" gorm:"column:k8s_managed"`
	ProcessNumber  int              `json:"processNumber" gorm:"column:process_number"`
	Processes      ProcessSlice     `json:"processes" gorm:"column:processes"`
	Ports          PortSlice        `json:"ports" gorm:"column:ports"`
	User           string           `json:"user" gorm:"column:user"`
}

func (rc TensorRawContainer) TableName() string {
	return "ivan_assets_raw_containers"
}
