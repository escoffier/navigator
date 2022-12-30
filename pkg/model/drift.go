package model

import (
	"time"

	v1 "k8s.io/api/core/v1"
)

type DriftPolicyCreate struct {
	ClusterKey   string `json:"cluster_key"`
	Namespace    string `json:"namespace"`
	Resource     string `json:"resource"`
	ResourceKind string `json:"resource_kind"`
	Creator      string `json:"creator"`
	Enable       int    `json:"enable"`
	Mode         string `json:"mode"`
}

type DriftPolicyCache struct {
	LastTime int64
	Policies []DriftPolicy
}

type DriftPolicyUpdate struct {
	PolicyID int64  `json:"policy_id"`
	Enable   int    `json:"enable"`
	Mode     string `json:"mode"`
	Updater  string `json:"updater"`
}

type DriftListPolicyResp struct {
	PolicyID      int64  `json:"policy_id"`
	Enable        int    `json:"enable"`
	Mode          string `gorm:"type:varchar(10)" json:"mode"`
	Namespace     string `gorm:"type:varchar(255)" json:"namespace"`
	Resource      string `gorm:"type:varchar(255)" json:"resource"`
	ResourceKind  string `gorm:"type:varchar(255)" json:"resource_type"`
	ClusterKey    string `gorm:"type:varchar(255)" json:"cluster_key"`
	AbnormalNum   int    `json:"abnormal_num"`
	ScannerStatus int8   `json:"scanner_status"`
}

type DriftPolicyAbnormal struct {
	ID                  string `json:"id"`
	FilePath            string `json:"file_path"`
	ContainerID         string `json:"container_id"`
	PodName             string `json:"pod_name"`
	HappendTime         int64  `json:"happend_time"`
	Action              string `json:"action"`
	IsInGlobalWhitelist bool   `json:"in_global_whitelist"`
}

type DriftPolicyDetailResp struct {
	ContainerID        uint32   `json:"container_id"`
	ContainerName      string   `json:"container_name"`
	ImageID            int64    `json:"image_id"`
	Image              string   `json:"image"`
	ContainerFullNames []string `json:"container_full_names"`
}

type DriftPolicy struct {
	ID           int64     `gorm:"primaryKey" json:"id"`
	CreatedAt    time.Time `gorm:"created_at" json:"created_at"`
	UpdatedAt    time.Time `gorm:"updated_at" json:"updated_at"`
	ResourceUUID uint32    `gorm:"type:varchar(255)" json:"resource_uuid"`
	ResourceKind string    `gorm:"type:varchar(255)" json:"resource_type"`
	Namespace    string    `gorm:"type:varchar(255)" json:"namespace"`
	Resource     string    `gorm:"type:varchar(255)" json:"resource"`
	ClusterKey   string    `gorm:"type:varchar(255)" json:"cluster_key"`
	Creator      string    `gorm:"type:varchar(255)" json:"creator"`
	Updater      string    `gorm:"type:varchar(255)" json:"updater"`
	Enable       int       `json:"enable"`
	Mode         string    `gorm:"type:varchar(10)" json:"mode"`
}

type DaemonDriftPolicies struct {
	Policies     map[uint32]DriftPolicy
	VersionStamp int64
}

type DaemonDriftWhitelist struct {
	Whitelist    map[string]int64 // path -> ExpiredAt
	VersionStamp int64
}

type DaemonDriftResp struct {
	APIVersion string              `json:"apiVersion"`
	Data       DaemonDriftRespData `json:"data"`
}

type PoliciesData struct {
	Policies     []DriftPolicy `json:"policies,omitempty"`
	VersionStamp int64         `json:"versionStamp"`
	Err          error         `json:"-"`
}
type WhitelistData struct {
	Whitelist    []DriftGlobalWhitelistItem `json:"whitelist,omitempty"`
	VersionStamp int64                      `json:"versionStamp"`
	Err          error                      `json:"-"`
}

type DaemonDriftRespData struct {
	Items      []DriftPolicy `json:"items"`
	TotalItems int64         `json:"totalItems,omitempty"`
	Whitelist  WhitelistData `json:"g_whitelist"`
	Policies   PoliciesData  `json:"policies"`
}

func (DriftPolicy) TableName() string {
	return "ivan_drift_policies"
}

type DriftGlobalWhitelistItem struct {
	ID            uint64 `gorm:"column:id" json:"id_backend"`
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"` // milliseconds
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"` // milliseconds
	Creator       string `gorm:"type:varchar(255);column:creator" json:"creator"`
	Updater       string `gorm:"type:varchar(255);column:updater" json:"updater"`
	Path          string `gorm:"type:varchar(768);column:path" json:"path"`
	ExpireAt      int64  `gorm:"type:bigint;column:expire_at" json:"expire_at"` // milliseconds
	IsForever     bool   `gorm:"type:boolean;column:is_forever" json:"is_forever"`
	IDForFrontend string `gorm:"-" json:"id"`
}

func (DriftGlobalWhitelistItem) TableName() string {
	return "ivan_drift_global_whitelist"
}

const (
	SubjectOfDriftSupportEvent   = "drifit_info_signals"
	SubjectOfDriftWhiteListEvent = "drift_whitelist_signals"
)

type DriftPolicyAbnormalOpen struct {
	FilePath    string `json:"filePath"`
	ContainerID string `json:"containerId"`
	PodName     string `json:"podName"`
	HappendTime int64  `json:"happendTime"`
}

type OpenDriftPolicyDetailResp struct {
	ContainerID   uint32 `json:"containerId"`
	ContainerName string `json:"containerName"`
	ImageID       int64  `json:"imageId"`
	Image         string `json:"image"`
}

type OpenDriftContainer struct {
	Cluster       string             `json:"cluster"`
	Namespace     string             `json:"namespace"`
	ResourceKind  string             `json:"resourceKind"`
	ResourceName  string             `json:"resourceName"`
	Name          string             `json:"name"`
	WorkingDir    string             `json:"workingDir"`
	Command       []string           `json:"command"`
	Type          string             `json:"type"`
	ImageRepo     string             `json:"imageRepo"`
	ImageName     string             `json:"imageName"`
	ImageTag      string             `json:"imageTag"`
	Ports         []v1.ContainerPort `json:"ports"`
	Envs          []v1.EnvVar        `json:"envs"`
	FrameWorkInfo []WebFrameInfo     `json:"frameWorkInfo"`
	VolumeMounts  []v1.VolumeMount   `json:"volumeMounts"`
}

type OpenDriftListPolicyResp struct {
	PolicyID     int64  `json:"policyId"`
	Enable       int    `json:"enable"`
	Mode         string `json:"mode"`
	Namespace    string `gorm:"type:varchar(255)" json:"namespace"`
	Resource     string `gorm:"type:varchar(255)" json:"resource"`
	ResourceKind string `gorm:"type:varchar(255)" json:"resourceType"`
	ClusterKey   string `gorm:"type:varchar(255)" json:"clusterKey"`
	AbnormalNum  int    `json:"abnormalNum"`
}

type OpenDriftPolicyUpdate struct {
	PolicyID int64  `json:"policyId"`
	Enable   int    `json:"enable"`
	Mode     string `json:"mode"`
	Updater  string `json:"updater"`
}

type OpenDriftPolicyCreate struct {
	ClusterKey   string `json:"clusterKey"`
	Namespace    string `json:"namespace"`
	Resource     string `json:"resource"`
	ResourceKind string `json:"resourceKind"`
	Creator      string `json:"creator"`
	Enable       int    `json:"enable"`
	Mode         string `json:"mode"`
}

type OpenTensorNamespace struct {
	CreatedAt       time.Time `gorm:"column:createdAt" json:"CreatedAt,omitempty"`
	UpdatedAt       time.Time `gorm:"column:updatedAt" json:"UpdatedAt,omitempty"`
	Name            string    `gorm:"column:name"`
	ClusterKey      string    `gorm:"column:clusterKey;index:idx_tn_list_q"`
	UID             string    `gorm:"column:UID"`
	OwnerReferences OwnerRefs `gorm:"column:ownerReferences;type:varchar(256)"`
	Labels          []byte    `gorm:"column:labels;type:blob"`
	Alias           string    `gorm:"column:alias"`
	Managers        Managers  `gorm:"column:managers;type:varchar(256)"`
	Authority       string    `gorm:"column:authority"`
}

type DriftSupportInfo struct {
	IsSupportDrift bool   `json:"is_support_drift"`
	Cluster        string `json:"cluster"`
	Namespace      string `json:"namespace"`
	ResourceKind   string `json:"resource_kind"`
	ResourceName   string `json:"resource_name"`
	OSTarget       string `json:"os_target"`
	ContainerID    string `json:"container_id"`
	ScannerStatus  int8   `json:"scanner_status"`
}

type DriftImageWhitelist struct {
	ImageID   string `json:"image_id" gorm:"column:image_id;varchar(65)"`
	Filepath  string `json:"filepath" gorm:"column:path;varchar(768)"`
	CheckSum  string `json:"check_sum" gore:"column:hash;varchar(8)"`
	RepoTag   string `json:"repo_tag" gorm:"column:repo_tag;varchar(255)"`
	CreatedAt int64  `json:"created_at" gorm:"column:created_at;autoCreateTime:milli"`
	UpdatedAt int64  `json:"updated_at" gorm:"column:updated_at;autoUpdateTime:milli"`
}

func (DriftImageWhitelist) TableName() string {
	return "ivan_drift_default_whitelist"
}

type DriftWhitelistFile struct {
	FileName string `json:"file_name"`
	Checksum string `json:"checksum" `
}

type DriftImageWhitelistKafka struct {
	ImageID    string               `json:"image_id"`
	RepoTags   []string             `json:"repo_tags"`
	Whitelists []DriftWhitelistFile `json:"whitelists"`
}
