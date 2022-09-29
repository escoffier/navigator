package model

import "time"

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
	PolicyID     int64  `json:"policy_id"`
	Enable       int    `json:"enable"`
	Mode         string `gorm:"type:varchar(10)" json:"mode"`
	Namespace    string `gorm:"type:varchar(255)" json:"namespace"`
	Resource     string `gorm:"type:varchar(255)" json:"resource"`
	ResourceKind string `gorm:"type:varchar(255)" json:"resource_type"`
	ClusterKey   string `gorm:"type:varchar(255)" json:"cluster_key"`
	AbnormalNum  int    `json:"abnormal_num"`
}

type DriftPolicyAbnormal struct {
	ID                  string `json:"id"`
	FilePath            string `json:"file_path"`
	ContainerID         string `json:"container_id"`
	PodName             string `json:"pod_name"`
	HappendTime         int64  `json:"happend_time"`
	IsInGlobalWhitelist bool   `json:"in_global_whitelist"`
}

type DriftPolicyDetailResp struct {
	ContainerID   uint32 `json:"container_id"`
	ContainerName string `json:"container_name"`
	ImageID       int64  `json:"image_id"`
	Image         string `json:"image"`
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
	Updater      string    `gorm:"type:varchar(255)" json:"updator"`
	Enable       int       `json:"enable"`
	Mode         string    `gorm:"type:varchar(10)" json:"mode"`
}

type DaemonDriftPolicies struct {
	Policies map[uint32]DriftPolicy
	LastTime int64
}

type DaemonDriftResp struct {
	APIVersion string              `json:"apiVersion"`
	Data       DaemonDriftRespData `json:"data"`
}

type DaemonDriftRespData struct {
	Items                []DriftPolicy              `json:"items"`
	TotalItems           int64                      `json:"totalItems,omitempty"`
	GlobalWhitelistItems []DriftGlobalWhitelistItem `json:"g_whitelist"`
}

func (DriftPolicy) TableName() string {
	return "ivan_drift_policies"
}

type DriftGlobalWhitelistItem struct {
	ID         int64  `gorm:"column:id" json:"id"`
	CreatedAt  int64  `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"`
	UpdatedAt  int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"`
	Creator    string `gorm:"type:varchar(255);column:creator" json:"creator"`
	Updater    string `gorm:"type:varchar(255);column:updater" json:"updater"`
	Path       string `gorm:"type:varchar(768);column:path" json:"path"`
	Expire_at  int64  `gorm:"type:bigint;column:expire_at" json:"expire_at"`
	Is_forever bool   `gorm:"type:boolean;column:is_forever" json:"is_forever"`
}

func (DriftGlobalWhitelistItem) TableName() string {
	return "ivan_drift_global_whitelist"
}

const (
	SubjectOfDriftSupportEvent = "drifit_info_signals"
)

type DriftSupportInfo struct {
	IsSupportDrift bool   `json:"is_support_drift"`
	Cluster        string `json:"cluster"`
	Namespace      string `json:"namespace"`
	ResourceKind   string `json:"resource_kind"`
	ResourceName   string `json:"resource_name"`
	OSTarget       string `json:"os_target"`
	ContainerID    string `json:"container_id"`
}
