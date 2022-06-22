package model

import "time"

type DriftPolicyCreate struct {
	ClusterKey   string `json:"cluster_key"`
	Namespace    string `json:"namespace"`
	Resource     string `json:"resource"`
	ResourceKind string `json:"resource_kind"`
	Creator      string `json:"creator"`
	Enable       int    `json:"enable"`
	Mode         int    `json:"mode"`
}

type DriftPolicyCache struct {
	LastTime int64
	Policies []DriftPolicy
}

type DriftPolicyUpdate struct {
	PolicyID int64  `json:"policy_id"`
	Enable   int    `json:"enable"`
	Mode     int    `json:"mode"`
	Updater  string `json:"updater"`
}

type DriftListPolicyResp struct {
	PolicyID     int64  `json:"policy_id"`
	Enable       int    `json:"enable"`
	Mode         int    `json:"mode"`
	Namespace    string `gorm:"type:varchar(255)" json:"namespace"`
	Resource     string `gorm:"type:varchar(255)" json:"resource"`
	ResourceKind string `gorm:"type:varchar(255)" json:"resource_type"`
	ClusterKey   string `gorm:"type:varchar(255)" json:"cluster_key"`
	AbnormalNum  int    `json:"abnormal_num"`
}

type DriftPolicyAbnormal struct {
	FilePath    string `json:"file_path"`
	ContainerID string `json:"container_id"`
	PodName     string `json:"pod_name"`
	HappendTime int64  `json:"happend_time"`
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
	Mode         int       `json:"mode"`
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
	Items      []DriftPolicy `json:"items"`
	TotalItems int64         `json:"totalItems,omitempty"`
}

func (DriftPolicy) TableName() string {
	return "ivan_drift_policies"
}

const (
	SubjectOfDriftEvent = "ivan_drift_event"
)
