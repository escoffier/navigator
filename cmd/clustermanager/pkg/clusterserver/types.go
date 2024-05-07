package clusterserver

import (
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"time"
)

type MicroType = int

const (
	Segment MicroType = iota + 1
	Resource
	IPBlock
	Namespace
	Nsgrp
	Tenant
)

type TensorCluster struct {
	Key           string                 `json:"key"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Status        int32                  `json:"status"`
	ConsoleURL    string                 `json:"console_url"`
	K8SRestConfig *k8s.InfoForRestConfig `json:"k8s_rest_config"`
}

type TensorPod struct {
	ClusterKey string `json:"clusterKey"`
	Namespace  string `json:"namespace"`
	Resource   string `json:"resource"`
	Name       string `json:"name"`
}

type PodResData struct {
	Namespace string `json:"namespace"`
	Resource  string `json:"resource"`
	KindName  string `json:"kind"`
	PodName   string `json:"name"`
}
type BaseInfo struct {
	Status    int `gorm:"type:smallint"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type UserInfo struct {
	Creator string `gorm:"type:varchar(100);"`
	Updater string `gorm:"type:varchar(100);"`
}

type TensorMicrosegRule struct {
	ID         uint32 `gorm:"type:bigint;primarykey"`
	Policy     string `gorm:"type:varchar(100)"`
	Direction  int    `gorm:"type:smallint"`
	SrcType    int    `gorm:"type:smallint"`
	SrcID      uint32 `gorm:"type:bigint"`
	SrcIPBlock string `gorm:"type:varchar(100)"`
	DstType    int    `gorm:"type:smallint"`
	DstID      uint32 `gorm:"type:bigint"`
	DstIPBlock string `gorm:"type:varchar(100)"`
	Action     int    `gorm:"type:smallint"`
	Protocol   int    `gorm:"type:smallint"`
	Ports      string `gorm:"type:varchar(100)"`
	ClusterKey string `gorm:"type:varchar(100)"`
	Comment    string `gorm:"type:text"`
	IsSegRule  bool
	Revision   int
	Priority   int
	Enable     bool
	BaseInfo
}

func (t *TensorMicrosegRule) TableName() string {
	return "ivan_microseg_rules"
}

type TensorMicrosegSegment struct {
	ID         uint32 `gorm:"type:bigint;primarykey"`
	Name       string `gorm:"type:varchar(100);index:idx_seg_name"`
	Cluster    string `gorm:"type:varchar(100)"`
	Namespace  string `gorm:"type:varchar(100)"`
	Policy     string `gorm:"type:varchar(100)"`
	InnerTrust bool   `gorm:"column:inner_trust"`
	UserInfo
	BaseInfo
	Enabled int
}

func (t *TensorMicrosegSegment) TableName() string {
	return "ivan_microseg_segments"
}

type Clusters []string

type IPGroup struct {
	Cluster Clusters `gorm:"column:cluster"`
	ID      uint32   `gorm:"column:id"`
	Name    string   `gorm:"column:name"`
	IpSet   string   `gorm:"column:ip_set"`
	Comment string   `gorm:"column:comment"`
	Status  int      `gorm:"column:status"`
}

func (i *IPGroup) TableName() string {
	return "ivan_microseg_ipgroups"
}

type TensorMicrosegNsgrp struct {
	ID              int64  `gorm:"type:bigserial;primarykey"`
	UUID            uint32 `gorm:"type:bigint"`
	Name            string `gorm:"type:varchar(100)"`
	Cluster         string `gorm:"type:varchar(100)"`
	PolicyNamespace string `gorm:"type:varchar(100)"`
	Namespaces      string `gorm:"type:varchar(1024)"`
	InnerTrust      bool   `gorm:"column:inner_trust"`
	BaseInfo
}

func (t *TensorMicrosegNsgrp) TableName() string {
	return "ivan_microseg_nsgrps"
}

type TensorMicrosegResource struct {
	ID          uint32 `gorm:"type:bigint;primarykey"`
	SegmentID   uint32 `gorm:"type:bigint;index:idx_res_sid"`
	SegmentName string `gorm:"type:varchar(100);index:idx_res_sname"`
	NsgroupID   uint32 `gorm:"column:nsgroup_id"`
	Cluster     string `gorm:"type:varchar(100)"`
	Namespace   string `gorm:"type:varchar(100)"`
	Kind        string `gorm:"type:varchar(100)"`
	Name        string `gorm:"type:varchar(100)"`
	Policy      string `gorm:"type:varchar(100)"`
	NetworkType int    `gorm:"type:smallint"`
	ResourceTag int    `gorm:"type:smallint"`
	BaseInfo
	Enabled      int
	AllowGateway int `gorm:"column:allow_gateway"`
}

func (t *TensorMicrosegResource) TableName() string {
	return "ivan_microseg_resources"
}
