package model

import (
	"encoding/json"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
	softdelete "gorm.io/plugin/soft_delete"
)

// 扫描策略

// ScapPolicy 是合规扫描的策略表对应的model
type ScapPolicy struct {
	ID uint `gorm:"primarykey"`
	// 策略名字，与deleted_at构成唯一索引
	Name string `gorm:"column:name;type:varchar(100);uniqueIndex:name_unique;priority:2"`

	// 是否默认
	IsDefault bool `gorm:"column:is_default;type:bool"`

	// 策略类型：kube:1/docker:2/host:3
	Type uint8 `gorm:"column:type;uniqueIndex:name_unique;priority:1;type:tinyint"`

	// 操作人
	Operator string `gorm:"column:operator;type:varchar(30)"`
	// 说明
	Comment string `gorm:"column:comment;type:varchar(255)"`

	// 具体策略的id
	Rules   datatypes.JSON `gorm:"column:rule_ids;type:json"`
	RuleIds []int64        `gorm:"-"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt softdelete.DeletedAt `gorm:"uniqueIndex:name_unique;priority:3"`
}

func (ScapPolicy) TableName() string {
	return "ivan_scap_policy"
}

func (s *ScapPolicy) BeforeSave(tx *gorm.DB) (err error) {
	if len(s.RuleIds) != 0 && s.Rules == nil {
		s.Rules, err = json.Marshal(s.RuleIds)
	}

	return
}

func (s *ScapPolicy) AfterFind(tx *gorm.DB) (err error) {
	if s.Rules != nil {
		err = json.Unmarshal(s.Rules, &s.RuleIds)
	}

	return
}

// 定时任务

// ScapCronRecord 保存定时任务
type ScapCronRecord struct {
	gorm.Model
	// 策略类型：kube:1/docker:2/host:3
	Type uint8 `gorm:"column:type;type:tinyint"`
	// Cron表达式
	Cron string `gorm:"column:cron;type:varchar(20)"`
	// 操作人
	Operator string `gorm:"column:operator;type:varchar(30)"`
	// 版本号
	Version int64 `gorm:"column:version;type:bigint"`
	// cluster 信息
	ClusterInfos   datatypes.JSON `gorm:"column:cluster_infos;type:json"`
	ClusterInfoIds []uint         `gorm:"-"`
	// 策略ID
	PolicyID uint `gorm:"column:policy_id;type:bigint"`
}

func (s *ScapCronRecord) BeforeSave(tx *gorm.DB) (err error) {
	if len(s.ClusterInfoIds) != 0 {
		s.ClusterInfos, err = json.Marshal(s.ClusterInfoIds)
	}

	return
}

func (s *ScapCronRecord) AfterFind(tx *gorm.DB) (err error) {
	if s.ClusterInfos != nil {
		err = json.Unmarshal(s.ClusterInfos, &s.ClusterInfoIds)
	}

	return
}

func (ScapCronRecord) TableName() string {
	return "ivan_scap_cron_record"
}

// 集群信息

type ScapClusterInfo struct {
	gorm.Model
	IsAllNodes bool   `gorm:"column:is_all_nodes;type:bool"`
	ClusterKey string `gorm:"column:cluster_key;type:varchar(100)"`

	ClusterNodes   datatypes.JSON `gorm:"column:cluster_nodes;type:json"`
	ClusterNodeIds []uint         `gorm:"-"`

	ClusterName      string   `gorm:"-"`
	ClusterNodeNames []string `gorm:"-"`
	CheckUUID        string   `gorm:"-"` // 该次扫描的UUID主要用于查询状态
}

func (s *ScapClusterInfo) BeforeSave(tx *gorm.DB) (err error) {
	if len(s.ClusterNodeIds) != 0 {
		s.ClusterNodes, err = json.Marshal(s.ClusterNodeIds)
	}

	return
}

func (s *ScapClusterInfo) AfterFind(tx *gorm.DB) (err error) {
	if s.ClusterNodes != nil {
		err = json.Unmarshal(s.ClusterNodes, &s.ClusterNodeIds)
	}

	return
}

func (ScapClusterInfo) TableName() string {
	return "ivan_scap_cluster_info"
}
