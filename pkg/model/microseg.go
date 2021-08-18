package model

import (
	"hash/fnv"
	"strings"
	"time"
)

type NetworkType = int

const (
	PodNetwork = iota
	HostNetwork
)

type TensorMicrosegResource struct {
	ID          uint32 `gorm:"type:bigint;primarykey"`
	SegmentID   uint32 `gorm:"type:bigint;index:idx_res_sid"`
	SegmentName string `gorm:"type:varchar(100);index:idx_res_sname"`
	Cluster     string `gorm:"type:varchar(100)"`
	Namespace   string `gorm:"type:varchar(100)"`
	Kind        string `gorm:"type:varchar(100)"` // Deployment/StatefulSet/DaemonSet/Job/Cronjob/ReplicaSet/ReplicationController
	Name        string `gorm:"type:varchar(100)"`
	Policy      string `gorm:"type:varchar(100)"`
	NetworkType int    `gorm:"type:smallint"`
	ResourceTag int    `gorm:"type:smallint"`
	Status      int    `gorm:"type:smallint"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (t *TensorMicrosegResource) TableName() string {
	return "tensor_microseg_resources"
}

func GenID(strs ...string) uint32 {
	s := strings.Join(strs, ",")
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}
