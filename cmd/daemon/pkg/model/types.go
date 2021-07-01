package model

import (
	"fmt"
	"hash/fnv"
	"time"
)

type K8sResData struct {
	Cluster   string `json:"cluster" gorm:"primaryKey;type:varchar(100)"`
	Name      string `json:"name" gorm:"primaryKey;type:varchar(100)"`
	Kind      string `json:"kind" gorm:"primaryKey;type:varchar(100)"`
	Namespace string `json:"namespace" gorm:"primaryKey;type:varchar(100)"`
}

type K8sNetToplgy struct {
	Uuid      uint32     `json:"uuid" gorm:"uuid"`
	SrcRes    K8sResData `gorm:"embedded;embeddedPrefix:src_"`
	DstRes    K8sResData `gorm:"embedded;embeddedPrefix:dst_"`
	Status    int        `json:"status" gorm:"status"`
	DstPort   int        `json:"dst_port", gorm:"dst_port;type:integer"`
	Proto     uint8      `json:"proto", gorm:"proto"`
	CreatedAt time.Time  `json:"created_at" gorm:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" gorm:"updated_at"`
}

func (knt *K8sNetToplgy) TableName() string {
	return "tensor_network_flows"
}

func (knt *K8sNetToplgy) CreateUuid() {
	src := &knt.SrcRes
	dst := &knt.DstRes
	value := fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v,%v,%v",
		src.Cluster, src.Kind, src.Name, src.Namespace,
		dst.Cluster, dst.Kind, dst.Name, dst.Namespace, knt.DstPort)

	//log.Infof("create uuid by value : %s", value)
	h := fnv.New32a()
	h.Write([]byte(value))
	knt.Uuid = h.Sum32()
}

func (krd K8sResData) ToString() string {
	return fmt.Sprintf("Cluster : %s, name : %s, kind : %s, namespace : %s.", krd.Cluster, krd.Name, krd.Kind, krd.Namespace)
}
