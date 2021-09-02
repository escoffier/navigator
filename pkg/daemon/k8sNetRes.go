package daemon

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

type K8sNetResMap struct {
	Uuid         uint32    `json:"uuid" gorm:"uuid"`
	SrcCluster   string    `json:"src_cluster" gorm:"primaryKey;type:varchar(100)"`
	SrcName      string    `json:"src_name" gorm:"primaryKey;type:varchar(100)"`
	SrcKind      string    `json:"src_kind" gorm:"primaryKey;type:varchar(100)"`
	SrcNamespace string    `json:"src_namespace" gorm:"primaryKey;type:varchar(100)"`
	DstCluster   string    `json:"dst_cluster" gorm:"primaryKey;type:varchar(100)"`
	DstName      string    `json:"dst_name" gorm:"primaryKey;type:varchar(100)"`
	DstKind      string    `json:"dst_kind" gorm:"primaryKey;type:varchar(100)"`
	DstNamespace string    `json:"dst_namespace" gorm:"primaryKey;type:varchar(100)"`
	Status       int       `json:"status" gorm:"status"`
	DstPort      int       `json:"dst_port" gorm:"dst_port;type:integer"`
	Proto        uint8     `json:"proto" gorm:"proto"`
	CreatedAt    time.Time `json:"created_at" gorm:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" gorm:"updated_at"`
}

func (knt *K8sNetResMap) TableName() string {
	return "tensor_network_flows"
}

func (knt *K8sNetResMap) CreateUuid() {
	value := fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v,%v,%v",
		knt.SrcCluster, knt.SrcKind, knt.SrcName, knt.SrcNamespace,
		knt.DstCluster, knt.DstKind, knt.DstName, knt.DstNamespace, knt.DstPort)

	//log.Infof("create uuid by value : %s", value)
	h := fnv.New32a()
	h.Write([]byte(value))
	knt.Uuid = h.Sum32()
}

func (krd K8sResData) ToString() string {
	return fmt.Sprintf("Cluster : %s, name : %s, kind : %s, namespace : %s.", krd.Cluster, krd.Name, krd.Kind, krd.Namespace)
}
