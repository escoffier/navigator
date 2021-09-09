package model

import (
	"bytes"
	"hash/fnv"
	"strconv"
	"time"
)

type TensorNetworkFlow struct {
	UUID         uint32    `json:"uuid" gorm:"type:bigint;primarykey"`
	SrcCluster   string    `json:"src_cluster" gorm:"type:varchar(100);"`
	SrcNamespace string    `json:"src_namespace" gorm:"type:varchar(100)"`
	SrcKind      string    `json:"src_kind" gorm:"type:varchar(100)"`
	SrcName      string    `json:"src_name" gorm:"type:varchar(100);index:idx_flow_sname"`
	DstCluster   string    `json:"dst_cluster" gorm:"type:varchar(100)"`
	DstNamespace string    `json:"dst_namespace" gorm:"type:varchar(100)"`
	DstKind      string    `json:"dst_kind" gorm:"type:varchar(100)"`
	DstName      string    `json:"dst_name" gorm:"type:varchar(100);index:idx_flow_dname"`
	Proto        uint8     `json:"proto" gorm:"type:smallint"`
	DstPort      int       `json:"dst_port" gorm:"type:integer"`
	Status       int       `json:"status" gorm:"status"`
	CreatedAt    time.Time `json:"created_at" gorm:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" gorm:"updated_at"`
}

func (t *TensorNetworkFlow) TableName() string {
	return "tensor_network_flows"
}
func (t *TensorNetworkFlow) CreateUuid() {
	bui := bytes.NewBufferString(t.SrcCluster)
	bui.WriteByte(',')
	bui.WriteString(t.SrcKind)
	bui.WriteByte(',')
	bui.WriteString(t.SrcName)
	bui.WriteByte(',')
	bui.WriteString(t.SrcNamespace)
	bui.WriteByte(',')
	bui.WriteString(t.DstCluster)
	bui.WriteByte(',')
	bui.WriteString(t.DstKind)
	bui.WriteByte(',')
	bui.WriteString(t.DstName)
	bui.WriteByte(',')
	bui.WriteString(t.DstNamespace)
	bui.WriteByte(',')
	bui.WriteString(strconv.Itoa(t.DstPort))

	h := fnv.New32a()
	h.Write(bui.Bytes())
	t.UUID = h.Sum32()
}
