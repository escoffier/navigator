package model

import (
	"bytes"
	"hash/fnv"
	"strconv"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
)

type TensorNetworkFlow struct {
	UUID             uint32    `json:"uuid" gorm:"type:bigint;primarykey"`
	AssocKey         uint32    `json:"assoc_key" gorm:"-"`
	SrcCluster       string    `json:"src_cluster" gorm:"type:varchar(100);"`
	SrcNamespace     string    `json:"src_namespace" gorm:"type:varchar(100)"`
	SrcKind          string    `json:"src_kind" gorm:"type:varchar(100)"`
	SrcOwnerName     string    `json:"src_owner_name" gorm:"type:varchar(100);column:src_name;index:idx_flow_sname"`
	SrcContainerName string    `json:"src_container_name" gorm:"type:varchar(100)"`
	SrcProcess       string    `json:"src_process" gorm:"type:varchar(100)"`
	SrcPodName       string    `json:"src_pod_name"  gorm:"-"`
	SrcPid           int       `json:"src_pid" gorm:"-"`
	DstCluster       string    `json:"dst_cluster" gorm:"type:varchar(100)"`
	DstNamespace     string    `json:"dst_namespace" gorm:"type:varchar(100)"`
	DstKind          string    `json:"dst_kind" gorm:"type:varchar(100)"`
	DstOwnerName     string    `json:"dst_owner_name" gorm:"type:varchar(100);column:dst_name;index:idx_flow_dname"`
	DstContainerName string    `json:"dst_container_name" gorm:"type:varchar(100)"`
	DstProcess       string    `json:"dst_process" gorm:"type:varchar(100)"`
	DstPodName       string    `json:"dst_pod_name" gorm:"-"`
	DstPid           int       `json:"dst_pid" gorm:"-"`
	Proto            uint8     `json:"proto" gorm:"type:smallint"`
	DstPort          uint16    `json:"dst_port" gorm:"type:integer"`
	Status           int       `json:"status" gorm:"status"`
	CreatedAt        time.Time `json:"created_at" gorm:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" gorm:"updated_at"`
}

func (TensorNetworkFlow) TableName() string {
	return "ivan_network_flows"
}

func (t *TensorNetworkFlow) CreateUuid() {
	bui := bytes.NewBufferString(t.SrcCluster)
	bui.WriteByte(',')
	bui.WriteString(t.SrcKind)
	bui.WriteByte(',')
	bui.WriteString(t.SrcOwnerName)
	bui.WriteByte(',')
	bui.WriteString(t.SrcNamespace)
	bui.WriteByte(',')
	bui.WriteString(t.SrcContainerName)
	bui.WriteByte(',')
	bui.WriteString(t.SrcProcess)
	bui.WriteByte(',')
	bui.WriteString(t.DstCluster)
	bui.WriteByte(',')
	bui.WriteString(t.DstKind)
	bui.WriteByte(',')
	bui.WriteString(t.DstOwnerName)
	bui.WriteByte(',')
	bui.WriteString(t.DstNamespace)
	bui.WriteByte(',')
	bui.WriteString(t.DstContainerName)
	bui.WriteByte(',')
	bui.WriteString(strconv.Itoa(int(t.DstPort)))

	h := fnv.New32a()
	h.Write(bui.Bytes())
	t.UUID = h.Sum32()
}

func (t *TensorNetworkFlow) CreateAssocKey(tuple *daemon.FiveTuple) {
	bui := bytes.NewBufferString(tuple.SrcIp)
	bui.WriteByte(',')
	bui.WriteString(strconv.Itoa(int(tuple.SrcPort)))
	bui.WriteByte(',')
	bui.WriteString(tuple.DstIp)
	bui.WriteByte(',')
	bui.WriteString(strconv.Itoa(int(tuple.DstPort)))
	bui.WriteByte(',')
	bui.WriteByte(tuple.Proto)

	h := fnv.New32a()
	h.Write(bui.Bytes())
	t.AssocKey = h.Sum32()
}
