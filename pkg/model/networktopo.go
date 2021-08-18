package model

import "time"

type TensorNetworkFlow struct {
	UUID         uint32 `gorm:"type:bigint;primarykey"`
	SrcCluster   string `gorm:"type:varchar(100);"`
	SrcNamespace string `gorm:"type:varchar(100)"`
	SrcKind      string `gorm:"type:varchar(100)"`
	SrcName      string `gorm:"type:varchar(100);index:idx_flow_sname"`
	DstCluster   string `gorm:"type:varchar(100)"`
	DstNamespace string `gorm:"type:varchar(100)"`
	DstKind      string `gorm:"type:varchar(100)"`
	DstName      string `gorm:"type:varchar(100);index:idx_flow_dname"`
	Proto        uint8  `gorm:"type:smallint"`
	DstPort      int    `gorm:"type:integer"`
	Status       int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (t *TensorNetworkFlow) TableName() string {
	return "tensor_network_flows"
}
