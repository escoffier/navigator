package model

import "time"

type TensorNetworkFlow struct {
	UUID         int64
	SrcCluster   string `gorm:"type:varchar(100)"`
	SrcNamespace string `gorm:"type:varchar(100)"`
	SrcKind      string `gorm:"type:varchar(100)"`
	SrcName      string `gorm:"type:varchar(100)"`
	DstCluster   string `gorm:"type:varchar(100)"`
	DstNamespace string `gorm:"type:varchar(100)"`
	DstKind      string `gorm:"type:varchar(100)"`
	DstName      string `gorm:"type:varchar(100)"`
	DstPort      int32  `gorm:"type:integer"`
	Status       int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (t *TensorNetworkFlow) TableName() string {
	return "tensor_network_flows"
}
