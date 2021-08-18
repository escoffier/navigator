package model

import "time"

type TableBase struct {
	ID        uint32    `gorm:"column:id;type:bigint;primaryKey" json:"id,omitempty"`
	CreatedAt time.Time `gorm:"column:created_at" json:"CreatedAt,omitempty"`
	UpdatedAt time.Time `gorm:"column:updated_at" json:"UpdatedAt,omitempty"`
	Status    int32     `gorm:"column:status;type:smallint" json:"Status,omitempty"`
}
