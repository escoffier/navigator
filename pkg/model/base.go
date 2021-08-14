package model

import "time"

type TableBase struct {
	ID        uint32    `gorm:"column:id;type:bigint;primaryKey"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
	Status    int32     `gorm:"column:status;type:smallint"`
}
