package model

import (
	"gorm.io/gorm"
)

type mutationModel struct {
	db *gorm.DB
}

func NewMutationModel(db *gorm.DB) Model {
	return &mutationModel{
		db: db,
	}
}
