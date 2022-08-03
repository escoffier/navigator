package service

import (
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/microsegmutator/model"
	"gorm.io/gorm"
)

type mutationService struct {
	backend model.Model
}

func NewMutationService(db *gorm.DB) Service {
	return &mutationService{
		backend: model.NewMutationModel(db),
	}
}
