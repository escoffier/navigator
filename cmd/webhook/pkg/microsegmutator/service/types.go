package service

import (
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/microsegmutator/model"
	"gorm.io/gorm"
	"k8s.io/client-go/kubernetes"
)

type mutationService struct {
	backend model.Model
	kubeCli *kubernetes.Clientset
}

func NewMutationService(db *gorm.DB, kubeCli *kubernetes.Clientset) Service {
	return &mutationService{
		backend: model.NewMutationModel(db),
		kubeCli: kubeCli,
	}
}
