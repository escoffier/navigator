package service

import (
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/microsegmutator/model"
	"gorm.io/gorm"
	"k8s.io/client-go/kubernetes"
)

type mutationService struct {
	backend model.Model
	k8sCli  *kubernetes.Clientset
}

func NewMutationService(db *gorm.DB, k8sCli *kubernetes.Clientset) Service {
	return &mutationService{
		backend: model.NewMutationModel(db),
		k8sCli:  k8sCli,
	}
}

//type Patch struct {
//	Op    string `json:"op"`
//	Path  string `json:"path"`
//	Value string `json:"value,omitempty"`
//}
