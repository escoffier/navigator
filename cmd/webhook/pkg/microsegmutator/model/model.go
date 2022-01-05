package model

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type Model interface {
	GetResourceByID(ctx context.Context, ID uint32) (model.TensorMicrosegResource, error)
	GetClusterByName(ctx context.Context, name string) (*model.TensorCluster, error)
}
