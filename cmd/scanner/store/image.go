package store

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ImageDal interface {
	UpdateImage(ctx context.Context, where string, updater map[string]interface{}, image *model.ImageList) error
	DeleteImage(ctx context.Context, imageId int64) error
	SearchImage(ctx context.Context, param SearchImageParam, filter *model.Filter) ([]model.ImageList, int64, error)
	GroupRegistryProject(ctx context.Context, param GroupRegistryRepoParam) ([]RegProject, error)
}

type ScanImageInterface interface {
}
