package store

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ImageDal interface {
	UpdateImage(ctx context.Context, where string, updater map[string]interface{}, image *model.ImageList) error
	DeleteImage(ctx context.Context, imageId int64) error
	SearchImage(ctx context.Context, param imagesec.SearchImageParam, filter *model.Filter) ([]model.ImageList, int64, error)
	GroupRegistryProject(ctx context.Context, param GroupRegistryRepoParam) ([]imagesec.Project, error)
}

type ScanImageInterface interface {
}
