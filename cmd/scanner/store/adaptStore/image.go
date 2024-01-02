package adaptStore

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ImageDal interface {
	UpdateImage(ctx context.Context, where string, updater map[string]interface{}, image *model.ImageList) error
	DeleteImage(ctx context.Context, imageId int64) error
	CreateImage(ctx context.Context, image *model.ImageList) error
	SearchImage(ctx context.Context, param imagesec.SearchImageParam, filter *imagesec.Filter) ([]model.ImageList, int64, error)
	GroupRegistryProject(ctx context.Context, param GroupRegistryRepoParam) ([]imagesec.Project, error)
}

type ScanImageInterface interface {
}
