package store

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ImageInterface interface {
	UpdateImage(ctx context.Context, where string, updater map[string]interface{}, image *model.ImageList) error
	SearchImage(ctx context.Context, param SearchImageParam, filter *model.Filter) ([]model.ImageList, int64, error)
}

type ScanImageInterface interface {
}
