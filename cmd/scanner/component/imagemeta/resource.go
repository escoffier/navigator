package imagemeta

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ResourceService interface {
	SearchResource(ctx context.Context, param imagesecModel.SearchResourceParam) ([]model.TensorRawContainer, int64, error)
}
