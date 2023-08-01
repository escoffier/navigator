package types

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ImageService interface {
	GetImageCorrelateData(ctx context.Context, param imagesecModel.GetImageAssociateDataParam) (*imagesecModel.ImageWithCorrelateData2, error)
}
