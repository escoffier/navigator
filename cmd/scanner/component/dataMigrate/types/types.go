package types

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ImageService interface {
	GetImageCorrelateData(ctx context.Context, imageID int64) (*imagesecModel.ImageWithCorrelateData2, []*imagesecModel.Vuln, error)
}
