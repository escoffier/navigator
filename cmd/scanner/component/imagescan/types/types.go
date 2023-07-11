package types

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type Dequeue interface {
	GenSubtaskChan(ctx context.Context) chan imagesecTypes.ScanSubTask
	GenUpdateSubtaskChan(ctx context.Context) chan UpdateSubTask
}

type UpdateSubTask struct {
	CreatedAt int64
	SubtaskID int64
	Status    int64
	Err       error
	Reason    string
	RetryCnt  int64
}

type UpdateTask struct {
	CreatedAt int64
	TaskID    int64
	Status    int64
	RetryCnt  int64
}

type ImageService interface {
	GetImageCorrelateData(ctx context.Context, param imagesecModel.GetImageAssociateDataParam) (
		*imagesecModel.ImageWithCorrelateData2, error)
	ListImageWithScanInfo(ctx context.Context, param imagesecModel.ImageListParam) (
		[]*imagesecModel.ImageBaseResponse, int64, error)
}

type NodeReportService interface {
	SearchNode(ctx context.Context, param imagesecModel.SearchNodeInfoParam) ([]*imagesecModel.NodeInfo, int64, error)
}
