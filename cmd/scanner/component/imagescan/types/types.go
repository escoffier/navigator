package types

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type ScanImageTaskDequeue interface {
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
	GetImageCorrelateData(ctx context.Context, param imagesecModel.ImageAssociateParam) (
		*imagesecModel.ImageWithCorrelateData2, error)
	ListImageWithScanInfo(ctx context.Context, param imagesecModel.ImageSearchApiParam) (
		[]*imagesecModel.ImageBaseResponse, int64, error)
}

type NodeReportService interface {
	SearchNode(ctx context.Context, param imagesecModel.SearchNodeInfoParam) ([]*imagesecModel.NodeInfo, int64, error)
}

type LatestDBVersion struct {
	Avira    string
	ClamAv   string
	Webshell string
}

type MalwareService interface {
	// 同一个 client 保证线程安全
	ScanMalware(ctx context.Context, path string, recursion bool) ([]string, error)
	// 更新db库
	UpdateDB(ctx context.Context, config imagesecModel.DBMeta, data []byte) error
}

type UpdateDBService interface {
	UpdateDB(ctx context.Context, param imagesecModel.UpdateDbParam) error
}

type UpdateDBEngin interface {
	UpdateDB(ctx context.Context, param imagesecModel.UpdateDbParam) (*imagesecModel.ScanDbMeta, error)
}

type DispatchDBService interface {
	SendToSubScanner(ctx context.Context) error
	SendToNode(ctx context.Context) error
}

type RPCReceiver interface {
	ReceiveFromRPC(ctx context.Context) error
}
