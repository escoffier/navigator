package types

import (
	"context"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ExportHtmlInterface interface {
	// 返回镜像ID，用于循环生成单个镜像报告
	GetImageIdNames(ctx context.Context, taskID int64) (*ImageIDNameWithTask, error)
	// 风险信息总揽
	GetRiskOverView(ctx context.Context, taskID int64) (*RiskOverView, error)
	// 镜像列表
	GetImages(ctx context.Context, taskID int64, starID int64) (*ImageResponse, error)
	// 漏洞列表
	GetExportVuln(ctx context.Context, param GetExportVulnParam) (*VulnWithImageResponse, error)
	// 镜像的漏洞列表
	GetImageVuln(ctx context.Context, param GetExportVulnParam) (*VulnWithImageResponse, error)
	// 病毒列表
	GetVirus(ctx context.Context, taskID int64) ([]VirusInfo, error)
	// 单个镜像报告
	GetImageRisk(ctx context.Context, taskID int64, imageID int64) (*ImageRiskOverView, error)
}

type ScanTaskService interface {
	SearchScanSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) ([]*imagesecModel.ImageScanSubTask, int64, error)
}

type GetExportVulnParam struct {
	TaskID   int64
	ImageID  int64
	Severity string
	CanFixed string
	StartID  int64
	Limit    int64
}

type SearchExportTaskParam struct {
	Finished     string
	Failure      string
	ExecuteType  []string
	NeedCiReport string
}

type GetExportTaskParam struct {
	ID   int64
	UUID string
}
