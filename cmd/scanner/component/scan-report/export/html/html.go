package html

import (
	"context"
)

type ExportHtmlInterface interface {
	// 返回镜像ID，用于循环生成单个镜像报告
	GetImageIdNames(ctx context.Context, taskID int64) (*ImageIDNameWithTask, error)
	// 风险信息总揽
	GetRiskOverView(ctx context.Context, taskID int64) (*RiskOverView, error)
	// 镜像列表
	GetImages(ctx context.Context, taskID int64, starID int64) (*ImageResponse, error)
	// 漏洞列表
	GetExportVulns(ctx context.Context, taskID int64, severity int, canFixed string, starID int64) (*VulnWithImageResponse, error)
	// 镜像的漏洞列表
	GetImageVulns(ctx context.Context, taskID int64, imageID int64, severity int, starID int64) (*VulnWithImageResponse, error)
	// 病毒列表
	GetVirus(ctx context.Context, taskID int64) ([]VirusInfo, error)
	// 单个镜像报告
	GetImageRisk(ctx context.Context, taskID int64, imageID int64) (*ImageRiskOverView, error)
}
