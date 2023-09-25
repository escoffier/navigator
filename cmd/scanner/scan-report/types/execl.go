package types

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type UpdateExportTask interface {
	Start(ctx context.Context, id int64) error
	Success(ctx context.Context, id int64, filePath string) error
	Failure(ctx context.Context, id int64, msg string) error
	IncrRedisFinished(ctx context.Context, taskID int64) error
	SetRedisAll(ctx context.Context, taskID, all int64) error
	DeleteRedisData(ctx context.Context, taskID int64) error
	// DeleteIdempotent(ctx context.Context) error
}

type VulnService interface {
	SearchVuln(ctx context.Context, param imagesecModel.ApiSearchVulnParam) ([]*imagesecModel.VulnView, int64, error)
}

type TaskExportParma struct {
	ScanTaskID    int64  `json:"scanTaskId"`
	ImageFromType string `json:"imageFromType"`
}

type ExcelExportService interface {
	RunExport(ctx context.Context, executeType string, imageChanFunc GenImageChanFunc, convertDataFunc ConvertDataFunc)
}

type GenImageChanFunc func(ctx context.Context, task model.ExportTensorTask) chan imagesecModel.Image

type ConvertDataFunc func(res map[SheetName]chan []string, lang string) map[SheetName]chan []string

type SingeImageExportParam struct {
	ImageFromType string `json:"imageFromType"`
	ImageID       int64  `json:"imageID"`
	FullRepoName  string `json:"fullRepoName"`
	Tag           string `json:"tag"`
	Library       string `json:"library"`
}

type ScanTaskExportParam struct {
	ScanTaskID    int64  `json:"scanTaskId"`
	TaskCreateAt  string `json:"taskCreateAt"`
	ImageFromType string `json:"imageFromType"`
}

type ImageSrvInterface interface {
	GetImageCorrelateData(ctx context.Context, param imagesecModel.GetImageAssociateDataParam) (*imagesecModel.ImageWithCorrelateData2, error)
	ListImageWithScanInfo(ctx context.Context, param imagesecModel.ImageSearchApiParam) ([]*imagesecModel.ImageBaseResponse, int64, error)
}

type ExcelMeta struct {
	SheetName SheetName
	Filename  string
	Header    []string
}

type ExcelMetaDataOption func(data *ExcelMeta)

// key：excel sheet name
// value：`chan []string`：表示一个sheet的数据流(一个镜像或一个漏洞的数据)
// 为啥使用：[] chan []string ，因为要导出多个镜像
type ExcelExportImageData map[SheetName][]chan []string

type ExcelDataWithMeta struct {
	ExcelExportImageData ExcelExportImageData
	Filepath             string
	ExcelMeta            []ExcelMeta
	ExportTask           model.ExportTensorTask
}

type SheetName string

func (vi SheetName) String() string {
	return string(vi)
}
