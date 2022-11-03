package api

import (
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ExportTensorTaskView struct {
	ID          int64  `json:"id"`          // 任务ID
	TaskType    string `json:"taskType"`    // 任务类型，周期任务，一次性任务等，暂时不用
	ExecuteType string `json:"executeType"` // 导出类型,根据该名字取确实具体的执行函数
	Parameter   string `json:"parameter"`   // 执行的参数
	FilePath    string `json:"filePath"`    // 文件名（含绝对路径）
	Creator     string `json:"creator"`     // 任务创建人
	StartAt     int64  `json:"startAt"`     // 任务开始执行时间
	FinishAt    int64  `json:"finishAt"`    // 任务执行完成时间
	ErrMsg      string `json:"errMsg"`      // 错误信息
	Status      int    `json:"status"`      // 当前的状态

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func ModelToView(data model.ExportTensorTask) ExportTensorTaskView {

	task := ExportTensorTaskView{
		ID:          data.ID,
		ExecuteType: data.ExecuteType,
		TaskType:    data.TaskType,
		Parameter:   data.Parameter,
		Creator:     data.Creator,
		StartAt:     data.StartAt,
		FinishAt:    data.FinishAt,
		ErrMsg:      data.ErrMsg,
		CreatedAt:   data.CreatedAt,
	}
	task.FilePath = GetFilename(data.FilePath)

	switch data.ExecuteType {
	case consts.ExportSingleImage, consts.ExportScanResult, consts.ExportImageSearch:
		task.ExecuteType = consts.ExportImageView
	case consts.ExportVuln:
		task.ExecuteType = consts.ExportVulnView
	case consts.AuditExeType:
		task.ExecuteType = consts.AuditExeTypeView
	}

	if data.StartAt <= consts.ExportHtmlReady {
		task.Status = consts.ExportStatusPending
	}
	if data.StartAt > consts.ExportHtmlReady && data.FinishAt == 0 {
		task.Status = consts.ExportStatusRunning
	}
	if data.FinishAt > 0 && data.ErrMsg == "" {
		task.Status = consts.ExportStatusFinish
	}
	if data.FinishAt > 0 && data.ErrMsg != "" {
		task.Status = consts.ExportStatusError
	}

	return task
}
