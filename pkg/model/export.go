package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
)

// 数据导出任务
type ExportTensorTask struct {
	ID          int64  `json:"id"`          // 任务ID
	TaskType    string `json:"taskType"`    // 任务类型，Html或excel
	ExecuteType string `json:"executeType"` // 导出类型,根据该名字取确定具体执行函数
	Parameter   string `json:"parameter"`   // 执行的参数
	FilePath    string `json:"filePath"`    // 文件的绝对路径

	Creator string `json:"creator"` // 任务创建人

	StartAt  int64  `json:"startAt"`  // 任务开始执行时间
	FinishAt int64  `json:"finishAt"` // 任务执行完成时间
	ErrMsg   string `json:"errMsg"`   // 错误信息

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (s *ExportTensorTask) GenRedisAllKey() string {
	return fmt.Sprintf("export-all-%s-%d", s.TaskType, s.ID)
}

func (s *ExportTensorTask) GenRedisFinishedKey() string {
	return fmt.Sprintf("export-finished-%s-%d", s.TaskType, s.ID)
}

func (s *ExportTensorTask) GenFilenamePrefix() string {
	return strings.ReplaceAll(s.FilePath, ".zip", "")
}

// 导出html时一些中间数据
type ExportHtmlPrepare struct {
	ID       int64  `gorm:"id" json:"ID"`
	TaskID   int64  `gorm:"column:task_id" json:"taskID"`
	DataType int8   `gorm:"column:data_type" json:"dataType"` // 数据类型
	Data     string `gorm:"column:data" json:"data"`
}

func (ExportHtmlPrepare) TableName() string {
	return "ivan_export_html_prepare"
}

const (
	ExportHtmlPrepareRiskOver      = 1
	ExportHtmlPrepareVulnLastImage = 2
)

type ExportTaskImage struct {
	ID        int64  `gorm:"id"  json:"id"`
	TaskID    int64  `gorm:"task_id" json:"taskID"`
	ImageID   int64  `gorm:"column:image_id" json:"imageID"`
	ImageName string `gorm:"column:image_name" json:"imageName"`
}

func (ExportTaskImage) TableName() string {
	return "ivan_export_task_image"
}

type ExportVulnImage struct {
	ID         int64    `gorm:"column:id" json:"id"`
	TaskID     int64    `gorm:"column:task_id" json:"taskID"`
	UniqueVuln uint64   `gorm:"column:unique_vuln" json:"uniqueVuln,string"`
	Severity   int      `gorm:"column:severity" json:"severity"`
	CanFixed   bool     `gorm:"column:can_fixed" json:"canFixed"`
	ImagesJson string   `gorm:"column:images" json:"-"`
	Images     []string `gorm:"-" json:"images"`
}

func (ExportVulnImage) TableName() string {
	return "ivan_export_vuln_image"
}

func (evi *ExportVulnImage) Serialize() {
	if len(evi.Images) > 0 {
		bys, err := json.Marshal(evi.Images)
		if err != nil {
			logging.Get().Err(err).Msg("ExportVulnImage Serialize")
		} else {
			evi.ImagesJson = string(bys)
		}
	}
}
func (evi *ExportVulnImage) Deserialize() {
	if len(evi.ImagesJson) > 0 {
		images := make([]string, 0)
		err := json.Unmarshal([]byte(evi.ImagesJson), &images)
		if err != nil {
			logging.Get().Err(err).Msg("ExportVulnImage Deserialize")
		} else {
			evi.Images = images
		}
	}
	if evi.Images == nil {
		evi.Images = make([]string, 0)
	}
}

func (*ExportTensorTask) TableName() string {
	return "ivan_export_task"
}

func (s *ExportTensorTask) Check() error {
	if s.Creator == "" {
		return fmt.Errorf("no creator")
	}
	if s.TaskType != ExportExcel && s.TaskType != ExportHtml {
		return fmt.Errorf("incorrect task type")
	}
	return nil
}

func (s *ExportTensorTask) Serialize() {

}

func (s *ExportTensorTask) Deserialize() {

}

type Idempotent struct {
	ID        int64  `gorm:"id"  json:"id"`
	DataID    int64  `gorm:"column:data_id" json:"dataID"`
	DataName  string `gorm:"column:data_name" json:"dataName"`
	CreatedAt int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"`
	UpdatedAt int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"`
}

func (s *Idempotent) TableName() string {
	return "ivan_scanner_idempotent"
}

func (s *Idempotent) Valid() error {
	if s.DataID <= 0 {
		return fmt.Errorf("idempotent no tableID")
	}
	if s.DataName == "" {
		return fmt.Errorf("idempotent no tableName")
	}
	return nil
}
