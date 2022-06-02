package model

import (
	"fmt"
	"time"
)

// 数据导出任务
type ExportTensorTask struct {
	ID          int64  `json:"id"`          // 任务ID
	TaskType    string `json:"taskType"`    // 任务类型，周期任务，一次性任务等，暂时不用
	ExecuteType string `json:"executeType"` // 导出类型,根据该名字取确实具体的执行函数
	Parameter   string `json:"parameter"`   // 执行的参数
	FilePath    string `json:"filePath"`    // 文件的绝对路径

	Creator string `json:"creator"` // 任务创建人

	StartAt  int64  `json:"startAt"`  // 任务开始执行时间
	FinishAt int64  `json:"finishAt"` // 任务执行完成时间
	ErrMsg   string `json:"errMsg"`   // 错误信息

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Header数据
type ExportTensorHeader struct {
	ID          int64    `json:"id"`          // 任务ID
	ExecuteType string   `json:"executeType"` // 任务名
	SheetName   string   `json:"sheetName"`
	HeaderJSON  string   `json:"-"` // 导出文件头 []string 序列化后的结果
	Header      []string `json:"header"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	DeletedAt int64     `json:"deletedAt"`
}

func (ExportTensorTask) TableName() string {
	return "ivan_export_task"
}

func (s *ExportTensorTask) Check() error {
	if s.Creator == "" {
		return fmt.Errorf("no creator")
	}
	if s.Parameter == "" {
		return fmt.Errorf("no parameter")
	}
	return nil
}

func (s *ExportTensorTask) Serialize() {

}

func (s *ExportTensorTask) Deserialize() {

}
