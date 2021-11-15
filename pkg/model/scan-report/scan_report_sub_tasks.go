package scan_report

import (
	"database/sql/driver"
	"time"

	"gorm.io/gorm"
)

type SubTasksStatus uint8

const (
	SubTasksStatusWaiting   SubTasksStatus = iota // 待执行
	SubTasksStatusRunning                         // 执行中
	SubTasksStatusSucceeded                       // 执行成功
	SubTasksStatusFailed                          // 执行失败
	SubTasksStatusCancel                          // 任务取消
)

func (t SubTasksStatus) Value() (driver.Value, error) { return uint8(t), nil }

type SubTaskType uint8

const (
	SubTaskTypeCircle SubTaskType = iota // 周期任务，比如正常周期生成、或者自定义的任务
	SubTaskTypeOnce                      // 一次性任务，调用立即生成执行的任务或者自定义的任务

)

func (s SubTaskType) Value() (driver.Value, error) { return uint8(s), nil }

// TensorScanReportSubTasks 保存生成文件的信息
type TensorScanReportSubTasks struct {
	ID                    uint                   `gorm:"primarykey" json:"id"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"-"`
	DeletedAt             gorm.DeletedAt         `gorm:"index" json:"-"`
	Type                  SubTaskType            `gorm:"column:type;default:0;comment:任务类型,周期任务:0,一次性任务:1" json:"-"`
	ScanReportId          uint                   `gorm:"column:scan_report_id;uniqueIndex:scan_report_sub_tasks_uqx;priority:1;comment:报告ID,对应report_tasks表的主键" json:"-"`
	File                  []byte                 `gorm:"column:file;comment:报告内容" json:"-"`
	StartTimeStamp        int64                  `gorm:"column:start_timestamp;comment:开始时间" json:"start_timestamp"`
	EndTimeStamp          int64                  `gorm:"column:end_timestamp;uniqueIndex:scan_report_sub_tasks_uqx;priority:2;index:end_time_index;comment:结束时间" json:"end_timestamp"`
	Status                SubTasksStatus         `gorm:"column:status;comment:任务状态，待执行:0,执行中:1,成功:2,失败:3,取消:4" json:"-"`
	FailedCount           uint8                  `gorm:"column:failed_count;type:smallint;not null;default:0;comment:失败的次数" json:"-"` // 失败次数，如果任务失败超过三次，则不需要再次执行
	TensorScanReportTasks *TensorScanReportTasks `gorm:"foreignKey:ScanReportId" json:"-"`
}

func (TensorScanReportSubTasks) TableName() string { return "tensor_scan_report_sub_tasks" }
