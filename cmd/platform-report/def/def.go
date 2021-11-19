package def

import (
	"context"
	"errors"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	ErrTaskConflict              = errors.New("report task conflict")
	ErrTaskTemplateNameDuplicate = errors.New("task template name conflict")
	ErrTaskTemplateNotExist      = errors.New("task template not exist")
	ErrReportNotFound            = errors.New("report not found")
)

type TaskManager interface {
	GetTaskTemplate(ctx context.Context, id int32) (*model.ReportTaskTemplateMeta, error)
	CreateTaskTemplate(ctx context.Context, template *model.ReportTaskTemplateMeta) (id int32, err error)
	UpdateTaskTemplate(ctx context.Context, template *model.ReportTaskTemplateMeta) error
	DeleteTaskTemplate(ctx context.Context, id int32) error
	LoadAllTaskTemplates(ctx context.Context) ([]*model.ReportTaskTemplateMeta, error)
	GetReportTaskTemplates(ctx context.Context, types []string, query string, offset, limit int) ([]*model.ReportTaskTemplateMeta, int64, error)

	CreateTask(ctx context.Context, taskID int32, startTimestamp, endTimestamp int64) (uuid string, err error)
	DealExpireRecords(ctx context.Context, nowTime time.Time) error
	UpdateTaskFailed(ctx context.Context, uuid string) error
	FinishTask(ctx context.Context, templateID int32, uuid string, content []byte) error
	GetTemplateReports(ctx context.Context, templateID int32, offset, limit int) ([]*model.ReportRecord, int64, error)
	GetReport(ctx context.Context, uuid string) (*model.ReportDetail, error)
}

type EmailConf struct {
	Username string
	Password string
	Host     string
	Port     int
	BaseURL  string
}

type NotifyHandler interface {
	Notify(ctx context.Context, template *model.ReportTaskTemplateMeta, startTimestamp, endTimestamp int64) error
}
