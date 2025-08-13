package service

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/store"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ExportTaskInterface interface {
	CreateExportTask(ctx context.Context, data *imagesec.ExportTensorTask) error
	SearchExportTask(ctx context.Context, param imagesec.SearchExportTaskParam) ([]imagesec.ExportTensorTask, int64, error)
}

type ExportTaskSer struct {
	ExportTaskDal store.ExportTaskDal
	Log           *scannerUtils.LogEvent
}

func NewExportTaskService(dal store.ExportTaskDal) *ExportTaskSer {
	return &ExportTaskSer{ExportTaskDal: dal,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithModule("ExportTask"),
			scannerUtils.WithSubModule("exportTask")),
	}
}

func (s *ExportTaskSer) CreateExportTask(ctx context.Context, data *imagesec.ExportTensorTask) error {
	s.Log.Info().Interface("data", data).Msg("CreateExportTask")
	if err := s.ExportTaskDal.CreateExportTask(ctx, data); err != nil {
		s.Log.Err(err).Any("data", data).Msg("CreateExportTask")
		return err
	}
	s.Log.Info().Any("data", data).Msg("CreateExportTask")
	return nil
}

func (s *ExportTaskSer) SearchExportTask(ctx context.Context, param imagesec.SearchExportTaskParam) ([]imagesec.ExportTensorTask, int64, error) {
	tasks, count, err := s.ExportTaskDal.SearchExportTask(ctx, param)
	if err != nil {
		s.Log.Err(err).Interface("param", param).Msg("SearchExportTask")
		return nil, 0, err
	}
	s.Log.Info().Interface("param", param).Msg("SearchExportTask")
	return tasks, count, nil
}
