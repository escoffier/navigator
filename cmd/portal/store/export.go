package store

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/security-rd/go-pkg/databases"
)

type ExportTaskDal interface {
	CreateExportTask(ctx context.Context, data *imagesec.ExportTensorTask) error
	SearchExportTask(ctx context.Context, param imagesec.SearchExportTaskParam) ([]imagesec.ExportTensorTask, int64, error)
}

type exportTaskStore struct {
	db *databases.RDBInstance
}

func NewExportTaskDao(db *databases.RDBInstance) ExportTaskDal {
	return &exportTaskStore{db: db}
}

func (s *exportTaskStore) CreateExportTask(ctx context.Context, data *imagesec.ExportTensorTask) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	data.Serialize()
	if err := data.Check(); err != nil {
		return err
	}

	db := s.db.Get().WithContext(ctx).Create(data)

	return db.Error
}

func (s *exportTaskStore) SearchExportTask(ctx context.Context, param imagesec.SearchExportTaskParam) ([]imagesec.ExportTensorTask, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	db := s.db.Get().WithContext(ctx).Model(new(imagesec.ExportTensorTask))
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if param.TaskType != "" {
		db = db.Where("task_type = ?", param.TaskType)
	}
	if len(param.ExecuteType) > 0 {
		db = db.Where("execute_type IN ?", param.ExecuteType)
	}
	var count int64
	if err := db.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	db = imagesec.AddFilter(db, param.Filter)
	res := make([]imagesec.ExportTensorTask, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	for i := range res {
		res[i].Deserialize()
	}
	return res, count, nil
}
