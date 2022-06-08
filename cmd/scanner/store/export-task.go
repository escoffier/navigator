package store

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ExportTaskDal interface {
	SearchExportTensorTask(ctx context.Context, parma SearchExportTensorTask, filter *model.Filter) ([]model.ExportTensorTask, int64, error)
	CreateExportTensorTask(ctx context.Context, data model.ExportTensorTask) error
	UpdateExportTensorTask(ctx context.Context, where string, updater map[string]interface{}, data *model.ExportTensorTask) error
	DeleteExportTensorTask(ctx context.Context, param SearchExportTensorTask) error
}

type ExportTaskDao struct {
	db *databases.RDBInstance
}

func (dal *ExportTaskDao) DeleteExportTensorTask(ctx context.Context, param SearchExportTensorTask) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportTensorTask))
	return db.Where("created_at < ? ", param.ExpirationDate).Delete(&model.ExportTensorTask{}).Error
}

func (dal *ExportTaskDao) CreateExportTensorTask(ctx context.Context, data model.ExportTensorTask) error {

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportTensorTask))

	return db.Create(&data).Error
}

func (dal *ExportTaskDao) UpdateExportTensorTask(ctx context.Context, where string, updater map[string]interface{}, data *model.ExportTensorTask) error {
	if where == "" {
		return fmt.Errorf("no where condition")
	}

	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	db := dal.db.Get().WithContext(timeoutCtx).Model(new(model.ExportTensorTask))
	db = db.Where(where)
	if len(updater) > 0 {
		return db.Updates(updater).Error
	}
	if data != nil {
		return db.Updates(dal).Error
	}
	return nil
}

func NewExportTaskDao(db *databases.RDBInstance) *ExportTaskDao {
	return &ExportTaskDao{db: db}
}

func (dal *ExportTaskDao) SearchExportTensorTask(ctx context.Context, parma SearchExportTensorTask, filter *model.Filter) ([]model.ExportTensorTask, int64, error) {

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportTensorTask))

	if parma.ExecuteType != "" {
		db = db.Where("execute_type = ?", parma.ExecuteType)
	}
	if parma.ID > 0 {
		db = db.Where("id = ?", parma.ID)
	}
	if parma.Finished == consts.TrueString {
		db = db.Where("finish_at > ?", 0)
	} else if parma.Finished == consts.FalseString {
		db = db.Where("finish_at = 0 OR finish_at is null")
	}
	if parma.Failure == consts.TrueString {
		db = db.Where("err_msg != ?", "")
	} else if parma.Failure == consts.FalseString {
		db = db.Where("err_msg = '' OR err_msg is null")
	}
	if parma.Parameter != "" {
		db = db.Where("parameter = ? ", parma.Parameter)
	}
	if len(parma.NotIds) > 0 {
		db = db.Where("id NOT IN  ? ", parma.NotIds)
	}
	var count int64
	if err := db.Count(&count).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)
	res := make([]model.ExportTensorTask, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}

	return res, count, nil
}

type ResourceDal interface {
	SearchResources(ctx context.Context, imageUUID uint32) ([]TensorResources, error)
}

type ResourceDao struct {
	db *databases.RDBInstance
}

func NewResourceDao(db *databases.RDBInstance) *ResourceDao {
	return &ResourceDao{db: db}
}

type TensorResources struct {
	Name         string
	ResourceName string
	Namespace    string
	ClusterKey   string
	ClusterName  string
}

func (dal *ResourceDao) SearchResources(ctx context.Context, imageUUID uint32) ([]TensorResources, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx)
	db = db.Model(new(model.TensorContainer)).Where("image_uuid = ?", imageUUID)
	res := make([]model.TensorContainer, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}

	// 再查集群名
	clusters := make([]model.TensorCluster, 0)
	err := dal.db.Get().WithContext(ctx).Model(new(model.TensorCluster)).Find(&clusters).Error
	if err != nil {
		return nil, err
	}
	// 数据不多，两层循环
	ans := make([]TensorResources, len(res))
	for i := range ans {
		ans[i] = TensorResources{
			Name:         res[i].Name,
			ResourceName: res[i].ResourceName,
			Namespace:    res[i].Namespace,
			ClusterKey:   res[i].ClusterKey,
		}
	}
	// 数据不多，两层循环
	for i := range ans {
		for j := range clusters {
			if ans[i].ClusterKey == clusters[j].Key {
				ans[i].ClusterName = clusters[j].Name
				break
			}
		}
	}

	return ans, nil
}

type ScanTaskDal interface {
	GetSubTasks(ctx context.Context, param SearchSubTaskParam, filter *model.Filter) ([]model.SubTask, int64, error)
	GetTasks(ctx context.Context, param SearchTaskParam, filter *model.Filter) ([]model.Task, int64, error)
}
