package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ExportTaskDal interface {
	SearchExportTensorTask(ctx context.Context, parma SearchExportTensorTask, filter *model.Filter) ([]model.ExportTensorTask, int64, error)
	CreateExportTensorTask(ctx context.Context, data *model.ExportTensorTask) error
	UpdateExportTensorTask(ctx context.Context, where string, updater map[string]interface{}, data *model.ExportTensorTask) error
	DeleteExportTensorTask(ctx context.Context, taskID int64) error
	DeleteExportVulnImage(ctx context.Context, taskId int64) error
	CreateExportTaskImage(ctx context.Context, data []*model.ExportTaskImage) error
	DeleteExportTaskImage(ctx context.Context, taskID int64) error
	SearchExportTaskImage(ctx context.Context, param SearchExportTaskImageParam, filter *model.Filter) ([]model.ExportTaskImage, error)
	GetExportImageRelatedVuln(ctx context.Context, uniqueVuln uint64, taskId int64) ([]model.ExportTaskImage, error)
	SearchHtmlPrepare(ctx context.Context, taskID int64, dataType int8) ([]model.ExportHtmlPrepare, error)
	CreateOrUpdateHtmlPrepare(ctx context.Context, data *model.ExportHtmlPrepare) error

	SearchHtmlVulnImage(ctx context.Context, param SearchHtmlVulnImageParam, filter *model.Filter) ([]model.ExportVulnImage, error)
	CreateHtmlVulnImage(ctx context.Context, data []*model.ExportVulnImage) error

	CreateExportIdempotent(ctx context.Context, id int64) (bool, error)
}

type ExportTaskDao struct {
	db *databases.RDBInstance
}

func (dal *ExportTaskDao) CreateExportIdempotent(ctx context.Context, id int64) (bool, error) {

	data := &model.Idempotent{
		DataID:   id,
		DataName: new(model.ExportTensorTask).TableName(),
	}

	if err := data.Valid(); err != nil {
		return false, err
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(model.Idempotent{})
	err := db.Create(data).Error
	if err == nil {
		return true, nil
	}
	if strings.Contains(err.Error(), consts.DuplicateKey) {
		return false, nil
	}
	return false, err
}

func (dal *ExportTaskDao) SearchHtmlVulnImage(ctx context.Context, param SearchHtmlVulnImageParam, filter *model.Filter) ([]model.ExportVulnImage, error) {
	if param.TaskID <= 0 {
		return nil, fmt.Errorf("no taskID")
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*200)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportVulnImage))
	db = db.Where("task_id = ?", param.TaskID)
	if len(param.UniqueVulns) > 0 {
		db = db.Where("unique_vuln IN ?", param.UniqueVulns)
	}
	if param.CanFixed == model.TrueString {
		db = db.Where("can_fixed  = ?", true)
	}
	if param.CanFixed == model.FalseString {
		db = db.Where("can_fixed  = ?", false)
	}
	if param.Severity > 0 {
		db = db.Where("severity  = ?", param.Severity)
	}
	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}

	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}
	db = model.AddFilter(db, filter)

	res := make([]model.ExportVulnImage, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	for i := range res {
		res[i].Deserialize()
	}
	return res, nil
}

func (dal *ExportTaskDao) CreateHtmlVulnImage(ctx context.Context, data []*model.ExportVulnImage) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportVulnImage))
	for i := range data {
		data[i].Serialize()
	}

	return db.CreateInBatches(data, consts.DefaultCreateInBatches).Error
}

// 查出这个漏洞关联的本次任务查找出来的镜像
func (dal *ExportTaskDao) GetExportImageRelatedVuln(ctx context.Context, uniqueVuln uint64, taskId int64) ([]model.ExportTaskImage, error) {
	if uniqueVuln <= 0 || taskId <= 0 {
		return nil, fmt.Errorf("no taskID or uniqueVuln")
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*20)
	defer cancelFunc()
	vulnTable := new(model.VulnImage).TableName()
	exportTable := model.ExportTaskImage{}.TableName()

	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportTaskImage))

	db = db.Select("task_id", fmt.Sprintf("%s.image_id", exportTable), "image_name")
	db.Joins(fmt.Sprintf("JOIN %s  where  %s.image_id = %s.image_id and %s.unique_vuln = %d and %s.task_id = %d",
		vulnTable, exportTable, vulnTable, vulnTable, uniqueVuln, exportTable, taskId))

	res := make([]model.ExportTaskImage, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (dal *ExportTaskDao) SearchExportTaskImage(ctx context.Context, param SearchExportTaskImageParam, filter *model.Filter) ([]model.ExportTaskImage, error) {
	if param.TaskID <= 0 {
		return nil, fmt.Errorf("no taskID")
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportTaskImage))
	db = db.Where("task_id = ?", param.TaskID)

	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}
	if len(param.ImageIds) > 0 {
		db = db.Where("image_id IN ?", param.ImageIds)
	}

	db = model.AddFilter(db, filter)
	res := make([]model.ExportTaskImage, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (dal *ExportTaskDao) SearchHtmlPrepare(ctx context.Context, taskID int64, dataType int8) ([]model.ExportHtmlPrepare, error) {
	if taskID <= 0 {
		return nil, fmt.Errorf("no taskID")
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportHtmlPrepare))
	db = db.Where("task_id = ?", taskID)
	db = db.Where("data_type = ?", dataType)

	res := make([]model.ExportHtmlPrepare, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (dal *ExportTaskDao) CreateOrUpdateHtmlPrepare(ctx context.Context, data *model.ExportHtmlPrepare) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportHtmlPrepare))
	if err := db.Create(data).Error; err != nil && strings.Contains(err.Error(), consts.DuplicateKey) {
		db = dal.db.Get().WithContext(ctx).Model(model.ExportHtmlPrepare{})
		db = db.Where("task_id = ?", data.TaskID)
		db = db.Where("data_type = ?", data.DataType)
		updater := map[string]interface{}{"data": data.Data}

		return db.Updates(updater).Error
	}
	return nil
}

func (dal *ExportTaskDao) CreateExportTaskImage(ctx context.Context, data []*model.ExportTaskImage) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportTaskImage))

	return db.CreateInBatches(data, consts.DefaultCreateInBatches).Error
}

func (dal *ExportTaskDao) DeleteExportTaskImage(ctx context.Context, taskId int64) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportTaskImage))
	return db.Where("task_id  = ? ", taskId).Delete(&model.ExportTaskImage{}).Error
}

func (dal *ExportTaskDao) DeleteExportVulnImage(ctx context.Context, taskId int64) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportVulnImage))
	return db.Where("task_id  = ? ", taskId).Delete(&model.ExportVulnImage{}).Error
}

func (dal *ExportTaskDao) DeleteExportTensorTask(ctx context.Context, taskID int64) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportTensorTask))
	return db.Where("id  = ? ", taskID).Delete(&model.ExportTensorTask{}).Error
}

func (dal *ExportTaskDao) CreateExportTensorTask(ctx context.Context, data *model.ExportTensorTask) error {

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ExportTensorTask))

	return db.Create(data).Error
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

	if !parma.ExpirationDate.IsZero() {
		db = db.Where("created_at < ?", parma.ExpirationDate)
	}

	if len(parma.ExecuteType) > 0 {
		db = db.Where("execute_type IN ?", parma.ExecuteType)
	}
	if parma.ID > 0 {
		db = db.Where("id = ?", parma.ID)
	}
	if parma.Finished == consts.TrueString {
		db = db.Where("finish_at > ?", 0)
	} else if parma.Finished == consts.FalseString {
		db = db.Where("finish_at = 0")
	}
	if parma.Failure == consts.TrueString {
		db = db.Where("err_msg != ?", "")
	} else if parma.Failure == consts.FalseString {
		db = db.Where("err_msg = ''")
	}
	if parma.Parameter != "" {
		db = db.Where("parameter = ? ", parma.Parameter)
	}
	if len(parma.NotIds) > 0 {
		db = db.Where("id NOT IN  ? ", parma.NotIds)
	}
	if parma.TaskType != "" {
		db = db.Where("task_type =  ? ", parma.TaskType)
	}
	if parma.ExportHtmlReady == consts.TrueString {
		db = db.Where("start_at = ?", consts.ExportHtmlReady)
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
