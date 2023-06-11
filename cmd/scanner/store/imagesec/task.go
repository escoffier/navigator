package imagesec

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ScanTaskDal interface {
	CreateScanTask(ctx context.Context, data *imagesecModel.ImageScanTask) error
	UpdateScanTask(ctx context.Context, param imagesecModel.UpdateTaskParam) error
	SearchScanTask(ctx context.Context, param imagesecModel.SearchTaskParam) ([]*imagesecModel.ImageScanTask, int64, error)

	CreateScanSubtask(ctx context.Context, data []*imagesecModel.ImageScanSubTask) error
	UpdateScanSubtask(ctx context.Context, param imagesecModel.UpdateTaskParam) error

	SearchScanSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) ([]*imagesecModel.ImageScanSubTask, int64, error)
	GroupScanSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) (imagesecModel.TaskStatusGroup, error)
	DeleteSubScanTask(ctx context.Context, param imagesecModel.SearchTaskParam) error
}

type ScanTaskDao struct {
	db *databases.RDBInstance
}

func NewScanTaskDao(db *databases.RDBInstance) *ScanTaskDao {
	return &ScanTaskDao{db: db}
}

func (dal *ScanTaskDao) DeleteSubScanTask(ctx context.Context, param imagesecModel.SearchTaskParam) error {
	if param.SubtaskID <= 0 && param.ImageUniqueID <= 0 {
		return fmt.Errorf("not get subtaskID or ImageUniqueID")
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	m := &imagesecModel.ImageScanSubTask{}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName())

	if param.SubtaskID > 0 {
		db = db.Where("id = ?", param.SubtaskID)
	}
	if param.ImageUniqueID > 0 {
		db = db.Where("image_unique_id = ?", param.ImageUniqueID)
	}
	return db.Delete(&m).Error
}

func (dal *ScanTaskDao) CreateScanTask(ctx context.Context, data *imagesecModel.ImageScanTask) error {

	data.Serialize()

	if err := data.Check(); err != nil {
		return err
	}

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	return dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).Create(data).Error
}

func (dal *ScanTaskDao) UpdateScanTask(ctx context.Context, param imagesecModel.UpdateTaskParam) error {
	if err := param.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.ImageScanTask).TableName())
	db = db.Where("id = ?", param.ID)
	if param.Where != "" {
		db = db.Where(param.Where)
	}
	if len(param.Updater) > 0 {
		return db.Updates(param.Updater).Error
	}
	return nil
}

func (dal *ScanTaskDao) SearchScanTask(ctx context.Context, param imagesecModel.SearchTaskParam) (
	[]*imagesecModel.ImageScanTask, int64, error) {
	param.Serialize()

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	m := imagesecModel.ImageScanTask{}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName())
	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}
	if param.ImageFromType != "" {
		db = db.Where("image_from_type = ?", param.ImageFromType)
	}
	if param.TaskID > 0 {
		db = db.Where("id = ?", param.TaskID)
	}
	if param.Where != "" {
		db = db.Where(param.Where)
	}
	if param.Started == consts.TrueString {
		db = db.Where("started_at > 0 ")
	} else if param.Started == consts.FalseString {
		db = db.Where("started_at = 0 ")
	}
	if param.Finished == consts.TrueString {
		db = db.Where("finished_at > 0 ")
	} else if param.Finished == consts.FalseString {
		db = db.Where("finished_at = 0 ")
	}
	if len(param.ScanType) > 0 {
		db = db.Where("scan_type IN ?", param.ScanType)
	}
	if len(param.ScanStatus) > 0 {
		db = db.Where("status IN ?", param.ScanStatus)
	}
	if len(param.NotScanStatus) > 0 {
		db = db.Where("status NOT IN ?", param.NotScanStatus)
	}
	if param.NodeNameKeyword != "" {
		sub := dal.db.Get().WithContext(ctx).Table(new(imagesecModel.ImageScanSubTask).TableName()).Select("distinct task_id").
			Where("node_host_name like ? OR image_name like ? ", fmt.Sprintf("%%%s%%", param.NodeNameKeyword),
				fmt.Sprintf("%%%s%%", param.NodeNameKeyword))
		db = db.Where("id IN (?)", sub)
	}

	var cnt int64

	if err := db.Count(&cnt).Error; err != nil {
		return nil, cnt, err
	}

	db = model.AddFilter(db, param.Filter)
	res := make([]*imagesecModel.ImageScanTask, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	for i := range res {
		res[i].Deserialize()
	}
	return res, cnt, nil
}

func (dal *ScanTaskDao) CreateScanSubtask(ctx context.Context, data []*imagesecModel.ImageScanSubTask) error {
	for i := range data {
		data[i].Serialize()
		if err := data[i].Check(); err != nil {
			return err
		}
	}

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	m := &imagesecModel.ImageScanSubTask{}
	return dal.db.Get().WithContext(cancelCtx).Table(m.TableName()).CreateInBatches(data, consts.DefaultBathSize).Error
}

func (dal *ScanTaskDao) UpdateScanSubtask(ctx context.Context, param imagesecModel.UpdateTaskParam) error {
	if err := param.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.ImageScanSubTask).TableName())
	db = db.Where("id = ?", param.ID)
	if param.Where != "" {
		db = db.Where(param.Where)
	}
	if len(param.Updater) > 0 {
		return db.Updates(param.Updater).Error
	}
	return nil
}

func (dal *ScanTaskDao) SearchScanSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) (
	[]*imagesecModel.ImageScanSubTask, int64, error) {
	param.IsSearchSubtask = true
	param.Serialize()

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	m := imagesecModel.ImageScanSubTask{}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName())
	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}
	if param.ImageUniqueID > 0 {
		db = db.Where("image_unique_id = ?", param.ImageUniqueID)
	}
	if param.TaskID > 0 {
		db = db.Where("task_id = ?", param.TaskID)
	}
	if param.SubtaskID > 0 {
		db = db.Where("id = ?", param.SubtaskID)
	}
	if param.Started == consts.TrueString {
		db = db.Where("started_at > 0 ")
	} else if param.Started == consts.FalseString {
		db = db.Where("started_at = 0 ")
	}
	if param.Finished == consts.TrueString {
		db = db.Where("finished_at > 0 ")
	} else if param.Finished == consts.FalseString {
		db = db.Where("finished_at = 0 ")
	}
	if len(param.ScanStatus) > 0 {
		db = db.Where("status IN ?", param.ScanStatus)
	}
	if len(param.NotScanStatus) > 0 {
		db = db.Where("status NOT IN ?", param.NotScanStatus)
	}

	if param.NodeClusterKey != "" {
		db = db.Where("node_cluster_key = ?", param.NodeClusterKey)
	}

	if param.NodeUniqueID > 0 {
		db = db.Where("node_unique_id = ?", param.NodeUniqueID)
	}
	if param.NodeNameKeyword != "" {
		db = db.Where("node_host_name like ? OR image_name like ? ", fmt.Sprintf("%%%s%%", param.NodeNameKeyword),
			fmt.Sprintf("%%%s%%", param.NodeNameKeyword))
	}

	if param.Where != "" {
		db = db.Where(param.Where)
	}
	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}

	var cnt int64

	if err := db.Count(&cnt).Error; err != nil {
		return nil, cnt, err
	}

	db = model.AddFilter(db, param.Filter)
	res := make([]*imagesecModel.ImageScanSubTask, 0)
	err := db.Find(&res).Error
	if err != nil {
		return nil, 0, err
	}
	for i := range res {
		res[i].Deserialize()
	}
	return res, cnt, err
}

func (dal *ScanTaskDao) GroupScanSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) (
	imagesecModel.TaskStatusGroup, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	type Group struct {
		Status int64
		Cnt    int64
	}
	ans := imagesecModel.TaskStatusGroup{}
	group := make([]Group, 0)
	m := &imagesecModel.ImageScanSubTask{}

	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName()).Where("task_id = ?", param.TaskID)
	if param.Where != "" {
		db = db.Where(param.Where)
	}
	err := db.Select("count(id) as cnt", "status").Group("status").Find(&group).Error
	if err != nil {
		return ans, err
	}

	for i := range group {
		ans.All += group[i].Cnt
		switch group[i].Status {
		case imagesecModel.TaskStatusSendFinished:
			ans.SendFinished += group[i].Cnt
		case imagesecModel.TaskStatusNotReady:
			ans.NotReady += group[i].Cnt
		case imagesecModel.TaskStatusPending:
			ans.Pending += group[i].Cnt
		case imagesecModel.TaskStatusInprogress:
			ans.Inprogress += group[i].Cnt
		case imagesecModel.TaskStatusScanFinished:
			ans.ScanFinished += group[i].Cnt
		case imagesecModel.TaskStatusDetectFinished:
			ans.DetectFinished += group[i].Cnt
		case imagesecModel.TaskStatusPause:
			ans.Pause += group[i].Cnt
		case imagesecModel.TaskStatusTerminate:
			ans.Terminate += group[i].Cnt
		case imagesecModel.TaskStatusFailed:
			ans.Failed += group[i].Cnt
		}
	}
	return ans, nil
}
