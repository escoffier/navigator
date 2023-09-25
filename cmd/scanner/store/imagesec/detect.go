package imagesec

import (
	"context"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type DetectTaskDal interface {
	CreateDetectTask(ctx context.Context, data *imagesecModel.ImageDetectTask) error
	UpdateDetectTask(ctx context.Context, param imagesecModel.UpdateTaskParam) error
	SearchDetectTask(ctx context.Context, param imagesecModel.SearchTaskParam) (
		[]*imagesecModel.ImageDetectTask, int64, error)

	CreateDetectSubtask(ctx context.Context, data []*imagesecModel.ImageDetectSubTask) error
	UpdateDetectSubtask(ctx context.Context, param imagesecModel.UpdateTaskParam) error

	DeleteDetectTask(ctx context.Context, param imagesecModel.SearchTaskParam) error
	DeleteDetectSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) error

	SearchDetectSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) (
		[]*imagesecModel.ImageDetectSubTask, int64, error)

	GroupDetectSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) (
		imagesecModel.TaskStatusGroup, error)
}

type DetectTaskDao struct {
	db *databases.RDBInstance
}

func NewDetectTaskDao(db *databases.RDBInstance) *DetectTaskDao {
	return &DetectTaskDao{db: db}
}

type ImageDetectResultDal interface {
	SearchDetectResult(ctx context.Context, param imagesecModel.SearchDetectResultParam) ([]*imagesecModel.ImageDetectResult, error)
	CreateDetectResult(ctx context.Context, param imagesecModel.CreateDetectResultParam) error
	DeleteDetectResult(ctx context.Context, param imagesecModel.SearchDetectResultParam) error
	SearchDetectBrief(ctx context.Context, param imagesecModel.SearchDetectBriefParam) ([]*imagesecModel.ImageDetectBrief, error)
	CreateDetectBrief(ctx context.Context, data *imagesecModel.ImageDetectBrief) error
	DeleteDetectBrief(ctx context.Context, param imagesecModel.SearchDetectBriefParam) error
}

type ImageDetectResultDao struct {
	db        *databases.RDBInstance
	policyDal DetectPolicyDal
}

func NewImageDetectResultDao(db *databases.RDBInstance) *ImageDetectResultDao {
	policyDal := NewDetectPolicyDao(db)
	return &ImageDetectResultDao{db: db, policyDal: policyDal}
}

func (dal *ImageDetectResultDao) CreateDetectResult(ctx context.Context, param imagesecModel.CreateDetectResultParam) error {
	if err := param.Check(); err != nil {
		return err
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()

	mo := &imagesecModel.ImageDetectResult{DetectType: param.DetectType}
	tableName := mo.TableName()

	dbPre, createData, deleteData := make([]*imagesecModel.ImageDetectResult, 0), make([]*imagesecModel.ImageDetectResult, 0), make([]int64, 0)

	if err := dal.db.Get().WithContext(ctx).Table(tableName).Where("image_unique_id = ?", param.ImageUniqueID).Where("policy_id = ?", param.PolicyID).
		Find(&dbPre).Error; err != nil {
		return err
	}

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range param.Data {
			if dbPre[i].Same(param.Data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}
	// find need create
	for i := range param.Data {
		needCreate := true
		for j := range dbPre {
			if param.Data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, param.Data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Where("id IN  ? ", deleteData).
			Delete(&imagesecModel.ImageDetectResult{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}

	return nil
}

func (dal *ImageDetectResultDao) SearchDetectResult(ctx context.Context, param imagesecModel.SearchDetectResultParam) (
	[]*imagesecModel.ImageDetectResult, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	if err := param.Check(); err != nil {
		return nil, err
	}
	m := imagesecModel.ImageDetectResult{DetectType: param.DetectType}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName())
	if param.ImageUniqueID > 0 {
		db = db.Where("image_unique_id = ?", param.ImageUniqueID)
	}
	if len(param.PolicyIds) > 0 {
		db = db.Where("policy_id IN ?", param.PolicyIds)
	}
	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}
	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}
	db = model.AddFilter(db, param.Filter)
	res := make([]*imagesecModel.ImageDetectResult, 0)
	err := db.Find(&res).Error

	return res, err
}

func (dal *ImageDetectResultDao) SearchDetectBrief(ctx context.Context, param imagesecModel.SearchDetectBriefParam) (
	[]*imagesecModel.ImageDetectBrief, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	if err := param.Check(); err != nil {
		return nil, err
	}

	m := imagesecModel.ImageDetectBrief{}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName())
	if param.ImageUniqueID > 0 {
		db = db.Where("image_unique_id = ?", param.ImageUniqueID)
	}
	if param.NotPolicyID > 0 {
		db = db.Where("policy_id != ?", param.NotPolicyID)
	}
	if param.PolicyID > 0 {
		db = db.Where("policy_id = ?", param.PolicyID)
	}
	if len(param.PolicyIds) > 0 {
		db = db.Where("policy_id IN ?", param.PolicyIds)
	}

	if param.LastID > 0 {
		db = db.Where("id > ?", param.LastID)
	}
	db = model.AddFilter(db, param.Filter)

	res := make([]*imagesecModel.ImageDetectBrief, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	for i := range res {
		if param.NeedPolicy {
			res[i].Deserialize()
			if res[i].PolicyUniqueID == 0 { // 2.20版本才是以快照的方式存
				continue
			}
			snapshot, err := dal.policyDal.SearchDetectPolicySnapshot(ctx, imagesecModel.SearchSecurityPolicyParam{UniqueID: res[i].PolicyUniqueID})
			if err != nil {
				return nil, err
			}
			if len(snapshot) == 0 {
				logging.Get().Err(err).Str("module", "detect").Msg("SearchDetectPolicySnapshot")
				continue
			}
			sp := snapshot[0]
			res[i].Policy = &sp
		}
		res[i].Deserialize()
		res[i] = res[i].ChangePolicyName(ctx)
	}

	return res, nil
}

func (dal *ImageDetectResultDao) CreateDetectBrief(ctx context.Context, data *imagesecModel.ImageDetectBrief) error {
	data.Serialize()

	if err := data.Check(); err != nil {
		return err
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()

	mo := &imagesecModel.ImageDetectBrief{}
	tableName := mo.TableName()

	brief, err := dal.SearchDetectBrief(ctx, imagesecModel.SearchDetectBriefParam{
		ImageUniqueID: data.ImageUniqueID,
		PolicyID:      data.PolicyID,
	})

	if err != nil {
		return err
	}
	deleteData := make([]int64, 0)
	createData := make([]*imagesecModel.ImageDetectBrief, 0)
	if len(brief) > 0 && !data.Same(brief[0]) {
		deleteData = append(deleteData, brief[0].ID)
	}
	if len(brief) == 0 || !data.Same(brief[0]) {
		createData = append(createData, data)
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Where("id IN  ? ", deleteData).
			Delete(&imagesecModel.ImageDetectBrief{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}

	return nil
}

func (dal *ImageDetectResultDao) DeleteDetectResult(ctx context.Context, param imagesecModel.SearchDetectResultParam) error {

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	if err := param.Check(); err != nil {
		return err
	}
	m := imagesecModel.ImageDetectResult{DetectType: param.DetectType}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName())
	if param.ImageUniqueID > 0 {
		db = db.Where("image_unique_id = ?", param.ImageUniqueID)
	}
	if len(param.PolicyIds) > 0 {
		db = db.Where("policy_id IN ?", param.PolicyIds)
	}
	if param.PolicyID > 0 {
		db = db.Where("policy_id =  ?", param.PolicyID)
	}

	if len(param.Ids) > 0 {
		db = db.Where("id IN ?", param.Ids)
	}
	return db.Delete(&m).Error
}

func (dal *ImageDetectResultDao) DeleteDetectBrief(ctx context.Context, param imagesecModel.SearchDetectBriefParam) error {

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	if err := param.Check(); err != nil {
		return err
	}

	m := imagesecModel.ImageDetectBrief{}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName())
	if param.ImageUniqueID > 0 {
		db = db.Where("image_unique_id = ?", param.ImageUniqueID)
	}
	if param.NotPolicyID > 0 {
		db = db.Where("policy_id != ?", param.NotPolicyID)
	}
	if param.PolicyID > 0 {
		db = db.Where("policy_id = ?", param.PolicyID)
	}
	if len(param.Ids) > 0 {
		db = db.Where("id IN ?", param.Ids)
	}
	return db.Delete(&m).Error
}

func (dal *DetectTaskDao) DeleteDetectTask(ctx context.Context, param imagesecModel.SearchTaskParam) error {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	m := &imagesecModel.ImageDetectTask{}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName())

	if param.StartID > 0 {
		db = db.Where("id > ?", param.TaskID)
	}
	if param.TaskID > 0 {
		db = db.Where("id = ?", param.TaskID)
	}
	if len(param.TaskIds) > 0 {
		db = db.Where("id IN ?", param.TaskIds)
	}
	if param.ImageFromType != "" {
		db = db.Where("image_from_type = ?", param.ImageFromType)
	}
	if param.PolicyID > 0 {
		db = db.Where("policy_id = ?", param.PolicyID)
	}
	if param.Priority > 0 {
		db = db.Where("priority = ?", param.Priority)
	}
	if len(param.ScanSubtaskIds) > 0 {
		db = db.Where("scan_sub_task_id IN ?", param.ScanSubtaskIds)
	}
	return db.Delete(m).Error
}

func (dal *DetectTaskDao) DeleteDetectSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) error {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	m := &imagesecModel.ImageDetectSubTask{}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName())

	if param.StartID > 0 {
		db = db.Where("id > ?", param.TaskID)
	}
	if param.TaskID > 0 {
		db = db.Where("task_id = ?", param.TaskID)
	}
	if len(param.SubtaskIds) > 0 {
		db = db.Where("id IN ?", param.SubtaskIds)
	}
	if len(param.TaskIds) > 0 {
		db = db.Where("task_id IN ?", param.TaskIds)
	}
	if param.ImageUniqueID > 0 {
		db = db.Where("image_unique_id = ?", param.ImageUniqueID)
	}
	if param.TaskID > 0 {
		db = db.Where("id = ?", param.TaskID)
	}

	return db.Delete(m).Error
}

func (dal *DetectTaskDao) CreateDetectTask(ctx context.Context, data *imagesecModel.ImageDetectTask) error {
	data.Serialize()

	if err := data.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)

	defer cancelFunc()
	return dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).Create(data).Error
}

func (dal *DetectTaskDao) UpdateDetectTask(ctx context.Context, param imagesecModel.UpdateTaskParam) error {
	if err := param.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.ImageDetectTask).TableName())
	db = db.Where("id = ?", param.ID)
	if len(param.Updater) > 0 {
		return db.Updates(param.Updater).Error
	}
	return nil
}

func (dal *DetectTaskDao) SearchDetectTask(ctx context.Context, param imagesecModel.SearchTaskParam) (
	[]*imagesecModel.ImageDetectTask, int64, error) {

	param.Serialize()

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	m := imagesecModel.ImageDetectTask{}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName())
	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}
	if param.TaskID > 0 {
		db = db.Where("id = ?", param.TaskID)
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
	if len(param.ScanSubtaskIds) > 0 {
		db = db.Where("scan_sub_task_id IN ?", param.ScanSubtaskIds)
	}
	if len(param.ScanStatus) > 0 {
		db = db.Where("status IN ?", param.ScanStatus)
	}
	if len(param.NotScanStatus) > 0 {
		db = db.Where("status NOT IN ?", param.NotScanStatus)
	}

	var cnt int64

	if err := db.Count(&cnt).Error; err != nil {
		return nil, cnt, err
	}

	db = model.AddFilter(db, param.Filter)
	res := make([]*imagesecModel.ImageDetectTask, 0)
	err := db.Find(&res).Error
	return res, cnt, err
}

func (dal *DetectTaskDao) CreateDetectSubtask(ctx context.Context, data2 []*imagesecModel.ImageDetectSubTask) error {
	data := make([]*imagesecModel.ImageDetectSubTask, 0)
	for i := range data2 {
		data2[i].Serialize()
		if err := data2[i].Check(); err != nil {
			continue
		}
		data = append(data, data2[i])
	}
	if len(data) == 0 {
		return nil
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	m := &imagesecModel.ImageDetectSubTask{}
	err := dal.db.Get().WithContext(cancelCtx).Table(m.TableName()).CreateInBatches(data, consts.DefaultMaxLimit).Error
	return err
}

func (dal *DetectTaskDao) UpdateDetectSubtask(ctx context.Context, param imagesecModel.UpdateTaskParam) error {
	if err := param.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.ImageDetectSubTask).TableName())
	db = db.Where("id = ?", param.ID)
	if len(param.Updater) > 0 {
		return db.Updates(param.Updater).Error
	}
	return nil
}

func (dal *DetectTaskDao) SearchDetectSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) (
	[]*imagesecModel.ImageDetectSubTask, int64, error) {
	param.IsSearchSubtask = true
	param.Serialize()

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	m := imagesecModel.ImageDetectSubTask{}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName())
	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}
	if param.PolicyID > 0 {
		db = db.Where("policy_id = ?", param.PolicyID)
	}
	if param.ImageUniqueID > 0 {
		db = db.Where("image_unique_id = ?", param.ImageUniqueID)
	}
	if param.TaskID > 0 {
		db = db.Where("task_id = ?", param.TaskID)
	}
	if len(param.ScanStatus) > 0 {
		db = db.Where("status IN ?", param.ScanStatus)
	}
	if len(param.NotScanStatus) > 0 {
		db = db.Where("status NOT IN ?", param.NotScanStatus)
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

	var cnt int64

	if err := db.Count(&cnt).Error; err != nil {
		return nil, cnt, err
	}

	db = model.AddFilter(db, param.Filter)
	res := make([]*imagesecModel.ImageDetectSubTask, 0)
	err := db.Find(&res).Error
	if err != nil {
		return nil, 0, err
	}
	for i := range res {
		res[i].Deserialize()
	}
	return res, cnt, err
}

func (dal *DetectTaskDao) GroupDetectSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) (
	imagesecModel.TaskStatusGroup, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	type Group struct {
		Status int64
		Cnt    int64
	}
	ans := imagesecModel.TaskStatusGroup{}
	group := make([]Group, 0)
	m := &imagesecModel.ImageDetectSubTask{}

	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName()).Where("task_id = ?", param.TaskID)

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
