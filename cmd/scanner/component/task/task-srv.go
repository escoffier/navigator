package task

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"time"

	flow_conf "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/flow-conf"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type UpdateTaskInfo struct {
	Scope       int
	TriggerType int
	StrategyId  int64
	Operator    string
}

type TaskSrv struct {
	scannerGormDb *store.ScannerOrm
	registryDal   *store.RegistryDao
	scanConfigDal store.ScanConfigDalInterface
}

func NewTaskSrv() *TaskSrv {
	sg := store.GetScannerOrmDb()
	sw := store.GetScannerWrapperDb()
	r := store.NewRegistryDao(sw)
	s := store.NewScanConfigDao(store.GetScannerWrapperDb())
	return &TaskSrv{
		scannerGormDb: sg,
		registryDal:   r,
		scanConfigDal: s,
	}
}

func (t *TaskSrv) GenerateScanTask(ctx context.Context, imageIds []int64, info UpdateTaskInfo) error {
	if len(imageIds) == 0 {
		return fmt.Errorf("no image id")
	}

	strategyID := info.StrategyId
	if strategyID <= 0 {
		// get default policy
		strategies, _, err := t.scanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{IsDefault: consts.TrueString}, nil)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("generate scan task err")
			return err
		}
		if len(strategies) == 0 {
			return fmt.Errorf("not fond default stratege")
		}
		strategyID = strategies[0].ID
	}

	scannerGormDb := store.GetScannerOrmDb()
	// generate task
	tmpTask := model.Task{
		Operator:     info.Operator,
		ScopeType:    info.Scope,
		SubTaskCount: len(imageIds), // scan one image
		Trigger:      info.TriggerType,
		Status:       consts.Pending,
		FlowConf:     flow_conf.DefaultImageScanFlowName,
		PolicyId:     strategyID,
	}
	taskId, err := scannerGormDb.AddTask(ctx, tmpTask)
	if err != nil {
		return err
	}
	subtasks := make([]model.SubTask, 0)
	for i := range imageIds {
		// generate subtasks
		subtask := model.SubTask{
			TaskId:    taskId,
			ImageId:   imageIds[i],
			Status:    consts.ImageScanPending,
			HeartBeat: time.Now(),
		}
		subtasks = append(subtasks, subtask)
	}

	err = scannerGormDb.AddSubTask(ctx, subtasks)
	if err != nil {
		err2 := t.SetTaskFailed(taskId, fmt.Sprintf("add subtask err:%v", err))
		if err2 != nil {
			return err2
		}
		return err
	}

	return nil
}

func (t *TaskSrv) SetTaskFailed(id int64, msg string) error {
	dbTask := model.Task{
		ID:         id,
		Status:     consts.End,
		Result:     consts.ScanFail,
		Msg:        msg,
		FinishedAt: time.Now(),
	}
	p := store.SearchTaskParam{
		ExcludeStatus: t.GetTaskSuspendStatus(),
	}
	err := store.GetScannerOrmDb().UpdateTask(context.Background(), dbTask, p)
	if err != nil {
		return err
	}
	return nil
}

func (t *TaskSrv) GetPendingTasks(ctx context.Context, limit int64) ([]Task, error) {
	scannerGormDb := store.GetScannerOrmDb()
	search := store.SearchTaskParam{
		Statuses: []int8{consts.Pending},
	}

	filter := &model.Filter{
		Limit: limit,
	}
	tasks, _, err := scannerGormDb.GetTasks(ctx, search, filter)
	if err != nil {
		return nil, err
	}

	pendingTasks := make([]Task, 0)
	for _, v := range tasks {

		// get subtasks by task id
		subtasks, err := t.GetPendingSubTasksByTaskId(ctx, v.ID)
		if err != nil {
			return nil, err
		}

		// generate scan policy by db policy id
		st, err := t.GenerateScanTypeByPolicy(ctx, v.PolicyId)
		if err != nil {
			return nil, err
		}

		// scan scope: full-scan or single scan
		ss := ScanScope{
			Type:     v.ScopeType,
			SubTasks: subtasks,
		}

		tmpTask := Task{
			Id:       v.ID,
			FlowConf: v.FlowConf,
			Scope:    ss,
			ScanType: st,
			Status:   v.Status,
			Result:   v.Result,
		}
		pendingTasks = append(pendingTasks, tmpTask)
	}

	return pendingTasks, nil
}

func (t *TaskSrv) GetPendingSubTasksByTaskId(ctx context.Context, taskId int64) ([]SubTask, error) {
	scannerGormDb := store.GetScannerOrmDb()
	stSearch := store.SearchSubTaskParam{
		TaskIds:  []int64{taskId},
		Statuses: []int{consts.ImageScanPending},
	}
	subtasks, _, err := scannerGormDb.GetSubTasks(ctx, stSearch, nil)
	if err != nil {
		return nil, err
	}

	pendingSubTasks := make([]SubTask, 0)
	for _, v := range subtasks {
		imageId := v.ImageId
		// get image info
		i, err := scannerGormDb.GetImageInfo(ctx, imageId)
		if err != nil {
			return nil, err
		}
		// get registry info
		registries, _, err := t.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{Id: i.RegistryId}, nil)
		if err != nil {
			return nil, err
		}
		if len(registries) == 0 {
			return nil, fmt.Errorf("not found registry(id %v)", i.RegistryId)
		}
		r := &(registries[0])

		// logging.GetLogger().Debug().Interface("registryInfo", r).Msg("get registry info")

		subtaskImage := transImage(i)
		subtaskRegistry := transRegistry(r)
		ps := SubTask{
			Id:       v.ID,
			TaskId:   taskId,
			Image:    subtaskImage,
			Registry: subtaskRegistry,
		}
		pendingSubTasks = append(pendingSubTasks, ps)
	}

	return pendingSubTasks, nil
}

// SetTasksInProgress update tasks status and set task scanner id,
// notice: this function will set task scanner id to current scanner id which will be used for scanner fail over
func (t *TaskSrv) SetTasksInProgress(ids []int64) error {
	search := store.SearchTaskParam{
		Ids:      ids,
		Statuses: []int8{consts.Pending},
	}
	updateInfo := make(map[string]interface{})
	updateInfo["heart_beat"] = time.Now()
	updateInfo["status"] = consts.InProgress
	updateInfo["scanner_id"] = global.ScannerId
	err := store.GetScannerOrmDb().UpdateTasksInfo(context.Background(), search, updateInfo)
	if err != nil {
		return err
	}
	return nil
}

func (t *TaskSrv) ReScheduleTask(ids []int64) error {
	search := store.SearchTaskParam{
		Ids: ids,
	}
	updateInfo := make(map[string]interface{})
	updateInfo["heart_beat"] = time.Now()
	updateInfo["status"] = consts.Pending
	updateInfo["scanner_id"] = global.ScannerId
	err := store.GetScannerOrmDb().UpdateTasksInfo(context.Background(), search, updateInfo)
	if err != nil {
		return err
	}
	return nil
}

func (t *TaskSrv) SetTaskEnd(id int64) error {
	dbTask := model.Task{
		ID:         id,
		Status:     consts.End,
		FinishedAt: time.Now(),
	}
	p := store.SearchTaskParam{
		ExcludeStatus: t.GetTaskSuspendStatus(),
	}
	err := store.GetScannerOrmDb().UpdateTask(context.Background(), dbTask, p)
	if err != nil {
		logging.GetLogger().Err(err).Msg("set task end failed")
		return err
	}
	return nil
}

func (t *TaskSrv) UpdateTaskStartTime(id int64, curTime time.Time) error {
	dbTask := model.Task{
		ID:        id,
		StartedAt: curTime,
	}
	p := store.SearchTaskParam{
		ExcludeStatus: t.GetTaskSuspendStatus(),
	}
	err := store.GetScannerOrmDb().UpdateTask(context.Background(), dbTask, p)
	if err != nil {
		return err
	}
	return nil
}

func (t *TaskSrv) SetSubTaskFailed(id int64, msg string) error {
	dbTask := model.SubTask{
		ID:         id,
		Status:     consts.ImageScanFailed,
		FinishedAt: time.Now(),
		ErrMsg:     msg,
	}
	err := store.GetScannerOrmDb().UpdateSubTask(context.Background(), dbTask)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("update subtask db status to 'scan-failed' err")
		return err
	}
	return nil
}

func (t *TaskSrv) SetSubTaskSuccess(id int64) error {
	dbTask := model.SubTask{
		ID:         id,
		Status:     consts.ImageScanSuccess,
		FinishedAt: time.Now(),
	}
	err := store.GetScannerOrmDb().UpdateSubTask(context.Background(), dbTask)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("update subtask db status to 'scan-success' err")
		return err
	}
	return nil
}

func (t *TaskSrv) SetSubTaskInProgress(id int64) error {
	now := time.Now()
	dbTask := model.SubTask{
		ID:        id,
		Status:    consts.ImageScanInProgress,
		StartedAt: now,
		HeartBeat: now,
	}
	err := store.GetScannerOrmDb().UpdateSubTask(context.Background(), dbTask)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("update subtask db status to 'inprogress' err")
		return err
	}
	return nil
}

func (t *TaskSrv) GetProgressingTasks() ([]Task, error) {

	search := store.SearchTaskParam{
		Statuses: []int8{consts.InProgress},
	}
	checkTasks, _, err := store.GetScannerOrmDb().GetTasks(context.Background(), search, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("get progressing tasks err")
		return nil, err
	}

	res := make([]Task, 0)
	for _, v := range checkTasks {
		t := transTask(v)
		res = append(res, t)
	}
	return res, nil
}

func (t *TaskSrv) GetDefaultPolicyId(ctx context.Context) (int64, error) {
	p, _, err := t.scanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{IsDefault: consts.TrueString}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("get default scan policy err")
		return 0, err
	}

	if len(p) != 1 {
		logging.GetLogger().Error().Msg("default policy contain multi results")
		return 0, fmt.Errorf("default policy number not one: %v", len(p))
	}

	return p[0].ID, nil
}

func (t *TaskSrv) GenerateScanTypeByPolicy(ctx context.Context, policyId int64) (map[ScanType]ScanPolicy, error) {
	p, _, err := t.scanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{StrategyID: policyId}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Int64("policyId", policyId).Msg("get scan policy err")
		return nil, err
	}

	if len(p) != 1 {
		logging.GetLogger().Error().Int64("policyId", policyId).Msg("match multi policies")
		return nil, fmt.Errorf("get scan policy number not one: %v", len(p))
	}
	dbPolicy := p[0]
	scanPolicy := make(map[ScanType]ScanPolicy)
	if dbPolicy.MaliciousEnable {
		scanPolicy[ScanType(consts.ScanMalicious)] = MaliciousPolicy{}
	}
	if dbPolicy.VulEnable {
		scanPolicy[ScanType(consts.ScanVul)] = VulnPolicy{dbPolicy.SoftwareJson}
	}
	if dbPolicy.SensitiveEnable {
		scanPolicy[ScanType(consts.ScanSensitiveFile)] = SensitiveFilePolicy{CustomFileName: dbPolicy.SensitiveFileJson}
	}
	if dbPolicy.WebshellEnable {
		scanPolicy[ScanType(consts.ScanWebshell)] = WebshellPolicy{}
	}
	if dbPolicy.EnvsEnable {
		scanPolicy[ScanType(consts.ScanEnv)] = EnvPolicy{
			EnvName: dbPolicy.EnvsJson,
		}
	}
	if dbPolicy.OpenLicenseEnable {
		scanPolicy[ScanType(consts.ScanLicense)] = LicensePolicy{
			LicenseName: dbPolicy.OpenLicenseJson,
		}
	}

	return scanPolicy, nil
}

func (t *TaskSrv) GetTaskSuspendStatus() []int {
	s := []int{consts.Pause, consts.Terminate}
	return s
}

func (t *TaskSrv) GetTaskStatus(taskId int64) (int, error) {
	search := store.SearchTaskParam{
		Ids: []int64{taskId},
	}
	tasks, _, err := store.GetScannerOrmDb().GetTasks(context.Background(), search, nil)
	if err != nil {
		return 0, err
	}
	if len(tasks) != 1 {
		return 0, fmt.Errorf("task not match one:%v", len(tasks))
	}

	return tasks[0].Status, nil
}

func (t *TaskSrv) IsTaskSuspended(taskId int64) (bool, error) {
	status, err := t.GetTaskStatus(taskId)
	if err != nil {
		return false, err
	}
	ss := t.GetTaskSuspendStatus()
	for _, v := range ss {
		if status == v {
			return true, nil
		}
	}
	return false, nil
}

func (t *TaskSrv) FilterTasksInProgress(tasks []Task) ([]Task, error) {
	processTaskIds := make([]int64, 0)
	for _, v := range tasks {
		processTaskIds = append(processTaskIds, v.Id)
	}
	search := store.SearchTaskParam{
		Ids:      processTaskIds,
		Statuses: []int8{consts.InProgress},
	}
	ts, _, err := store.GetScannerOrmDb().GetTasks(context.Background(), search, nil)
	if err != nil {
		return nil, err
	}
	res := make([]Task, 0)
	for _, v := range ts {
		for _, m := range tasks {
			if v.ID == m.Id {
				res = append(res, m)
			}
		}
	}
	return res, nil
}

func (t *TaskSrv) UpdateTasksHeartBeat(ids []int64) error {
	search := store.SearchTaskParam{
		Ids:      ids,
		Statuses: []int8{consts.InProgress},
	}
	updateInfo := make(map[string]interface{})
	updateInfo["heart_beat"] = time.Now()
	err := store.GetScannerOrmDb().UpdateTasksInfo(context.Background(), search, updateInfo)
	if err != nil {
		return err
	}
	return nil
}

func (t *TaskSrv) UpdateSubTasksHeartBeat(ids []int64) error {
	search := store.SearchSubTaskParam{
		Ids:      ids,
		Statuses: []int{consts.ImageScanInProgress},
	}
	updateInfo := make(map[string]interface{})
	updateInfo["heart_beat"] = time.Now()
	err := store.GetScannerOrmDb().UpdateSubTasksInfo(context.Background(), search, updateInfo)
	if err != nil {
		return err
	}
	return nil
}

func (t *TaskSrv) GetProgressingSubTasks(taskIds []int64) ([]SubTask, error) {
	search := store.SearchSubTaskParam{
		TaskIds:  taskIds,
		Statuses: []int{consts.ImageScanInProgress},
	}
	sts, _, err := store.GetScannerOrmDb().GetSubTasks(context.Background(), search, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("get progressing tasks err")
		return nil, err
	}

	res := make([]SubTask, 0)
	for _, v := range sts {
		t := transSubTask(v)
		res = append(res, t)
	}
	return res, nil
}

func (t *TaskSrv) GetPendingSubTasks(taskIds []int64) ([]SubTask, error) {
	search := store.SearchSubTaskParam{
		TaskIds:  taskIds,
		Statuses: []int{consts.ImageScanPending},
	}
	sts, _, err := store.GetScannerOrmDb().GetSubTasks(context.Background(), search, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("get pending tasks err")
		return nil, err
	}

	res := make([]SubTask, 0)
	for _, v := range sts {
		t := transSubTask(v)
		res = append(res, t)
	}
	return res, nil
}

func transTask(dbTask model.Task) Task {
	t := Task{
		Id:        dbTask.ID,
		Status:    dbTask.Status,
		Result:    dbTask.Result,
		UpdateAt:  dbTask.UpdatedAt,
		CreateAt:  dbTask.CreatedAt,
		HeartBeat: dbTask.HeartBeat,
		ScannerId: dbTask.ScannerId,
	}
	return t
}

func transSubTask(dbSubTask model.SubTask) SubTask {
	t := SubTask{
		Id:        dbSubTask.ID,
		Status:    dbSubTask.Status,
		UpdatedAt: dbSubTask.UpdatedAt,
		CreateAt:  dbSubTask.CreatedAt,
		HeartBeat: dbSubTask.HeartBeat,
	}
	return t
}

func transImage(i *model.ImageList) ImageInfo {
	return ImageInfo{
		Id:       i.ID,
		RepoName: i.FullRepoName,
		Tag:      i.Tags,
	}
}

func transRegistry(r *model.Registry) RegistryInfo {
	return RegistryInfo{
		Id:       r.ID,
		Host:     r.Url,
		Username: r.Username,
		Password: r.PasswordString,
	}
}
