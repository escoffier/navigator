package task

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	flowconf "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/flow-conf"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type UpdateTaskInfo struct {
	Scope        int    `json:"scope"`
	TriggerType  int    `json:"trigger_type"`
	StrategyID   int64  `json:"strategy_id"`
	StrategyName string `json:"strategyName"` // 扫描策略名字 用于openapi
	Operator     string `json:"operator"`
}

type TaskSrv struct { // nolint
	scannerGormDb *store.ScannerOrm
	registryDal   *store.RegistryDao
	scanConfigDal store.ScanConfigDal
	imageDal      store.ScannerDalInterface
}

func NewTaskSrv() *TaskSrv {
	sg := store.GetScannerOrmDb()
	sw := store.GetScannerWrapperDb()
	r := store.NewRegistryDao(sw)
	s := store.NewScanConfigDao(store.GetScannerWrapperDb())
	imageDal := store.NewScannerOrm(store.GetScannerWrapperDb())
	return &TaskSrv{
		scannerGormDb: sg,
		registryDal:   r,
		scanConfigDal: s,
		imageDal:      imageDal,
	}
}

func (t *TaskSrv) GenerateScanTask(ctx context.Context, imageIds []int64, info UpdateTaskInfo) error {
	logging.GetLogger().Info().Int("imageLength", len(imageIds)).Msg("GenerateScanTask")
	if len(imageIds) == 0 {
		return fmt.Errorf("not find image")
	}

	strategyID := info.StrategyID
	if strategyID <= 0 {
		// get default policy
		strategies, _, err := t.scanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{IsDefault: consts.TrueString}, nil)
		if err != nil {
			logging.GetLogger().Err(err).Msg("generate scan task err")
			return err
		}
		if len(strategies) == 0 {
			logging.GetLogger().Error().Msg("GenerateScanTask.not fond default strategy")
			return fmt.Errorf("not fond default strategy")
		}
		strategyID = strategies[0].ID
	}

	groupID := time.Now().UnixMilli()

	registries, _, err := t.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("GenerateScanTask SearchRegistry")
		return err
	}
	regMap := make(map[int64]model.Registry)
	taskMap := make(map[string]bool)
	subTaskMap := make(map[string][]model.SubTask)
	tasks := make([]model.Task, 0)
	for i := range registries {
		regMap[registries[i].ID] = registries[i]
	}

	scannerGormDb := store.GetScannerOrmDb()

	// 批量查询
	start := 0
	for start < len(imageIds) {
		end := start + consts.SubTaskBatchInsertCount
		if end > len(imageIds) {
			end = len(imageIds)
		}

		batch := imageIds[start:end]

		images, _, err := t.imageDal.SearchImage(ctx, store.SearchImageParam{
			InIds:             batch,
			OmitFields:        []string{"config_json", "manifest_v1_json", "manifest_v2_json"},
			NotParseNodeImage: true}, nil)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GenerateScanTask.SearchImage")
			return err
		}

		for i := range images {
			now := time.Now()
			// generate subtasks
			subtask := model.SubTask{
				ImageID:      images[i].ID,
				Status:       consts.ImageScanPending,
				HeartBeat:    &now,
				FullRepoName: images[i].FullRepoName,
				Tag:          images[i].Tags,
				Library:      images[i].Library,
			}
			reg, ok := regMap[images[i].RegistryID]
			if !ok {
				continue
			}
			if _, ok := subTaskMap[reg.ScannerInstance]; !ok {
				subTaskMap[reg.ScannerInstance] = make([]model.SubTask, 0)
			}
			subTaskMap[reg.ScannerInstance] = append(subTaskMap[reg.ScannerInstance], subtask)

			if !taskMap[reg.ScannerInstance] {
				tasks = append(tasks, model.Task{
					RegistryID:      reg.ID,
					Operator:        info.Operator,
					ScopeType:       info.Scope,
					Trigger:         info.TriggerType,
					Status:          consts.Pending,
					FlowConf:        flowconf.DefaultImageScanFlowName,
					PolicyId:        strategyID,
					GroupID:         groupID,
					ScannerInstance: reg.ScannerInstance,
				})
				taskMap[reg.ScannerInstance] = true
			}
		}
		start += consts.SubTaskBatchInsertCount
	}

	for i := range tasks {
		temTask, temSubtask := tasks[i], subTaskMap[tasks[i].ScannerInstance]
		if _, err := scannerGormDb.AddTaskAndSubTask(ctx, temTask, temSubtask); err != nil {
			logging.GetLogger().Err(err).Interface("task", temTask).Str("ScannerInstance", temTask.ScannerInstance).Int64("registryID", temTask.RegistryID).
				Int("subtasks", len(temSubtask)).Msg("AddTaskAndSubTask")
			continue
		}
		logging.GetLogger().Info().Interface("task", temTask).Str("ScannerInstance", temTask.ScannerInstance).Int64("registryID", temTask.RegistryID).
			Int("subtasks", len(temSubtask)).Msg("AddTaskAndSubTask")

		// 镜像扫描状态(等待中)
		for j := range temSubtask {
			if err := scannerGormDb.UpdateImageScanStatus(ctx, temSubtask[j].ImageID, model.FlagImageScanPending); err != nil {
				logging.GetLogger().Err(err).Int64("ImageId", temSubtask[j].ImageID).
					Int64("FlagImageScan", model.FlagImageScanPending).Msg("UpdateImageScanStatus")
			}
		}
	}
	logging.GetLogger().Info().Msg("GenerateScanTask complete")
	return nil
}

func (t *TaskSrv) SetTaskFailed(id int64, msg string) error {
	tmpTime := time.Now()
	dbTask := model.Task{
		ID:         id,
		Status:     consts.End,
		Result:     consts.ScanFail,
		Msg:        msg,
		FinishedAt: &tmpTime,
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

	pendingTasks := make([]Task, 0)
	scannerGormDb := store.GetScannerOrmDb()
	// 控制并发
	inp, _, err := t.imageDal.GetTaskList(ctx, store.SearchTaskParam{Statuses: []int8{consts.InProgress}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Str("ScannerInstance", global.ScannerInstance).Msg("GetPendingTasks.GetTaskList")
		return nil, err
	}

	maxTask, err := strconv.Atoi(os.Getenv("MAX_INPROGRESS_TASK_NUM"))
	if err != nil || maxTask <= 0 {
		maxTask = consts.DefaultMaxInProgressTask
	}

	if len(inp) > maxTask {
		logging.GetLogger().Info().Int("maxTask", maxTask).Int("InProgressCount", len(inp)).Msg("GetPendingTasks")
		return pendingTasks, nil
	}
	regs, _, err := t.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{ScannerInstance: global.ScannerInstance}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Str("ScannerInstance", global.ScannerInstance).Msg("GetPendingTasks.SearchRegistry")
		return nil, err
	}
	regIds := make([]int64, 0)
	for i := range regs {
		regIds = append(regIds, regs[i].ID)
	}
	if len(regIds) == 0 {
		logging.GetLogger().Info().Str("ScannerInstance", global.ScannerInstance).Msg("GetPendingTasks.not find registry")
		return []Task{}, nil
	}

	search := store.SearchTaskParam{
		RegIds:   regIds,
		Statuses: []int8{consts.Pending},
	}

	filter := &model.Filter{
		Limit: limit,
	}

	tasks, _, err := scannerGormDb.GetTaskList(ctx, search, filter)
	if err != nil {
		return nil, err
	}

	for _, v := range tasks {
		// get subtasks by task id
		subtasks, err := t.GetPendingSubTasksByTaskID(ctx, v.ID)
		if err != nil {
			// set task failed
			_ = t.SetTaskFailed(v.ID, fmt.Sprintf("get subtask err:%v", err))
			continue
		}
		if len(subtasks) == 0 {
			_ = t.SetTaskFailed(v.ID, "not found valid subtasks")
			continue
		}

		// generate scan policy by db policy id
		st, err := t.GenerateScanTypeByPolicy(ctx, v.PolicyId)
		if err != nil {
			// set task failed
			_ = t.SetTaskFailed(v.ID, fmt.Sprintf("get policy err:%v", err))
			continue
		}

		// scan scope: full-scan or single scan
		ss := ScanScope{
			Type:     v.ScopeType,
			SubTasks: subtasks,
		}

		tmpTask := Task{
			ID:       v.ID,
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

func (t *TaskSrv) GetPendingSubTasksByTaskID(ctx context.Context, taskID int64) ([]SubTask, error) {
	scannerGormDb := store.GetScannerOrmDb()
	stSearch := store.SearchSubTaskParam{
		TaskIds:  []int64{taskID},
		Statuses: []int{consts.ImageScanPending},
	}
	subtasks, _, err := scannerGormDb.GetSubTasks(ctx, stSearch, &model.Filter{SortFiled: "created_at", SortBy: consts.SortByDesc})
	if err != nil {
		logging.GetLogger().Err(err).
			Int64("taskId", taskID).
			Msg("get subtasks failed")
		return nil, err
	}

	pendingSubTasks := make([]SubTask, 0)
	for _, v := range subtasks {
		imageID := v.ImageID

		// get image info
		images, _, err := scannerGormDb.SearchImage(ctx, store.SearchImageParam{InIds: []int64{imageID}, NotParseNodeImage: true}, nil)
		if err != nil {
			// set subtask err
			_ = t.SetSubTaskFailed(v.ID, consts.ErrScanGetImage, fmt.Sprintf("get image info failed.%v", err))
			logging.GetLogger().Err(err).
				Int64("taskId", taskID).
				Int64("subtaskId", v.ID).
				Int64("imageId", imageID).
				Msg("get image info failed")
			continue
		}
		if len(images) == 0 {
			// set subtask err
			_ = t.SetSubTaskFailed(v.ID, consts.ErrScanImageRemoved, "image has been removed")
			logging.GetLogger().Error().
				Int64("taskId", taskID).
				Int64("subtaskId", v.ID).
				Int64("imageId", imageID).
				Msg("image has been removed")
			continue
		}

		// get registry info
		registries, _, err := t.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{ID: images[0].RegistryID, NoDelete: true}, nil)
		if err != nil {
			_ = t.SetSubTaskFailed(v.ID, consts.ErrScanGetRegistry, fmt.Sprintf("get registry info failed.registry id:%d,%v", images[0].RegistryID, err))
			logging.GetLogger().Err(err).
				Int64("taskId", taskID).
				Int64("subtaskId", v.ID).
				Int64("imageId", imageID).
				Int64("registryId", images[0].RegistryID).
				Msg("get registry info failed")
			continue
		}
		if len(registries) == 0 {
			_ = t.SetSubTaskFailed(v.ID, consts.ErrRegRemoved, fmt.Sprintf("registry has been removed id:%d,%v", images[0].RegistryID, err))
			logging.GetLogger().Error().
				Int64("taskId", taskID).
				Int64("subtaskId", v.ID).
				Int64("imageId", imageID).
				Int64("registryId", images[0].RegistryID).
				Msg("registry has been removed")
			continue
		}
		r := &(registries[0])

		subtaskImage := transImage(images[0])
		subtaskRegistry := transRegistry(r)
		ps := SubTask{
			ID:       v.ID,
			TaskID:   taskID,
			Image:    subtaskImage,
			Registry: subtaskRegistry,
			Status:   v.Status,
		}
		pendingSubTasks = append(pendingSubTasks, ps)
	}

	return pendingSubTasks, nil
}

// SetTasksInProgress update tasks status and set task scanner id,
// notice: this function will set task scanner id to current scanner id which will be used for scanner fail over
func (t *TaskSrv) SetTasksInProgress(ids []int64) error {
	search := store.SearchTaskParam{
		Ids: ids,
	}
	updateInfo := make(map[string]interface{})
	updateInfo["heart_beat"] = time.Now()
	updateInfo["status"] = consts.InProgress
	updateInfo["scanner_id"] = global.ScannerPodID
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
	updateInfo["scanner_id"] = ""
	err := store.GetScannerOrmDb().UpdateTasksInfo(context.Background(), search, updateInfo)
	if err != nil {
		return err
	}
	return nil
}

func (t *TaskSrv) SetTaskEnd(id int64) error {
	tmpTime := time.Now()
	dbTask := model.Task{
		ID:         id,
		Status:     consts.End,
		FinishedAt: &tmpTime,
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
		StartedAt: &curTime,
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

func (t *TaskSrv) SetSubTaskFailed(id int64, msgNo int, errDetail string) error {
	tmpTime := time.Now()

	updater := map[string]interface{}{
		"status":      consts.ImageScanFailed,
		"finished_at": &tmpTime,
		"err_msg":     errDetail,
		"err_no":      msgNo,
	}

	err := store.GetScannerOrmDb().UpdateSubTasksInfo(context.Background(), store.SearchSubTaskParam{Ids: []int64{id}}, updater)
	if err != nil {
		logging.GetLogger().Err(err).Msg("update subtask db status to 'scan-failed' err")
		return err
	}
	return nil
}

func (t *TaskSrv) SetSubTaskSuccess(id int64) error {
	tmpTime := time.Now()
	updater := map[string]interface{}{
		"status":      consts.ImageScanSuccess,
		"finished_at": &tmpTime,
		"err_msg":     "",
		"err_no":      0,
	}
	err := store.GetScannerOrmDb().UpdateSubTasksInfo(context.Background(), store.SearchSubTaskParam{Ids: []int64{id}}, updater)
	if err != nil {
		logging.GetLogger().Err(err).Msg("update subtask db status to 'scan-success' err")
		return err
	}
	return nil
}

func (t *TaskSrv) SetSubTaskInProgress(id int64) error {
	now := time.Now()

	updater := map[string]interface{}{
		"status":      consts.ImageScanInProgress,
		"finished_at": &now,
		"started_at":  &now,
		"heart_beat":  &now,
		"err_msg":     "",
		"err_no":      0,
	}

	err := store.GetScannerOrmDb().UpdateSubTasksInfo(context.Background(), store.SearchSubTaskParam{Ids: []int64{id}}, updater)

	if err != nil {
		logging.GetLogger().Err(err).Msg("update subtask db status to 'inprogress' err")
		return err
	}
	return nil
}

func (t *TaskSrv) GetProgressingTasks() ([]Task, error) {
	regs, _, err := t.registryDal.SearchRegistry(context.Background(), store.SearchRegistryParam{ScannerInstance: global.ScannerInstance, NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Str("ScannerInstance", global.ScannerInstance).Msg("GetPendingTasks.SearchRegistry")
		return nil, err
	}
	regIds := make([]int64, 0)
	for i := range regs {
		regIds = append(regIds, regs[i].ID)
	}
	if len(regIds) == 0 {
		logging.GetLogger().Info().Str("ScannerInstance", global.ScannerInstance).Msg("GetPendingTasks.not find registry")
		return []Task{}, nil
	}

	search := store.SearchTaskParam{
		RegIds:   regIds,
		Statuses: []int8{consts.InProgress},
	}
	checkTasks, _, err := store.GetScannerOrmDb().GetTaskList(context.Background(), search, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get progressing tasks err")
		return nil, err
	}

	res := make([]Task, 0)
	for _, v := range checkTasks {
		t := transTask(v)
		res = append(res, t)
	}
	return res, nil
}

func (t *TaskSrv) GetDefaultPolicyID(ctx context.Context) (int64, error) {
	p, _, err := t.scanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{IsDefault: consts.TrueString}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get default scan policy err")
		return 0, err
	}

	if len(p) != 1 {
		logging.GetLogger().Error().Msg("default policy contain multi results")
		return 0, fmt.Errorf("default policy number not one: %v", len(p))
	}

	return p[0].ID, nil
}

func (t *TaskSrv) GenerateScanTypeByPolicy(ctx context.Context, policyID int64) (map[ScanType]ScanPolicy, error) {
	p, _, err := t.scanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{StrategyID: policyID}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Int64("policyId", policyID).Msg("get scan policy err")
		return nil, err
	}

	if len(p) != 1 {
		logging.GetLogger().Error().Int64("policyId", policyID).Msg("match multi policies")
		return nil, fmt.Errorf("get scan policy number not one: %v", len(p))
	}
	dbPolicy := p[0]
	scanPolicy := make(map[ScanType]ScanPolicy)
	if dbPolicy.MaliciousEnable {
		scanPolicy[ScanType(consts.ScanMalicious)] = MaliciousPolicy{}
	}
	if dbPolicy.VulEnable {
		scanPolicy[ScanType(consts.ScanVul)] = VulnPolicy{Pkgs: dbPolicy.SoftwareJson, Licenses: dbPolicy.OpenLicenseJson}
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

func (t *TaskSrv) GetTaskStatus(taskID int64) (int, error) {
	search := store.SearchTaskParam{
		Ids: []int64{taskID},
	}
	tasks, _, err := store.GetScannerOrmDb().GetTaskList(context.Background(), search, nil)
	if err != nil {
		return 0, err
	}
	if len(tasks) != 1 {
		return 0, fmt.Errorf("task not match one:%v", len(tasks))
	}

	return tasks[0].Status, nil
}

func (t *TaskSrv) IsTaskSuspended(taskID int64) (bool, error) {
	status, err := t.GetTaskStatus(taskID)
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
		processTaskIds = append(processTaskIds, v.ID)
	}
	search := store.SearchTaskParam{
		Ids:      processTaskIds,
		Statuses: []int8{consts.InProgress},
	}
	ts, _, err := store.GetScannerOrmDb().GetTaskList(context.Background(), search, nil)
	if err != nil {
		return nil, err
	}
	res := make([]Task, 0)
	for _, v := range ts {
		for _, m := range tasks {
			if v.ID == m.ID {
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
		TaskIds:            taskIds,
		Statuses:           []int{consts.ImageScanInProgress},
		LessThanRetryCount: consts.SubTaskMaxRetryCount,
	}
	sts, _, err := store.GetScannerOrmDb().GetSubTasks(context.Background(), search, &model.Filter{SortFiled: "created_at", SortBy: consts.SortByDesc})
	if err != nil {
		logging.GetLogger().Err(err).Msg("get progressing tasks err")
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
	sts, _, err := store.GetScannerOrmDb().GetSubTasks(context.Background(), search, &model.Filter{SortFiled: "created_at", SortBy: consts.SortByDesc})
	if err != nil {
		logging.GetLogger().Err(err).Msg("get pending tasks err")
		return nil, err
	}

	res := make([]SubTask, 0)
	for _, v := range sts {
		t := transSubTask(v)
		res = append(res, t)
	}
	return res, nil
}

func (t *TaskSrv) AddSubTaskRetryCount(subTasks []SubTask) error {
	if len(subTasks) == 0 {
		return nil
	}
	ids := make([]int64, 0)
	for _, v := range subTasks {
		ids = append(ids, v.ID)
	}
	if err := store.GetScannerOrmDb().AddSubTasksRetryCount(context.Background(), ids); err != nil {
		return err
	}
	tasks, _, err := store.GetScannerOrmDb().GetSubTasks(context.Background(), store.SearchSubTaskParam{Ids: ids}, &model.Filter{SortFiled: "created_at", SortBy: consts.SortByDesc})
	if err != nil {
		return err
	}
	moreThanIds := make([]int64, 0)
	for i := range tasks {
		if tasks[i].RetryCount >= consts.SubTaskMaxRetryCount {
			moreThanIds = append(moreThanIds, tasks[i].ID)
		}
	}
	if len(moreThanIds) > 0 {
		// 超过重试次数的，不再重试，扫描状态设置成失败
		updateInfo := make(map[string]interface{})
		updateInfo["heart_beat"] = time.Now()
		updateInfo["status"] = consts.ImageScanFailed
		updateInfo["err_msg"] = "超过重试次数"
		updateInfo["err_no"] = consts.ErrExceededRetryCount
		if err := store.GetScannerOrmDb().UpdateSubTasksInfo(context.Background(), store.SearchSubTaskParam{Ids: moreThanIds}, updateInfo); err != nil {
			return err
		}
	}

	return nil
}

func (t *TaskSrv) ReScheduleSubTask(subTasks []SubTask) error {
	ids := make([]int64, 0)
	for _, v := range subTasks {
		ids = append(ids, v.ID)
	}
	search := store.SearchSubTaskParam{
		Ids: ids,
	}

	updateInfo := make(map[string]interface{})
	updateInfo["heart_beat"] = time.Now()
	updateInfo["status"] = consts.ImageScanPending
	err := store.GetScannerOrmDb().UpdateSubTasksInfo(context.Background(), search, updateInfo)
	if err != nil {
		return err
	}
	return nil
}

func transTask(dbTask model.Task) Task {
	t := Task{
		ID:        dbTask.ID,
		Status:    dbTask.Status,
		Result:    dbTask.Result,
		UpdateAt:  dbTask.UpdatedAt,
		CreateAt:  dbTask.CreatedAt,
		HeartBeat: dbTask.HeartBeat,
		ScannerID: dbTask.ScannerId,
	}
	return t
}

func transSubTask(dbSubTask model.SubTask) SubTask {
	t := SubTask{
		ID:        dbSubTask.ID,
		Status:    dbSubTask.Status,
		UpdatedAt: dbSubTask.UpdatedAt,
		CreateAt:  dbSubTask.CreatedAt,
		HeartBeat: dbSubTask.HeartBeat,
	}
	return t
}

func transImage(i model.ImageList) ImageInfo {
	return ImageInfo{
		ID:       i.ID,
		RepoName: i.FullRepoName,
		Tag:      i.Tags,
	}
}

func transRegistry(r *model.Registry) RegistryInfo {
	return RegistryInfo{
		ID:       r.ID,
		Host:     r.Url,
		Username: r.Username,
		Password: r.PasswordString,
	}
}
