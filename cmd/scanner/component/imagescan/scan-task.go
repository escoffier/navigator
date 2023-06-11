package imagescan

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-i18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ScanTaskService interface {
	CreateImageScanTask(ctx context.Context, imageSearchParam imagesecModel.ImageListParam, taskInfo imagesecModel.ImageScanTask) error
	UpdateScanTaskStatus(ctx context.Context, taskID int64, status string) error
	SearchScanTask(ctx context.Context, param imagesecModel.SearchTaskParam) ([]*imagesecModel.ImageScanTask, int64, error)
	SearchScanSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) ([]*imagesecModel.ImageScanSubTask, int64, error)
	RescheduleScanSubtask(ctx context.Context, subtaskID int64) error
	AddScanTaskByConfig(ctx context.Context) error
	ContinueUpdateTaskAndSubtask(ctx context.Context) error
}

type ScanTaskSrv struct {
	taskDal          imagesecStore.ScanTaskDal
	detectDal        imagesecStore.DetectTaskDal
	imageSrv         types.ImageService
	scannerConfigDal imagesecStore.ScanImageConfigDal
}

func NewScanTaskSrv(
	taskDal imagesecStore.ScanTaskDal,
	detectDal imagesecStore.DetectTaskDal,
	imageSrv types.ImageService,
	scannerConfigDal imagesecStore.ScanImageConfigDal,
) *ScanTaskSrv {
	s := &ScanTaskSrv{
		taskDal:          taskDal,
		detectDal:        detectDal,
		imageSrv:         imageSrv,
		scannerConfigDal: scannerConfigDal,
	}
	return s
}

func (s *ScanTaskSrv) CreateImageScanTask(ctx context.Context, imageSearchParam imagesecModel.ImageListParam,
	taskInfo imagesecModel.ImageScanTask) error {
	imageSearchParam.Deserialize()
	if err := imageSearchParam.Check(); err != nil {
		return err
	}

	imageSearchParam.Filter = model.EmptyFilter().SetLimit(1)

	taskInfo.Status = imagesecModel.TaskStatusNotReady
	taskInfo.StatusStr = imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusNotReady)

	_, cnt, err := s.imageSrv.ListImageWithScanInfo(ctx, imageSearchParam)
	if err != nil {
		logging.Get().Err(err).Msg("CreateScanImageTask find image error")
		return scani18.SearchImage(err)
	}
	if cnt == 0 {
		return scani18.NotGetImage()
	}

	if err := s.taskDal.CreateScanTask(ctx, &taskInfo); err != nil {
		logging.Get().Err(err).Msg("CreateScanTask")
		return scani18.CreateScanTask(err)
	}

	// 加子任务
	go func(taskID int64) {
		_ = s.CreateSubtask(ctx, taskID, imageSearchParam)
	}(taskInfo.ID)
	return nil
}

func (s *ScanTaskSrv) UpdateScanTaskStatus(ctx context.Context, taskID int64, status string) error {
	if taskID <= 0 {
		return scani18.NotGetScanTaskID()
	}
	// 先查
	task, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{TaskID: taskID})
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Msg("UpdateScanTask")
		return scani18.UpdateScanTask(err)
	}
	if len(task) == 0 {
		return scani18.NotGetScanTask()
	}
	if task[0].Status == imagesecModel.TaskStatusNotReady {
		return i18.CreateI18BadReqErr("扫描任务创建中", "task not ready")
	}
	switch status {

	case imagesecModel.TaskStatusPauseStr:
		return s.UpdateTaskPause(ctx, taskID)
	case imagesecModel.TaskStatusTerminateStr:
		return s.UpdateTaskTerminate(ctx, taskID)
	case imagesecModel.TaskStatusPendingStr:
		return s.UpdateTaskPending(ctx, taskID)
	default:
		return i18.CreateI18BadReqErr("扫描任务已完成或已终止，不可更新",
			fmt.Sprintf("task:%d can not updater status:%s", taskID, status))
	}
}

func (s *ScanTaskSrv) SearchScanTask(ctx context.Context, param imagesecModel.SearchTaskParam) (
	[]*imagesecModel.ImageScanTask, int64, error) {
	tasks, cnt, err := s.taskDal.SearchScanTask(ctx, param)
	if err != nil {
		logging.Get().Err(err).Interface("param", param).Msg("SearchScanTask")
		return nil, 0, scani18.SearchScanTask(err)
	}
	for i := range tasks {
		group, err := s.taskDal.GroupScanSubtask(ctx, imagesecModel.SearchTaskParam{TaskID: tasks[i].ID})
		if err != nil {
			logging.Get().Err(err).Int64("TaskID", tasks[i].ID).Msg("GroupScanSubtask")
			return nil, 0, scani18.SearchScanTask(err)
		}

		tasks[i].TaskStatusGroup = group.ToTaskStatusGroupView()
	}

	return tasks, cnt, nil
}

func (s *ScanTaskSrv) SearchScanSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) (
	[]*imagesecModel.ImageScanSubTask, int64, error) {

	if param.TaskID <= 0 {
		return nil, 0, scani18.NotGetScanTaskID()
	}

	tasks, cnt, err := s.taskDal.SearchScanSubtask(ctx, param)
	if err != nil {
		logging.Get().Err(err).Interface("param", param).Msg("SearchScanTask")
		return nil, 0, scani18.SearchScanTask(err)
	}

	return tasks, cnt, nil
}

func (s *ScanTaskSrv) RescheduleScanSubtask(ctx context.Context, subtaskID int64) error {
	if subtaskID <= 0 {
		return scani18.NotGetScanSubtaskID()
	}
	subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{SubtaskID: subtaskID})
	if err != nil {
		logging.Get().Err(err).Int64("subtaskID", subtaskID).Msg("RescheduleScanSubtask SearchScanTask")
		return scani18.SearchScanSubtask(err)
	}
	if len(subtask) == 0 {
		return scani18.NotGetScanSubtask()
	}

	st := subtask[0]
	tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{TaskID: st.TaskID})
	if err != nil {
		logging.Get().Err(err).Int64("taskID", st.TaskID).Msg("RescheduleScanSubtask SearchScanTask")
		return scani18.SearchScanTask(err)
	}
	if len(tasks) == 0 {
		return scani18.NotGetScanTask()
	}
	tk := tasks[0]

	subtaskUpdater := map[string]interface{}{
		"status":      imagesecModel.TaskStatusPending,
		"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
		"finished_at": 0,
		"started_at":  0,
		"msg":         "",
		"reason":      0,
	}

	taskUpdater := map[string]interface{}{
		"status":      imagesecModel.TaskStatusPending,
		"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
		"finished_at": 0,
	}

	if tk.Status != imagesecModel.TaskStatusInprogress && tk.Status != imagesecModel.TaskStatusSendFinished {
		if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{ID: tk.ID, Updater: taskUpdater,
			Where: fmt.Sprintf("status !=%d", imagesecModel.TaskStatusInprogress)}); err != nil {
			logging.Get().Err(err).Int64("taskID", tk.ID).Msg("RescheduleScanSubtask UpdateScanTask")
			return scani18.UpdateScanTask(err)
		}
	}

	if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{ID: subtaskID, Updater: subtaskUpdater,
		Where: fmt.Sprintf("status !=%d", imagesecModel.TaskStatusPending),
	}); err != nil {
		logging.Get().Err(err).Int64("subtaskID", st.ID).Msg("RescheduleScanSubtask UpdateScanTask")
		return scani18.UpdateScanSubtask(err)
	}
	return nil

}

func (s *ScanTaskSrv) AddScanTaskByConfig(ctx context.Context) error {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Msg("AddScanTaskByConfig recover")
			}
		}()

		ticker := time.NewTicker(imagesecModel.ScanCycleCheckInternal)
		defer ticker.Stop()
		for {
			<-ticker.C
			config, err := s.scannerConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
			if err != nil {
				logging.Get().Err(err).Str("configType", imagesecModel.ConfigTypeNodeScanImage).
					Msg("AddScanTaskByConfig GetScanImageConfig")
				continue
			}

			add := config.NodeImageConfig.IsTimeToAddTask(imagesecModel.ScanCycleCheckInternal)
			logging.Get().Info().Bool("addScanTask", add).Msg("AddScanTaskByConfig")
			if !add {
				continue
			}
			param := imagesecModel.ImageListParam{
				ImageFromType: imagesecModel.ImageFromNode,
				ClusterKey:    config.NodeImageConfig.ScanCycle.ClusterKey,
			}
			if config.NodeImageConfig.ScanCycle.AllCluster {
				param.ClusterKey = make([]string, 0)
			}
			taskInfo := imagesecModel.ImageScanTask{
				ImageFromType: imagesecModel.ImageFromNode,
				ScanType:      imagesecModel.CycleTrigger,
				Status:        imagesecModel.TaskStatusPending,
			}
			if err := s.CreateImageScanTask(ctx, param, taskInfo); err != nil {
				logging.Get().Err(err).Msg("AddScanTaskByConfig CreateImageScanTask")
				continue
			}
			logging.Get().Info().Str("scanType", imagesecModel.CycleTrigger).Msg("AddScanTaskByConfig CreateImageScanTask succeed")
		}
	}()

	return nil
}

func (s *ScanTaskSrv) ContinueUpdateTaskAndSubtask(ctx context.Context) error {

	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Msg("ContinueUpdateScanSubtask recover")
			}
		}()

		ticker := time.NewTicker(time.Second * 30)
		defer ticker.Stop()
		for {
			<-ticker.C
			_ = s.UpdateTaskReady(ctx)
			// _ = s.UpdateTaskSendFinished(ctx)
			_ = s.UpdateTaskFinished(ctx)
			_ = s.UpdateSubtaskTimeout(ctx)
		}
	}()

	return nil
}

func (s *ScanTaskSrv) DeleteDetectTask(ctc context.Context, subtaskIds []int64) error {
	param := imagesecModel.SearchTaskParam{
		Priority:       imagesecModel.DetectPriorityScan,
		ScanStatus:     []int64{imagesecModel.TaskStatusPending},
		ScanSubtaskIds: subtaskIds,
	}
	task, _, err := s.detectDal.SearchDetectTask(ctc, param)
	if err != nil {
		logging.Get().Err(err).Msg("DeleteDetectTask")
		return err
	}
	taskIds := make([]int64, 0)
	for i := range task {
		taskIds = append(taskIds, task[i].ID)
	}
	if len(taskIds) == 0 {
		return nil
	}
	if err := s.detectDal.DeleteDetectTask(ctc, imagesecModel.SearchTaskParam{TaskIds: taskIds}); err != nil {
		logging.Get().Err(err).Msg("DeleteDetectTask")
		return err
	}
	if err := s.detectDal.DeleteDetectSubtask(ctc, imagesecModel.SearchTaskParam{TaskIds: taskIds}); err != nil {
		logging.Get().Err(err).Msg("DeleteDetectSubtask")
		return err
	}
	return nil
}

func (s *ScanTaskSrv) UpdateTaskFinished(ctx context.Context) error {

	tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
		Where:  fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause),
		Filter: model.EmptyFilter().SetLimit(consts.DefaultPerPage).SetSortFiledByID().SetSortAsc(),
	})

	if err != nil {
		logging.Get().Err(err).Msg("UpdateTaskFinished SearchScanTask")
		return err
	}
	for i := range tasks {
		task := tasks[i]
		updater := map[string]interface{}{
			"status":      imagesecModel.TaskStatusDetectFinished,
			"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusDetectFinished),
			"finished_at": time.Now().UnixMilli(),
		}

		// 检查所有 subtask 都已完成
		group, err := s.taskDal.GroupScanSubtask(ctx, imagesecModel.SearchTaskParam{TaskID: task.ID})
		if err != nil {
			logging.Get().Err(err).Msg("ContinueUpdateScanTask GroupScanSubtask")
			return err
		}

		if group.Failed+group.DetectFinished >= group.All {
			if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
				ID:      task.ID,
				Updater: updater,
				Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause),
			}); err != nil {
				logging.Get().Err(err).Msg("ContinueUpdateScanTask UpdateScanTask")
				return err
			}
		}
	}
	logging.Get().Info().Int("tasks", len(tasks)).Msg("UpdateTaskFinished succeed")
	return nil
}

func (s *ScanTaskSrv) UpdateTaskReady(ctx context.Context) error {

	tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
		ScanStatus: []int64{imagesecModel.TaskStatusNotReady},
		Filter:     model.EmptyFilter().SetLimit(consts.DefaultPerPage).SetSortFiledByID().SetSortAsc(),
	})

	if err != nil {
		logging.Get().Err(err).Msg("UpdateTaskFinished SearchScanTask")
		return err
	}

	for i := range tasks {
		_, cnt1, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{TaskID: tasks[i].ID,
			Filter: model.EmptyFilter().SetLimit(1)})
		if err != nil {
			logging.Get().Err(err).Msg("UpdateTaskReady SearchScanSubtask")
			continue
		}

		time.Sleep(time.Minute * 1)
		_, cnt2, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{TaskID: tasks[i].ID,
			Filter: model.EmptyFilter().SetLimit(1)})
		if err != nil {
			logging.Get().Err(err).Msg("UpdateTaskReady SearchScanSubtask")
			continue
		}
		if cnt1 != cnt2 {
			logging.Get().Info().Int64("task", tasks[i].ID).Msg("UpdateTaskReady not ready")
			continue
		}
		updater := map[string]interface{}{
			"status":     imagesecModel.TaskStatusPending,
			"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
		}

		if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
			ID:      tasks[i].ID,
			Updater: updater,
			Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusPending),
		}); err != nil {
			logging.Get().Err(err).Msg("UpdateTaskReady UpdateScanTask")
			return err
		}
		logging.Get().Info().Int64("task", tasks[i].ID).Msg("UpdateTaskReady succeed")
	}
	logging.Get().Info().Int("tasks", len(tasks)).Msg("UpdateTaskReady succeed")
	return nil
}

func (s *ScanTaskSrv) UpdateTaskSendFinished(ctx context.Context) error {

	tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
		Where:  fmt.Sprintf("status < %d and status > %d", imagesecModel.TaskStatusSendFinished, imagesecModel.TaskStatusNotReady),
		Filter: model.EmptyFilter().SetLimit(consts.DefaultPerPage).SetSortFiledByID().SetSortDesc(),
	})

	if err != nil {
		logging.Get().Err(err).Msg("UpdateTaskSendFinished SearchScanTask")
		return err
	}

	for i := range tasks {
		task := tasks[i]

		updater := map[string]interface{}{
			"status":     imagesecModel.TaskStatusSendFinished,
			"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusSendFinished),
		}

		// 检查所有 subtask 都已发送完成
		group, err := s.taskDal.GroupScanSubtask(ctx, imagesecModel.SearchTaskParam{TaskID: task.ID})
		if err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateTaskSendFinished GroupScanSubtask")
			return err
		}

		if group.Pending+group.NotReady == 0 {
			if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
				ID:      task.ID,
				Updater: updater,
				Where:   fmt.Sprintf("status < %d and status > %d", imagesecModel.TaskStatusSendFinished, imagesecModel.TaskStatusNotReady),
			}); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateTaskSendFinished UpdateScanTask")
				return err
			}
		}
	}
	logging.Get().Info().Int("tasks", len(tasks)).Msg("UpdateTaskSendFinished succeed")
	return nil
}

func (s *ScanTaskSrv) UpdateSubtaskTimeout(ctx context.Context) error {

	scannerConfig, err := s.scannerConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
	if err != nil {
		logging.Get().Err(err).Msg("ContinueUpdateScanSubtask GetScanImageConfig")
		return err
	}
	nodeImageConfig := scannerConfig.NodeImageConfig

	updater := map[string]interface{}{
		"status":      imagesecModel.TaskStatusFailed,
		"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusFailed),
		"finished_at": time.Now().UnixMilli(),
		"msg":         imagesecModel.TaskFailedReasonTimeout,
		"reason":      imagesecModel.TaskFailedReasonTimeout,
	}

	tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
		ScanStatus: []int64{imagesecModel.TaskStatusInprogress, imagesecModel.TaskStatusSendFinished, imagesecModel.TaskStatusScanFinished},
	})
	if err != nil {
		logging.Get().Err(err).Msg("ContinueUpdateScanSubtask get scan task")
		return err
	}

	for _, task := range tasks {
		subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			TaskID:        task.ID,
			NotScanStatus: []int64{imagesecModel.TaskStatusDetectFinished},
		})

		if err != nil {
			logging.Get().Err(err).Msg("UpdateSubtaskTimeout SearchScanSubtask")
			return err
		}

		for j := range subtask {
			if subtask[j].StartedAt > 0 && time.Now().UnixMilli()-subtask[j].StartedAt > nodeImageConfig.ScanTimeout*60*1000 {
				if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
					ID:      subtask[j].ID,
					Updater: updater,
				}); err != nil {
					logging.Get().Err(err).Msg("UpdateSubtaskTimeout UpdateScanSubtask")
					continue
				}
			}
		}
		logging.Get().Info().Int("subtask", len(subtask)).Int64("taskID", task.ID).Msg("UpdateSubtaskTimeout succeed")
	}
	logging.Get().Info().Int("tasks", len(tasks)).Msg("UpdateSubtaskTimeout succeed")
	return nil
}

func (s *ScanTaskSrv) UpdateTaskPause(ctx context.Context, taskID int64) error {
	updater := map[string]interface{}{
		"status":     imagesecModel.TaskStatusPause,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPause),
	}

	if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
		ID:      taskID,
		Updater: updater,
		Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause),
	}); err != nil {
		logging.Get().Err(err).Msg("UpdateTaskPause")
		return scani18.UpdateScanTask(err)
	}
	go func() { _ = s.UpdateSubTaskPause(ctx, taskID) }()
	return nil
}

func (s *ScanTaskSrv) UpdateTaskPending(ctx context.Context, taskID int64) error {
	updater := map[string]interface{}{
		"status":     imagesecModel.TaskStatusPending,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
	}

	if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
		ID:      taskID,
		Updater: updater,
		Where:   fmt.Sprintf("status = %d", imagesecModel.TaskStatusPause),
	}); err != nil {
		logging.Get().Err(err).Msg("UpdateTaskPause")
		return scani18.UpdateScanTask(err)
	}
	go func() { _ = s.UpdateSubTaskPending(ctx, taskID) }()
	return nil
}

func (s *ScanTaskSrv) UpdateTaskTerminate(ctx context.Context, taskID int64) error {
	updater := map[string]interface{}{
		"status":      imagesecModel.TaskStatusTerminate,
		"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusTerminate),
		"finished_at": time.Now().UnixMilli(),
	}

	if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
		ID:      taskID,
		Updater: updater,
		Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusTerminate),
	}); err != nil {
		logging.Get().Err(err).Msg("UpdateTaskTerminate")
		return scani18.UpdateScanTask(err)
	}
	go func() { _ = s.UpdateSubTaskTerminate(ctx, taskID) }()
	return nil
}

// 子任务暂停:未完成--->暂停
func (s *ScanTaskSrv) UpdateSubTaskPause(ctx context.Context, taskID int64) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	updater := map[string]interface{}{
		"started_at": 0,
		"status":     imagesecModel.TaskStatusPause,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPause),
	}

	filter := model.EmptyFilter().SetLimit(consts.DefaultLimit).SetSortFiledByID().SetSortAsc()

	var startId int64

	for {
		<-ticker.C
		subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			TaskID:  taskID,
			StartID: startId,
			Filter:  filter,
		})
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskPause")
			continue
		}
		if len(subtask) == 0 {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskPause finished")
			break
		}
		startId = subtask[len(subtask)-1].ID
		subtaskIds := make([]int64, 0)
		for i := range subtask {
			subtaskIds = append(subtaskIds, subtask[i].ID)
			if subtask[i].Status >= imagesecModel.TaskStatusTerminate {
				continue
			}

			if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
				ID:      subtask[i].ID,
				Updater: updater,
				Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause),
			}); err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskPause")
				continue
			}
		}
		// 删除检测任务
		_ = s.DeleteDetectTask(ctx, subtaskIds)

	}
	return nil
}

// 子任务重新扫描:暂停--->未扫描
func (s *ScanTaskSrv) UpdateSubTaskPending(ctx context.Context, taskID int64) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	updater := map[string]interface{}{
		"started_at": 0,
		"status":     imagesecModel.TaskStatusPending,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
	}

	filter := model.EmptyFilter().SetLimit(consts.DefaultLimit).SetSortFiledByID().SetSortAsc()

	var startId int64

	for {
		<-ticker.C
		subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			TaskID:  taskID,
			StartID: startId,
			Filter:  filter,
		})
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskPending")
			continue
		}
		if len(subtask) == 0 {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskPending finished")
			break
		}
		startId = subtask[len(subtask)-1].ID
		subtaskIds := make([]int64, 0)
		for i := range subtask {
			subtaskIds = append(subtaskIds, subtask[i].ID)
			if subtask[i].Status >= imagesecModel.TaskStatusTerminate {
				continue
			}

			if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
				ID:      subtask[i].ID,
				Updater: updater,
				Where:   fmt.Sprintf("status <= %d", imagesecModel.TaskStatusPause),
			}); err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskPending")
				continue
			}
		}
		_ = s.DeleteDetectTask(ctx, subtaskIds)
	}
	return nil
}

// 子任务终止:未完成--->失败
func (s *ScanTaskSrv) UpdateSubTaskTerminate(ctx context.Context, taskID int64) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	filter := model.EmptyFilter().SetLimit(consts.DefaultLimit).SetSortFiledByID().SetSortAsc()

	var startId int64

	for {
		<-ticker.C
		subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			TaskID:  taskID,
			StartID: startId,
			Filter:  filter,
		})
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskTerminate")
			continue
		}
		if len(subtask) == 0 {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskTerminate finished")
			break
		}
		startId = subtask[len(subtask)-1].ID
		subtaskIds := make([]int64, 0)
		for i := range subtask {
			subtaskIds = append(subtaskIds, subtask[i].ID)
			if subtask[i].Status >= imagesecModel.TaskStatusTerminate {
				continue
			}

			updater := map[string]interface{}{
				"status":     imagesecModel.TaskStatusFailed,
				"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusFailed),
				"reason":     imagesecModel.TaskFailedTerminated,
				"msg":        imagesecModel.TaskFailedTerminated,
			}
			if subtask[i].StartedAt > 0 {
				updater["finished_at"] = time.Now().UnixMilli()
			}

			if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
				ID:      subtask[i].ID,
				Updater: updater,
				Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusFailed),
			}); err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).Int64("subtaskID", subtask[i].ID).
					Msg("UpdateSubTaskTerminate")
				continue
			}
		}
		_ = s.DeleteDetectTask(ctx, subtaskIds)
	}
	return nil
}

func (s *ScanTaskSrv) CreateSubtask(ctx context.Context, taskID int64, imageSearchParam imagesecModel.ImageListParam) error {
	var startID int64
	for {
		imageSearchParam.StartID = startID
		imageSearchParam.Filter = model.EmptyFilter().SetLimit(consts.DefaultLimit).SetSortAsc().SetSortFiledByID()

		subtasks := make([]*imagesecModel.ImageScanSubTask, 0)
		images, _, err := s.imageSrv.ListImageWithScanInfo(ctx, imageSearchParam)
		if err != nil {
			logging.Get().Err(err).Msg("CreateScanImageTask find image")
			return err
		}
		if len(images) == 0 {
			break
		}
		startID = images[len(images)-1].ID

		for i := range images {
			subtasks = append(subtasks, &imagesecModel.ImageScanSubTask{
				TaskID:         taskID,
				ImageUniqueID:  images[i].UniqueID,
				NodeClusterKey: images[i].NodeClusterKey,
				NodeUniqueID:   images[i].NodeUniqueID,
				Status:         imagesecModel.TaskStatusPending,
				StatusStr:      imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
				ImageName:      images[i].GetImageName(),
				NodeHostname:   images[i].NodeHostname,
			})
		}
		if err := s.taskDal.CreateScanSubtask(ctx, subtasks); err != nil {
			logging.Get().Err(err).Msg("CreateScanSubtask")
			continue
		}
	}
	updater := map[string]interface{}{
		"status":     imagesecModel.TaskStatusPending,
		"status_str": imagesecModel.TaskStatusPendingStr,
	}

	if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
		ID:      taskID,
		Updater: updater,
	}); err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Msg("UpdateScanTask TaskStatusPendingStr")
		return err
	}

	return nil
}
