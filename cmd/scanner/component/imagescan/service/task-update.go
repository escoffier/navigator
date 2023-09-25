package service

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

// 持续更新的扫描任务
func (s *ScanTaskSrv) ContinueUpdateTaskAndSubtask(ctx context.Context) error {
	_ = s.UpdateTaskReady(ctx)
	_ = s.UpdateTaskFinished(ctx)
	_ = s.UpdateSubtaskTimeout(ctx)
	_ = s.UpdatePreSubtask(ctx)
	return nil
}

// 删除未完成的检测任务
func (s *ScanTaskSrv) DeleteDetectTask(ctc context.Context, subtaskIds []int64) error {
	param := imagesecModel.SearchTaskParam{
		Priority:       imagesecModel.DetectPriorityScan,
		ScanStatus:     []int64{imagesecModel.TaskStatusPending},
		ScanSubtaskIds: subtaskIds,
	}
	task, _, err := s.detectDal.SearchDetectTask(ctc, param)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("DeleteDetectSubtask")
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
		logging.Get().Err(err).Str("module", "imagescan").Msg("DeleteDetectSubtask")
		return err
	}
	if err := s.detectDal.DeleteDetectSubtask(ctc, imagesecModel.SearchTaskParam{TaskIds: taskIds}); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("DeleteDetectSubtask")
		return err
	}
	return nil
}

// 任务已完成
func (s *ScanTaskSrv) UpdateTaskFinished(ctx context.Context) error {

	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Msg("ContinueUpdateScanSubtask recover")
			}
		}()

		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				ScanStatusStr: []string{imagesecModel.TaskStatusInprogressStr},
				Filter:        model.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiledByID().SetSortAsc(),
			})

			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("UpdateTaskFinished SearchScanTask")
				ticker.Reset(time.Minute * 5)
				continue
			}
			finishedTask := 0
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
					logging.Get().Err(err).Str("module", "imagescan").Msg("ContinueUpdateScanTask GroupScanSubtask")
					ticker.Reset(time.Minute * 5)
					continue
				}

				if group.Failed+group.DetectFinished >= group.All {
					finishedTask++
					if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
						ID:      task.ID,
						Updater: updater,
						Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause),
					}); err != nil {
						logging.Get().Err(err).Str("module", "imagescan").Msg("ContinueUpdateScanTask UpdateScanTask")
						ticker.Reset(time.Minute * 5)
						continue
					}
				}
			}
			logging.Get().Info().Str("module", "imagescan").Int("checkedTaskCount", len(tasks)).
				Int("finishedTaskCount", finishedTask).Msg("UpdateTaskFinished succeed")
		}
	}()
	return nil
}

// 子任务已全部添加，可以开始调度
func (s *ScanTaskSrv) UpdateTaskReady(ctx context.Context) error {

	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Msg("UpdateTaskReady recover")
			}
		}()

		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C

			tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				ScanStatusStr: []string{imagesecModel.TaskStatusNotReadyStr},
				Filter:        model.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiledByID().SetSortAsc(),
			})

			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("UpdateTaskFinished SearchScanTask")
				ticker.Reset(time.Minute * 5)
				continue
			}
			readyTask := 0
			for i := range tasks {
				_, cnt1, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{TaskID: tasks[i].ID,
					Filter: model.EmptyFilter().SetLimit(1)})
				if err != nil {
					logging.Get().Err(err).Str("module", "imagescan").Msg("UpdateTaskReady SearchScanSubtask")
					continue
				}

				time.Sleep(time.Minute * 1)
				_, cnt2, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{TaskID: tasks[i].ID,
					Filter: model.EmptyFilter().SetLimit(1)})
				if err != nil {
					logging.Get().Err(err).Str("module", "imagescan").Msg("UpdateTaskReady SearchScanSubtask")
					continue
				}
				if cnt1 != cnt2 {
					logging.Get().Info().Str("module", "imagescan").Int64("task", tasks[i].ID).Msg("UpdateTaskReady not ready")
					continue
				}
				readyTask++
				updater := map[string]interface{}{
					"status":     imagesecModel.TaskStatusPending,
					"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
				}

				if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
					ID:      tasks[i].ID,
					Updater: updater,
					Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusPending),
				}); err != nil {
					logging.Get().Err(err).Str("module", "imagescan").Msg("UpdateTaskReady UpdateScanTask")
					ticker.Reset(time.Minute * 5)
					continue
				}
			}
			logging.Get().Info().Str("module", "imagescan").Int("readyTaskCount", readyTask).
				Int("checkedTaskCount", len(tasks)).Msg("UpdateTaskReady succeed")
		}
	}()
	return nil
}

// 任务已发送完成
func (s *ScanTaskSrv) UpdateTaskSendFinished(ctx context.Context) error {

	tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
		Where:  fmt.Sprintf("status < %d and status > %d", imagesecModel.TaskStatusSendFinished, imagesecModel.TaskStatusNotReady),
		Filter: model.EmptyFilter().SetLimit(consts.DefaultPerPage).SetSortFiledByID().SetSortDesc(),
	})

	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("UpdateTaskSendFinished SearchScanTask")
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
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", task.ID).Msg("UpdateTaskSendFinished GroupScanSubtask")
			return err
		}

		if group.Pending+group.NotReady == 0 {
			if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
				ID:      task.ID,
				Updater: updater,
				Where:   fmt.Sprintf("status < %d and status > %d", imagesecModel.TaskStatusSendFinished, imagesecModel.TaskStatusNotReady),
			}); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", task.ID).Msg("UpdateTaskSendFinished UpdateScanTask")
				return err
			}
		}
	}
	logging.Get().Info().Str("module", "imagescan").Int("tasks", len(tasks)).Msg("UpdateTaskSendFinished succeed")
	return nil
}

// 子任务扫描超时
func (s *ScanTaskSrv) UpdateSubtaskTimeout(ctx context.Context) error {

	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Msg("UpdateSubtaskTimeout recover")
			}
		}()

		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			scannerConfig, err := s.scanConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("ContinueUpdateScanSubtask GetScanImageConfig")
				ticker.Reset(time.Minute * 5)
				continue
			}
			imageScanConfig := scannerConfig.ImageScanConfig

			updater := map[string]interface{}{
				"status":      imagesecModel.TaskStatusFailed,
				"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusFailed),
				"finished_at": time.Now().UnixMilli(),
				"msg":         imagesecModel.TaskFailedReasonTimeout,
				"reason":      imagesecModel.TaskFailedReasonTimeout,
			}

			tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				ScanStatusStr: []string{imagesecModel.TaskStatusInprogressStr},
			})
			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("ContinueUpdateScanSubtask get scan task")
				ticker.Reset(time.Minute * 5)
				continue
			}
			timeoutSubtask := 0
			for _, task := range tasks {
				subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
					TaskID:          task.ID,
					IsSearchSubtask: true,
					ScanStatusStr:   []string{imagesecModel.TaskStatusInprogressStr},
				})

				if err != nil {
					logging.Get().Err(err).Str("module", "imagescan").Msg("UpdateSubtaskTimeout SearchScanSubtask")
					ticker.Reset(time.Minute * 5)
					continue
				}

				for j := range subtask {
					// 查询老集群的扫描情况,升级后删除这里代码即可
					go func() { s.PreTaskUpdateChan <- subtask[j] }()

					if subtask[j].StartedAt > 0 && (time.Now().UnixMilli()-subtask[j].StartedAt)/1000/60 > imageScanConfig.ScanTimeout {
						timeoutSubtask++
						if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
							ID:      subtask[j].ID,
							Updater: updater,
						}); err != nil {
							logging.Get().Err(err).Str("module", "imagescan").Msg("UpdateSubtaskTimeout UpdateScanSubtask")
							continue
						}
					}
				}
			}
			logging.Get().Info().Str("module", "imagescan").Int("checkedTask", len(tasks)).
				Int("timeoutSubtask", timeoutSubtask).Msg("UpdateSubtaskTimeout task finished")
		}
	}()
	return nil
}

// 任务暂停
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
		logging.Get().Err(err).Str("module", "imagescan").Msg("UpdateTaskPause")
		return scani18.UpdateScanTask(err)
	}
	go func() { _ = s.UpdateSubTaskPause(ctx, taskID) }()
	return nil
}

// 任务重新调度
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
		logging.Get().Err(err).Str("module", "imagescan").Msg("UpdateTaskPause")
		return scani18.UpdateScanTask(err)
	}
	go func() { _ = s.UpdateSubTaskPending(ctx, taskID) }()
	return nil
}

// 任务终止
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
		logging.Get().Err(err).Str("module", "imagescan").Msg("UpdateTaskTerminate")
		return scani18.UpdateScanTask(err)
	}
	go func() { _ = s.UpdateSubTaskTerminate(ctx, taskID) }()
	return nil
}

// 子任务暂停:未完成--->暂停
func (s *ScanTaskSrv) UpdateSubTaskPause(ctx context.Context, taskID int64) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	filter := model.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiledByID().SetSortAsc()

	var startId int64

	for {
		<-ticker.C

		updater := map[string]interface{}{
			"started_at": 0,
			"status":     imagesecModel.TaskStatusPause,
			"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPause),
		}

		subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			TaskID:  taskID,
			StartID: startId,
			Filter:  filter,
		})
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", taskID).Msg("UpdateSubTaskPause")
			continue
		}
		if len(subtask) == 0 {
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", taskID).Msg("UpdateSubTaskPause finished")
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
				logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", taskID).Msg("UpdateSubTaskPause")
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

	filter := model.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiledByID().SetSortAsc()

	var startId int64

	for {

		updater := map[string]interface{}{
			"started_at": 0,
			"status":     imagesecModel.TaskStatusPending,
			"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
		}

		<-ticker.C
		subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			TaskID:  taskID,
			StartID: startId,
			Filter:  filter,
		})
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", taskID).Msg("UpdateSubTaskPending")
			continue
		}
		if len(subtask) == 0 {
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", taskID).Msg("UpdateSubTaskPending finished")
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
				logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", taskID).Msg("UpdateSubTaskPending")
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

	filter := model.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiledByID().SetSortAsc()

	var startId int64

	for {
		<-ticker.C
		subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			TaskID:  taskID,
			StartID: startId,
			Filter:  filter,
		})
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", taskID).Msg("UpdateSubTaskTerminate")
			continue
		}
		if len(subtask) == 0 {
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", taskID).Msg("UpdateSubTaskTerminate finished")
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
				logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", taskID).Int64("subtaskID", subtask[i].ID).
					Msg("UpdateSubTaskTerminate")
				continue
			}
		}
		_ = s.DeleteDetectTask(ctx, subtaskIds)
	}
	return nil
}

// 病毒库，漏洞库等更新触发扫描
func (s *ScanTaskSrv) TrigCreateScanTask(ctx context.Context, trigType string) error {
	if !scannerUtils.MainCluster() {
		return nil
	}
	// 节点镜像
	nodeConfig, err := s.scanConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("configType", imagesecModel.ConfigTypeNodeScanImage).
			Msg("CreateCycleScanTaskByConfig GetScanImageConfig")
		return err
	}
	nodeImc := nodeConfig.ImageScanConfig

	nodeImageAdd := true
	if (trigType == imagesecModel.VulnDbUpdateTrigger && !nodeImc.VulnFlush) ||
		(trigType == imagesecModel.SensitiveUpdateTrigger && !nodeImc.SensitiveFlush) ||
		(trigType == imagesecModel.MalwareDataUpdateTrigger && !nodeImc.MalwareFlush) {
		nodeImageAdd = false
	}

	if nodeImageAdd {
		nodeParam := imagesecModel.ImageSearchApiParam{
			ImageFromType: imagesecModel.ImageFromNode,
			ClusterKey:    nodeConfig.ImageScanConfig.ScanCycle.ClusterKey,
		}
		nodeTaskInfo := imagesecModel.ImageScanTask{
			ImageFromType: imagesecModel.ImageFromNode,
			ScanType:      trigType,
			Status:        imagesecModel.TaskStatusPending,
		}
		if err := s.CreateImageScanTask(ctx, nodeParam, nodeTaskInfo); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msg("TrigCreateScanTask CreateImageScanTask")
			return err
		}
		logging.Get().Info().Str("module", "imagescan").Str("scanType", trigType).Msg("TrigCreateScanTask CreateImageScanTask succeed")
	}

	regConfig, err := s.scanConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeRegScanImage)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("configType", imagesecModel.ConfigTypeNodeScanImage).
			Msg("TrigCreateScanTask GetScanImageConfig")
		return err
	}
	regImc := regConfig.ImageScanConfig

	regImageAdd := true
	if (trigType == imagesecModel.VulnDbUpdateTrigger && !regImc.VulnFlush) ||
		(trigType == imagesecModel.SensitiveUpdateTrigger && !regImc.SensitiveFlush) ||
		(trigType == imagesecModel.MalwareDataUpdateTrigger && !regImc.MalwareFlush) {
		regImageAdd = false
	}

	if regImageAdd {
		repParam := imagesecModel.ImageSearchApiParam{
			ImageFromType: imagesecModel.ImageFromRegistry,
			RegIds:        nodeConfig.ImageScanConfig.ScanCycle.RegIds,
		}
		regTaskInfo := imagesecModel.ImageScanTask{
			ImageFromType: imagesecModel.ImageFromRegistry,
			ScanType:      trigType,
		}
		if err := s.CreateImageScanTask(ctx, repParam, regTaskInfo); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msg("TrigCreateScanTask CreateImageScanTask")
			return err
		}
		logging.Get().Info().Str("module", "imagescan").Str("scanType", trigType).
			Msg("TrigCreateScanTask CreateImageScanTask succeed")
	}
	return nil
}
