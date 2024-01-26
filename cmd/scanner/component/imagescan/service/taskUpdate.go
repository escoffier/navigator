package service

import (
	"context"
	"fmt"
	"time"

	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

// 持续更新的扫描任务
func (s *ScanTaskSrv) ContinueUpdateTaskAndSubtask(ctx context.Context) error {
	_ = s.UpdateTaskReady(ctx)
	_ = s.UpdateTaskFinished(ctx)
	_ = s.UpdateSubtaskTimeout(ctx)
	_ = s.MigratePreSubtask(ctx)
	return nil
}

// 删除未完成的检测任务
func (s *ScanTaskSrv) DeleteDetectTask(ctc context.Context, subtaskIds []int64) error {
	if len(subtaskIds) == 0 {
		return nil
	}
	param := imagesecModel.SearchTaskParam{
		Priority:       imagesecModel.DetectPriorityScan,
		ScanStatus:     []int64{imagesecModel.TaskStatusPending},
		ScanSubtaskIds: subtaskIds,
	}
	task, _, err := s.detectDal.SearchDetectTask(ctc, param)
	if err != nil {
		s.Log.Err(err).Msg("DeleteDetectSubtask")
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
		s.Log.Err(err).Msg("DeleteDetectSubtask")
		return err
	}
	if err := s.detectDal.DeleteDetectSubtask(ctc, imagesecModel.SearchTaskParam{TaskIds: taskIds}); err != nil {
		s.Log.Err(err).Msg("DeleteDetectSubtask")
		return err
	}
	return nil
}

// 任务已完成
func (s *ScanTaskSrv) UpdateTaskFinished(ctx context.Context) error {

	go func() {
		defer func() {
			if err := recover(); err != nil {
				s.Log.Error().Msg("ContinueUpdateScanSubtask recover")
			}
		}()

		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				// 如果一个任务中只有一个子任务，且这个子任务还是老版本，那子任务可能先调度
				ScanStatusStr: []string{imagesecModel.TaskStatusInprogressStr, imagesecModel.TaskStatusPendingStr},
				Filter:        imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiledByID().SetSortAsc(),
			})

			if err != nil {
				s.Log.Err(err).Msg("UpdateTaskFinished SearchScanTask")
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
					s.Log.Err(err).Msg("ContinueUpdateScanTask GroupScanSubtask")
					continue
				}

				if group.Failed+group.DetectFinished >= group.All {
					finishedTask++
					if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
						ID:      task.ID,
						Updater: updater,
						Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause),
					}); err != nil {
						s.Log.Err(err).Msg("ContinueUpdateScanTask UpdateScanTask")
						continue
					}
				}
			}
			s.Log.Info().Int("checkedTaskCount", len(tasks)).
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
				s.Log.Error().Msg("UpdateTaskReady recover")
			}
		}()

		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C

			tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				ScanStatusStr: []string{imagesecModel.TaskStatusNotReadyStr},
				Filter:        imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiledByID().SetSortAsc(),
			})

			if err != nil {
				s.Log.Err(err).Msg("UpdateTaskFinished SearchScanTask")
				continue
			}
			readyTask := 0
			for i := range tasks {
				_, cnt1, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{TaskID: tasks[i].ID,
					Filter: imagesecModel.EmptyFilter().SetLimit(1)})
				if err != nil {
					s.Log.Err(err).Msg("UpdateTaskReady SearchScanSubtask")
					continue
				}

				time.Sleep(time.Minute * 1)
				_, cnt2, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{TaskID: tasks[i].ID,
					Filter: imagesecModel.EmptyFilter().SetLimit(1)})
				if err != nil {
					s.Log.Err(err).Msg("UpdateTaskReady SearchScanSubtask")
					continue
				}
				if cnt1 != cnt2 {
					s.Log.Info().Int64("task", tasks[i].ID).Msg("UpdateTaskReady not ready")
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
					s.Log.Err(err).Msg("UpdateTaskReady UpdateScanTask")
					continue
				}
			}
			s.Log.Info().Int("readyTaskCount", readyTask).
				Int("checkedTaskCount", len(tasks)).Msg("UpdateTaskReady succeed")
		}
	}()
	return nil
}

// 任务已发送完成
func (s *ScanTaskSrv) UpdateTaskSendFinished(ctx context.Context) error {

	tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
		Where:  fmt.Sprintf("status < %d and status > %d", imagesecModel.TaskStatusSendFinished, imagesecModel.TaskStatusNotReady),
		Filter: imagesecModel.EmptyFilter().SetLimit(consts.DefaultPerPage).SetSortFiledByID().SetSortDesc(),
	})

	if err != nil {
		s.Log.Err(err).Msg("UpdateTaskSendFinished SearchScanTask")
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
			s.Log.Err(err).Int64("taskID", task.ID).Msg("UpdateTaskSendFinished GroupScanSubtask")
			return err
		}

		if group.Pending+group.NotReady == 0 {
			if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
				ID:      task.ID,
				Updater: updater,
				Where:   fmt.Sprintf("status < %d and status > %d", imagesecModel.TaskStatusSendFinished, imagesecModel.TaskStatusNotReady),
			}); err != nil {
				s.Log.Err(err).Int64("taskID", task.ID).Msg("UpdateTaskSendFinished UpdateScanTask")
				return err
			}
		}
	}
	s.Log.Info().Int("tasks", len(tasks)).Msg("UpdateTaskSendFinished succeed")
	return nil
}

// 子任务扫描超时
func (s *ScanTaskSrv) UpdateSubtaskTimeout(ctx context.Context) error {

	go func() {
		defer func() {
			if err := recover(); err != nil {
				s.Log.Error().Msg("UpdateSubtaskTimeout recover")
			}
		}()

		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			conf1, err := s.scanConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
			if err != nil {
				s.Log.Err(err).Msg("ContinueUpdateScanSubtask GetScanImageConfig")
				continue
			}
			nodeScanConfig := conf1.ImageScanConfig

			config2, err := s.scanConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeRegScanImage)
			if err != nil {
				s.Log.Err(err).Msg("ContinueUpdateScanSubtask GetScanImageConfig")
				continue
			}
			regScanConfig := config2.ImageScanConfig

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
				s.Log.Err(err).Msg("ContinueUpdateScanSubtask get scan task")
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
					s.Log.Err(err).Msg("UpdateSubtaskTimeout SearchScanSubtask")
					continue
				}
				imageFromType := task.ImageFromType

				for j := range subtask {
					sub := subtask[j]
					timeout := false
					if sub.StartedAt <= 0 {
						continue
					}
					su := (time.Now().UnixMilli() - subtask[j].StartedAt) / 1000 / 60
					if imageFromType == imagesecModel.ImageFromNode && su > nodeScanConfig.ScanTimeout {
						timeout = true
					}
					if imageFromType == imagesecModel.ImageFromRegistry && su > regScanConfig.ScanTimeout {
						timeout = true
					}

					if timeout {
						timeoutSubtask++
						if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
							ID:      subtask[j].ID,
							Updater: updater,
						}); err != nil {
							s.Log.Err(err).Msg("UpdateSubtaskTimeout UpdateScanSubtask")
							continue
						}
					}
				}
			}
			s.Log.Info().Int("checkedTask", len(tasks)).
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
		s.Log.Err(err).Msg("UpdateTaskPause")
		return scani18.UpdateScanTask(err)
	}
	go func() {
		_ = s.UpdateSubTaskPause(ctx, taskID)
		// 兼容老版本
		_ = s.AdaptTaskPause(ctx, taskID)
	}()
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
		s.Log.Err(err).Msg("UpdateTaskPause")
		return scani18.UpdateScanTask(err)
	}
	go func() {
		_ = s.UpdateSubTaskPending(ctx, taskID)
		// 兼容老版本
		_ = s.AdaptTaskPending(ctx, taskID)
	}()
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
		s.Log.Err(err).Msg("UpdateTaskTerminate")
		return scani18.UpdateScanTask(err)
	}
	go func() { _ = s.UpdateSubTaskTerminate(ctx, taskID) }()
	// 兼容老版本
	go func() { _ = s.AdaptTaskTerminate(ctx, taskID) }()

	return nil
}

// 子任务暂停:未完成--->暂停
func (s *ScanTaskSrv) UpdateSubTaskPause(ctx context.Context, taskID int64) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	filter := imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiledByID().SetSortAsc()

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
			s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskPause")
			continue
		}
		if len(subtask) == 0 {
			s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskPause finished")
			break
		}
		startId = subtask[len(subtask)-1].ID
		subtaskIds := make([]int64, 0)
		for i := range subtask {
			subtaskIds = append(subtaskIds, subtask[i].ID)
			if subtask[i].Status >= imagesecModel.TaskStatusTerminate {
				continue
			}
		}
		if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
			Ids:     subtaskIds,
			Updater: updater,
			Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause),
		}); err != nil {
			s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskPause")
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

	filter := imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiledByID().SetSortAsc()

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
			s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskPending")
			continue
		}
		if len(subtask) == 0 {
			s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskPending finished")
			break
		}
		startId = subtask[len(subtask)-1].ID
		subtaskIds := make([]int64, 0)

		for i := range subtask {
			subtaskIds = append(subtaskIds, subtask[i].ID)
			if subtask[i].Status >= imagesecModel.TaskStatusTerminate {
				continue
			}
		}

		if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
			Ids:     subtaskIds,
			Updater: updater,
			Where:   fmt.Sprintf("status <= %d", imagesecModel.TaskStatusPause),
		}); err != nil {
			s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskPending")
			continue
		}

		_ = s.DeleteDetectTask(ctx, subtaskIds)
	}
	return nil
}

// 子任务终止:未完成--->失败
func (s *ScanTaskSrv) UpdateSubTaskTerminate(ctx context.Context, taskID int64) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	filter := imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiledByID().SetSortAsc()

	var startId int64

	for {
		<-ticker.C
		subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			TaskID:  taskID,
			StartID: startId,
			Filter:  filter,
		})
		if err != nil {
			s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskTerminate")
			continue
		}
		if len(subtask) == 0 {
			s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskTerminate finished")
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
				s.Log.Err(err).Int64("taskID", taskID).Int64("subtaskID", subtask[i].ID).
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
		s.Log.Err(err).Str("configType", imagesecModel.ConfigTypeNodeScanImage).
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
		}
		nodeTaskInfo := imagesecModel.ImageScanTask{
			ImageFromType: imagesecModel.ImageFromNode,
			ScanType:      trigType,
			Status:        imagesecModel.TaskStatusPending,
		}
		if err := s.CreateImageScanTask(ctx, nodeParam, nodeTaskInfo); err != nil {
			s.Log.Err(err).Msg("TrigCreateScanTask CreateImageScanTask")
			return err
		}
		s.Log.Info().Str("scanType", trigType).Msg("TrigCreateScanTask CreateImageScanTask succeed")
	}

	regConfig, err := s.scanConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeRegScanImage)
	if err != nil {
		s.Log.Err(err).Str("configType", imagesecModel.ConfigTypeNodeScanImage).
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
			s.Log.Err(err).Msg("TrigCreateScanTask CreateImageScanTask")
			return err
		}
		s.Log.Info().Str("scanType", trigType).
			Msg("TrigCreateScanTask CreateImageScanTask succeed")
	}
	return nil
}
