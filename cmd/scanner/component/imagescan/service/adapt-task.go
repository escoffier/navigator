package service

import (
	"context"
	"fmt"
	"time"

	ver210 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/dataMigrate/220"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts/preConsts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 兼容2.19版本
func (s *ScanTaskSrv) AdaptCreateSubtask(ctx context.Context, images []*imagesecModel.ImageBaseResponse,
	subtask []*imagesecModel.ImageScanSubTask) error {

	if len(images) != len(subtask) {
		s.Log.Error().Msg("AdaptPreScan image not equal subtask")
		return fmt.Errorf("image not equal subtask")
	}
	adaptCnt := 0

	strategy, err := s.preImageDal.SearchDefaultStrategy(ctx)
	if err != nil {
		s.Log.Err(err).Msg("AdaptPreScan not find default strategy")
		return err
	}

	for i := range images {
		image := images[i]
		sub := subtask[i]
		if util.ThanVersion(image.ScanInsVer, consts.ScannerVersion220) || image.ImageFromType != imagesecModel.ImageFromRegistry {
			continue
		}
		adaptCnt++

		task := &model.Task{
			ID:               sub.ID,
			ScopeType:        preConsts.FullScan,
			Trigger:          preConsts.ManualTrigger,
			FlowConf:         "defaultImageScanFlow",
			Status:           preConsts.Pending,
			Operator:         "AdaptCreateSubtask",
			PolicyId:         strategy.ID,
			GroupID:          time.Now().UnixMilli(),
			RegistryID:       image.RegistryID,
			ScannerInstance:  image.ScanInstance,
			ScanStrategyName: strategy.Name,
		}

		iml := &model.ImageList{
			ID:            image.ID,
			FullRepoName:  image.FullRepoName,
			Tags:          image.Tag,
			Digest:        image.Digest,
			RegistryID:    image.RegistryID,
			FirstPushTime: time.Now(), // 无用的数据，但是不赋值，会写入失败
			LastPullTime:  time.Now(),
			LastPushTime:  time.Now(),
			Status:        consts.ImageStatusImageForScanTask,
		}
		iml2 := imagesecModel.Image{
			ImageFromType: imagesecModel.ImageFromRegistry,
			Repo:          image.FullRepoName,
			Tag:           image.Tag,
			RegID:         image.RegistryID,
		}
		iml.UniqueImage = iml2.GenUniqueID() // 必须要有这一步

		su := &model.SubTask{
			ID:           sub.ID,
			TaskID:       sub.ID,
			ImageID:      image.ID,
			Status:       preConsts.ImageScanPending,
			RegID:        task.RegistryID,
			FullRepoName: iml.FullRepoName,
			Tag:          iml.Tags,
			Library:      iml.Library,
		}

		_ = s.preImageDal.DeletePreImage(ctx, iml)
		// 数据可能已以数据库中，所以不关心错误
		_ = s.preImageDal.CreatePreImage(ctx, iml)

		_ = s.preTaskDal.DeleteScanTask(ctx, sub.ID)
		if err := s.preTaskDal.CreateScanTask(ctx, task); err != nil {
			s.Log.Err(err).Str("imageName", image.GetImageName()).
				Int64("subtaskID", sub.ID).Msg("AdaptPreScan create pre ScanTask")
			continue
		}

		// 等到subtask创建好了，创建 task,防止 task 调度时subtask 没有创建好
		_ = s.preTaskDal.DeleteScanSubtask(ctx, sub.ID)
		if err := s.preTaskDal.CreateScanSubtask(ctx, su); err != nil {
			s.Log.Err(err).Str("imageName", image.GetImageName()).
				Int64("subtaskID", sub.ID).Msg("AdaptPreScan Create pre ScanSubtask")
			continue
		}

		s.Log.Info().Int64("subtaskID", sub.ID).Int64("taskID", sub.TaskID).Int64("imageID", image.ID).
			Msg("AdaptPreScan create task and subtask")
	}

	s.Log.Info().Int("preSubtaskCnt", adaptCnt).Msg("AdaptPreScan task and subtask finished")
	return nil
}

// 持续查询已完成或失败的任务
// 兼容老版本
func (s *ScanTaskSrv) MigratePreSubtask(ctx context.Context) error {

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Msg("AdaptPreScan recover panic")
			}
		}()

		ticker := time.NewTicker(time.Second * 10)
		defer ticker.Stop()
		for {

			<-ticker.C

			tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				ScanStatusStr: []string{imagesecModel.TaskStatusInprogressStr},
			})
			if err != nil {
				s.Log.Err(err).Msg("AdaptPreScan get scan task")
				time.Sleep(time.Minute * 5)
				continue
			}

			if len(tasks) == 0 {
				time.Sleep(time.Minute)
				continue
			}
			for _, task := range tasks {
				if task.ImageFromType != imagesecModel.ImageFromRegistry {
					continue
				}

				subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
					TaskID:          task.ID,
					IsSearchSubtask: true,
					ScanStatusStr:   []string{imagesecModel.TaskStatusInprogressStr},
				})

				if err != nil {
					s.Log.Err(err).Msg("UpdateSubtaskTimeout SearchScanSubtask")
					time.Sleep(time.Minute * 5)
					continue
				}
				for j := range subtask {
					sub := subtask[j]
					subtaskID := sub.ID
					if util.ThanVersion(sub.ScanInsVer, consts.ScannerVersion220) {
						continue
					}

					s.Log.Info().Int64("subtaskID", sub.ID).Int64("taskID", sub.TaskID).Msg("AdaptPreScan get low version subtask")

					preSub, err := s.preTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{SubtaskID: subtaskID})
					if err != nil {
						s.Log.Err(err).Msg("AdaptPreScan SearchScanSubtask")
						continue
					}
					if len(preSub) == 0 {
						s.Log.Info().Int64("subtaskID", subtaskID).Msg("AdaptPreScan not find pre subtask")
						continue
					}

					su := preSub[0]
					switch su.Status {
					case preConsts.ImageScanSuccess:
						_ = s.updateSuccess(ctx, su)
					case preConsts.ImageScanFailed:
						_ = s.updateFailed(ctx, su)
					default:
						s.Log.Info().Int64("taskID", sub.TaskID).Int64("subtaskID", sub.ID).
							Str("ImageName", sub.ImageName).Uint8("status", su.Status).Msg("AdaptPreScan subtask not finished waite next")
					}
				}
			}
		}
	}()

	// 子集群和主集群的调度顺序不一致
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Msg("AdaptPreScan recover panic")
			}
		}()

		ticker := time.NewTicker(time.Second * 10)
		defer ticker.Stop()
		for {
			<-ticker.C
			subtask, err := s.preTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{ScanStatus: []int64{preConsts.ImageScanSuccess, preConsts.ImageScanFailed}})
			if err != nil {
				s.Log.Err(err).Msg("AdaptPreScan get scan task")
				time.Sleep(time.Minute * 1)
				continue
			}

			s.Log.Info().Int("subtask", len(subtask)).Msg("AdaptPreScan find success or failed subtask")

			if len(subtask) == 0 {
				time.Sleep(time.Minute)
				continue
			}
			time.Sleep(time.Second * 10)
			for i := range subtask {
				su := subtask[i]
				switch su.Status {
				case preConsts.ImageScanSuccess:
					_ = s.updateSuccess(ctx, su)
				case preConsts.ImageScanFailed:
					_ = s.updateFailed(ctx, su)
				}
			}
		}
	}()

	return nil
}

func (s *ScanTaskSrv) updateSuccess(ctx context.Context, preSub *model.SubTask) error {

	/*
		这个方法中，taskID,subtaskID 很容易出错，要特别小心
	*/
	s.Log.Info().Int64("subtaskID", preSub.ID).Str("ImageName", preSub.FullRepoName+":"+preSub.Tag).
		Msg("AdaptPreScan low version subtask scan success")

	// 新老版本的扫描器的调度不一致
	// 当前任务已
	subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{SubtaskID: preSub.ID})
	if err != nil {
		s.Log.Err(err).Msg("AdaptPreSubtask SearchScanSubtask")
		return err
	}
	if len(subtask) == 0 {
		return nil
	}

	tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{TaskID: subtask[0].TaskID})
	if err != nil {
		s.Log.Err(err).Msg("AdaptPreSubtask SearchScanSubtask")
		return err
	}
	if len(tasks) == 0 || tasks[0].Status >= imagesecModel.TaskStatusPause {
		s.Log.Info().Str("status", tasks[0].StatusStr).Msg("AdaptPreSubtask task")
		return nil
	}
	newSubtask, newTask := subtask[0], tasks[0]

	if newSubtask.Reason == imagesecModel.TaskFailedReasonTimeout {
		config, err := s.scanConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeRegScanImage)
		if err != nil {
			s.Log.Err(err).Msg("AdaptPreSubtask  SearchImageConfig")
			return err
		}
		if (config.ImageScanConfig.ScanTimeout)*60 > preSub.FinishedAt.Unix()-preSub.StartedAt.Unix() {
			_ = s.deleteAdaptedPreScanTask(ctx, preSub.ID)
			return nil
		}
		taskUpdater := map[string]interface{}{
			"status":      imagesecModel.TaskStatusInprogress,
			"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusInprogress),
			"finished_at": 0,
		}
		// 更新主任务执行
		if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
			ID:      newTask.ID,
			Updater: taskUpdater,
		}); err != nil {
			s.Log.Err(err).Msg("AdaptPreSubtask  UpdateScanTask")
			return err
		}
		// 更新子任务
		if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
			ID:      newSubtask.ID,
			Updater: taskUpdater,
		}); err != nil {
			s.Log.Err(err).Msg("AdaptPreSubtask  UpdateScanTask")
			return err
		}
	}

	// 如果一个任务中只有一个子任务，且这个子任务还是老版本，那子任务可能先调度,这时就会出现一个情况，子任务已经在执行，但是主任务还是等待中
	// 更新任务执行中
	taskUpdater := map[string]interface{}{
		"status":     imagesecModel.TaskStatusInprogress,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusInprogress),
		"started_at": preSub.StartedAt.UnixMilli(),
	}
	if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
		ID:      newTask.ID,
		Updater: taskUpdater,
		Where:   fmt.Sprintf("status = %d", imagesecModel.TaskStatusPending),
	}); err != nil {
		s.Log.Err(err).Msg("AdaptPreSubtask  UpdateScanTask")
		return err
	}

	subtaskUpdater := map[string]interface{}{
		"status":     imagesecModel.TaskStatusScanFinished,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusScanFinished),
		"started_at": preSub.StartedAt.UnixMilli(),
	}
	if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
		ID:      newSubtask.ID,
		Updater: subtaskUpdater,
		Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause),
	}); err != nil {
		s.Log.Err(err).Msg("AdaptPreSubtask  UpdateScanSubtask")
		return err
	}

	v210, err := ver210.GetImageMigrate()
	if err != nil {
		s.Log.Err(err).Msg("AdaptPreSubtask  not GetImageMigrate")
		return err
	}
	if err := v210.MigrateScan(ctx, preSub.ImageID, newSubtask.ID); err != nil {
		s.Log.Err(err).Msg("AdaptPreSubtask  MigrateImage")
		return err
	}

	_ = s.deleteAdaptedPreScanTask(ctx, preSub.ID)

	s.Log.Info().Str("subtask", newSubtask.LogInfo()).Msg("AdaptPreScan task scan success and send data to kafka")

	return nil
}

func (s *ScanTaskSrv) updateFailed(ctx context.Context, sub *model.SubTask) error {

	s.Log.Info().Int64("taskID", sub.TaskID).Int64("subtaskID", sub.ID).
		Str("ImageName", sub.FullRepoName+":"+sub.Tag).Msg("AdaptPreScan low version  subtask scan failed")

	updater := map[string]interface{}{
		"status":      imagesecModel.TaskStatusFailed,
		"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusFailed),
		"finished_at": time.Now().UnixMilli(),
		"msg":         sub.ErrMsg,
		"reason":      imagesecModel.TaskFailedReasonScanner,
	}
	if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
		ID:      sub.ID,
		Updater: updater,
		Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause),
	}); err != nil {
		s.Log.Err(err).Msg("AdaptPreScan UpdateScanSubtask")
		return err
	}
	_ = s.deleteAdaptedPreScanTask(ctx, sub.ID)

	s.Log.Info().Int64("taskID", sub.TaskID).Int64("subtaskID", sub.ID).
		Str("ImageName", sub.FullRepoName+":"+sub.Tag).Msg("AdaptPreScan subtask scan failed and update subtask status")
	return nil
}

func (s *ScanTaskSrv) deleteAdaptedPreScanTask(ctx context.Context, subID int64) error {
	subtask, err := s.preTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{SubtaskID: subID})
	if err != nil {
		s.Log.Err(err).Int64("subtaskID", subID).Msg("AdaptPreScan delete adapted subtask")
		return err
	}
	if len(subtask) == 0 {
		return nil
	}
	sub := subtask[0]
	switch sub.Status {
	case preConsts.ImageScanSuccess:
		err = s.preTaskDal.DeleteScanSubtask(ctx, sub.ID)
		if err != nil {
			s.Log.Err(err).Int64("subtaskID", sub.ID).Msg("AdaptPreScan delete adapted subtask")
			return err
		}
	case preConsts.ImageScanFailed:
		// 不删除，便于排查原因
		update := map[string]interface{}{
			"status": consts.ImageStatusImageAdapted,
		}
		err = s.preTaskDal.UpdateScanSubtask(ctx, []int64{sub.ID}, update)
		if err != nil {
			s.Log.Err(err).Int64("subtaskID", sub.ID).Msg("AdaptPreScan update adapted subtask")
			return err
		}
	}

	err = s.preTaskDal.DeleteScanSubtask(ctx, sub.ID)
	if err != nil {
		s.Log.Err(err).Int64("subtaskID", sub.ID).Msg("AdaptPreScan delete adapted subtask")
		return err
	}
	err = s.preTaskDal.DeleteScanTask(ctx, sub.TaskID)
	if err != nil {
		s.Log.Err(err).Int64("TaskID", sub.TaskID).Msg("AdaptPreScan delete adapted task")
		return err
	}
	// 不能删除镜像，因为可能还有其他任务
	// 会出现的一个问题是，数据会冗余
	// err = s.preImageDal.DeletePreImage(ctx, &model.ImageList{ID: sub.ImageID})
	// if err != nil {
	// 	s.Log.Err(err).Int64("TaskID", sub.TaskID).Msg("AdaptPreScan delete adapted image")
	// 	return err
	// }
	return nil
}

// 对于未升级的集群 终止
func (s *ScanTaskSrv) AdaptTaskTerminate(ctx context.Context, taskID int64) error {
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
			time.Sleep(time.Minute)
			s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskTerminate")
			continue
		}
		if len(subtask) == 0 {
			s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskTerminate finished")
			break
		}
		startId = subtask[len(subtask)-1].ID

		for i := range subtask {
			_ = s.deleteAdaptedPreScanTask(ctx, subtask[i].ID)
		}
	}
	return nil
}

// 对于未升级的集群 暂停
func (s *ScanTaskSrv) AdaptTaskPause(ctx context.Context, taskID int64) error {
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
			return err
		}
		if len(subtask) == 0 {
			s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskTerminate finished")
			break
		}
		startId = subtask[len(subtask)-1].ID
		subtaskIds := make([]int64, 0)
		for i := range subtask {
			if subtask[i].Status >= imagesecModel.TaskStatusScanFinished {
				continue
			}
			subtaskIds = append(subtaskIds, subtask[i].ID)

		}

		if len(subtaskIds) == 0 {
			continue
		}
		subtaskUpdater := map[string]interface{}{
			"status": preConsts.ImageScanPending,
		}
		taskUpdater := map[string]interface{}{
			"status": preConsts.Pause,
		}
		_ = s.preTaskDal.UpdateScanTask(ctx, subtaskIds, taskUpdater) // 一定是 subtask.ID 不是 subtask.taskID
		_ = s.preTaskDal.UpdateScanSubtask(ctx, subtaskIds, subtaskUpdater)

	}
	return nil
}

// 对于未升级的集群重新执行
func (s *ScanTaskSrv) AdaptTaskPending(ctx context.Context, taskID int64) error {
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
			return err
		}
		if len(subtask) == 0 {
			s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateSubTaskTerminate finished")
			break
		}
		startId = subtask[len(subtask)-1].ID
		subtaskIds := make([]int64, 0)

		for i := range subtask {
			if subtask[i].Status >= imagesecModel.TaskStatusTerminate {
				continue
			}
			subtaskIds = append(subtaskIds, subtask[i].ID)
		}
		if len(subtaskIds) == 0 {
			continue
		}

		subtaskUpdater := map[string]interface{}{
			"status":      preConsts.ImageScanPending,
			"started_at":  nil,
			"finished_at": nil,
		}
		taskUpdater := map[string]interface{}{
			"status": preConsts.Pending,
		}
		_ = s.preTaskDal.UpdateScanTask(ctx, subtaskIds, taskUpdater) // 一定是 subtask.ID 不是 subtask.taskID
		_ = s.preTaskDal.UpdateScanSubtask(ctx, subtaskIds, subtaskUpdater)

	}
	return nil
}
