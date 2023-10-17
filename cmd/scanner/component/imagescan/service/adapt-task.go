package service

import (
	"context"
	"fmt"
	"time"

	ver210 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/dataMigrate/220"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 兼容老版本
func (s *ScanTaskSrv) AdaptCreateSubtask(ctx context.Context, images []*imagesecModel.ImageBaseResponse,
	subtask []*imagesecModel.ImageScanSubTask) error {

	if len(images) != len(subtask) {
		s.Log.Error().Msg("AdaptPreSubtask image not equal subtask")
		return fmt.Errorf("image not equal subtask")
	}
	adaptCnt := 0
	for i := range images {
		image := images[i]
		sub := subtask[i]
		if util.ThanVersion(image.ScanInsVer, consts.ScannerVersion220) || image.ImageFromType != imagesecModel.ImageFromRegistry {
			continue
		}
		adaptCnt++

		s.Log.Debug().Msg("AdaptPreSubtask create task and subtask")

		task := &model.Task{
			ID:              sub.ID,
			RegistryID:      image.RegistryID,
			ScopeType:       consts.FullScan,
			Trigger:         consts.ManualTrigger,
			Status:          consts.Pending,
			FlowConf:        "defaultImageScanFlow",
			GroupID:         time.Now().UnixMilli(),
			ScannerInstance: image.ScanInstance,
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
			Status:        consts.ImageStatusImageAdapt,
		}
		su := &model.SubTask{
			ID:           sub.ID,
			ImageID:      image.ID,
			Status:       consts.ImageScanPending,
			RegID:        task.RegistryID,
			FullRepoName: iml.FullRepoName,
			Tag:          iml.Tags,
			Library:      iml.Library,
		}

		iml.UniqueImage = iml.GenUniqueImage()

		_ = s.preImageDal.DeletePreImage(ctx, iml)
		if err := s.preImageDal.CreatePreImage(ctx, iml); err != nil {
			s.Log.Err(err).Str("imageName", image.GetImageName()).
				Int64("subtaskID", sub.ID).Msg("AdaptPreSubtask CreatePreImage")
			continue
		}

		_ = s.preTaskDal.DeleteScanTask(ctx, sub.ID)
		if err := s.preTaskDal.CreateScanTask(ctx, task); err != nil {
			s.Log.Err(err).Str("imageName", image.GetImageName()).
				Int64("subtaskID", sub.ID).Msg("AdaptPreSubtask create pre ScanTask")
			continue
		}
		_ = s.preTaskDal.DeleteScanSubtask(ctx, sub.ID)
		if err := s.preTaskDal.CreateScanSubtask(ctx, su); err != nil {
			s.Log.Err(err).Str("imageName", image.GetImageName()).
				Int64("subtaskID", sub.ID).Msg("AdaptPreSubtask Create pre ScanSubtask")
			continue
		}
	}

	s.Log.Info().Int("preSubtaskCnt", adaptCnt).Msg("AdaptPreSubtask task and subtask finished")
	return nil
}

// 兼容
func (s *ScanTaskSrv) UpdatePreSubtask(ctx context.Context) error {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Msg("UpdatePreSubtask recover panic")
			}
		}()

		for sub := range s.PreTaskUpdateChan {
			subtaskID := sub.ID
			// sub.ScanInsVer == "" 表示1.19之前的版本
			if util.ThanVersion(sub.ScanInsVer, consts.ScannerVersion220) {
				continue
			}

			subtask, err := s.preTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{SubtaskID: subtaskID})
			if err != nil {
				s.Log.Err(err).Msg("AdaptPreSubtask UpdatePreSubtask SearchScanSubtask")
				continue
			}
			if len(subtask) == 0 {
				s.Log.Info().Int64("subtaskID", subtaskID).Msg("AdaptPreSubtask not find subtask")
				continue
			}

			s.Log.Debug().Int64("taskID", sub.TaskID).Int64("subtaskID", sub.ID).
				Str("ImageName", sub.ImageName).Msg("AdaptPreSubtask find scan result")

			su := subtask[0]
			switch su.Status {
			case consts.ImageScanSuccess:
				_ = s.updateSuccess(ctx, su)
			case consts.ImageScanFailed:
				_ = s.updateFailed(ctx, su)
			}
		}
	}()
	return nil
}

func (s *ScanTaskSrv) updateSuccess(ctx context.Context, sub *model.SubTask) error {

	s.Log.Info().Int64("taskID", sub.TaskID).Int64("subtaskID", sub.ID).
		Str("ImageName", sub.FullRepoName+":"+sub.Tag).Msg("AdaptPreSubtask task scan success")

	updater := map[string]interface{}{
		"status":      imagesecModel.TaskStatusScanFinished,
		"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusFailed),
		"finished_at": time.Now().UnixMilli(),
	}
	if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
		ID:      sub.ID,
		Updater: updater,
		Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause),
	}); err != nil {
		s.Log.Err(err).Msg("AdaptPreSubtask UpdatePreSubtask UpdateScanSubtask")
		return err
	}

	v210, err := ver210.GetImageMigrate()
	if err != nil {
		s.Log.Err(err).Msg("AdaptPreSubtask UpdatePreSubtask not GetImageMigrate")
		return err
	}
	if err := v210.MigrateImage(ctx, sub.ImageID, sub.ID); err != nil {
		s.Log.Err(err).Msg("AdaptPreSubtask UpdatePreSubtask  MigrateImage")
		return err
	}

	s.Log.Info().Int64("taskID", sub.TaskID).Int64("subtaskID", sub.ID).
		Str("ImageName", sub.FullRepoName+":"+sub.Tag).Msg("AdaptPreSubtask task scan success and send data to kafka")

	return nil
}

func (s *ScanTaskSrv) updateFailed(ctx context.Context, sub *model.SubTask) error {

	s.Log.Info().Int64("taskID", sub.TaskID).Int64("subtaskID", sub.ID).
		Str("ImageName", sub.FullRepoName+":"+sub.Tag).Msg("AdaptPreSubtask task scan failed")

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
		s.Log.Err(err).Msg("UpdatePreSubtask UpdateScanSubtask")
		return err
	}

	s.Log.Info().Int64("taskID", sub.TaskID).Int64("subtaskID", sub.ID).
		Str("ImageName", sub.FullRepoName+":"+sub.Tag).Msg("AdaptPreSubtask task scan failed and update subtask status")
	return nil
}
