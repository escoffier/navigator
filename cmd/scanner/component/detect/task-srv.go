package detect

import (
	"context"
	"regexp"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageDetectTaskService interface {
	CreateImageDetectTask(ctx context.Context,
		imageSearchParam imagesecModel.ImageListParam,
		taskInfo imagesecModel.ImageDetectTask) error
	DeleteDetectTask(ctx context.Context, param imagesecModel.SearchTaskParam) error
}

type ImageDetectTaskSrv struct {
	imageSrv  ImageService
	taskDal   imagesecStore.DetectTaskDal
	policyDal imagesecStore.DetectPolicyDal
}

type ImageService interface {
	ListImageWithScanInfo(ctx context.Context, param imagesecModel.ImageListParam) ([]*imagesecModel.ImageBaseResponse, int64, error)
}

func NewImageDetectTaskSrv(
	imageSrv ImageService,
	taskDal imagesecStore.DetectTaskDal,
	policyDal imagesecStore.DetectPolicyDal,
) *ImageDetectTaskSrv {
	srv := &ImageDetectTaskSrv{
		imageSrv:  imageSrv,
		taskDal:   taskDal,
		policyDal: policyDal,
	}
	return srv
}

func (s *ImageDetectTaskSrv) CreateImageDetectTask(
	ctx context.Context,
	imageSearchParam imagesecModel.ImageListParam,
	taskInfo imagesecModel.ImageDetectTask,
) error {

	task := &imagesecModel.ImageDetectTask{
		ImageFromType: imageSearchParam.ImageFromType,
		Priority:      taskInfo.Priority,
		ScanSubTaskID: taskInfo.ScanSubTaskID,
		Status:        imagesecModel.TaskStatusNotReady,
		StatusStr:     imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusNotReady),
		Updater:       consts.DefaultAdminUser,
		Creator:       consts.DefaultAdminUser,
	}

	if err := s.taskDal.CreateDetectTask(ctx, task); err != nil {
		logging.Get().Err(err).Interface("task", task).Msg("CreateDetectTask")
		return err
	}

	go func(taskID int64) {
		_ = s.CreateDetectSubtask(ctx, task, imageSearchParam)
	}(task.ID)

	logging.Get().Info().Int64("taskID", task.ID).Msg("CreateDetectTask succeed")

	return nil
}

func (s *ImageDetectTaskSrv) DeleteDetectTask(ctx context.Context, param imagesecModel.SearchTaskParam) error {
	tasks, _, err := s.taskDal.SearchDetectTask(ctx, param)
	if err != nil {
		logging.Get().Err(err).Interface("param", param).Msg("DeleteDetectTask")
		return err
	}

	for i := range tasks {
		if err := s.taskDal.DeleteDetectSubtask(ctx, imagesecModel.SearchTaskParam{TaskID: tasks[i].ID}); err != nil {
			logging.Get().Err(err).Int64("taskID", tasks[i].ID).Msg("DeleteDetectSubtask")
			continue
		}
		if err := s.taskDal.DeleteDetectTask(ctx, imagesecModel.SearchTaskParam{TaskID: tasks[i].ID}); err != nil {
			logging.Get().Err(err).Int64("taskID", tasks[i].ID).Msg("DeleteDetectTask")
			continue
		}
		logging.Get().Info().Int64("taskID", tasks[i].ID).Msg("DeleteDetectTask")
	}
	logging.Get().Info().Int64("taskID", param.TaskID).Msg("DeleteDetectTask succeed")
	return nil
}

func (s *ImageDetectTaskSrv) CreateDetectSubtask(
	ctx context.Context,
	task *imagesecModel.ImageDetectTask,
	imageSearchParam imagesecModel.ImageListParam,
) error {
	var startId int64

	policy, _, err := s.policyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{Deleted: consts.FalseString})
	if err != nil {
		logging.Get().Err(err).Msg("CreateDetectSubtask SearchDetectPolicy")
		return err
	}
	if len(policy) == 0 {
		logging.Get().Info().Msg("CreateDetectSubtask not find policy")
		return nil
	}
	filter := &model.Filter{
		SortBy:    consts.SortByAsc,
		SortFiled: "id",
		Limit:     consts.DefaultLimit,
	}
	for {
		imageSearchParam.StartID = startId
		imageSearchParam.Filter = filter

		images, _, err := s.imageSrv.ListImageWithScanInfo(ctx, imageSearchParam)
		if err != nil {
			logging.Get().Err(err).Msg("CreateDetectSubtask SearchImage")
			break
		}

		if len(images) == 0 {
			logging.Get().Info().Interface("param", imageSearchParam).Msg("CreateDetectSubtask not find image")
			break
		}
		startId = images[len(images)-1].ID

		subtasks := make([]*imagesecModel.ImageDetectSubTask, 0)

		for i := range images {
			policyIds := make([]int64, 0)
			for j := range policy {
				if NeedAddDetectSubtask(images[i], policy[j].Scope) {
					policyIds = append(policyIds, policy[j].ID)
				}
			}
			if len(policyIds) > 0 {
				subtask := &imagesecModel.ImageDetectSubTask{
					TaskID:        task.ID,
					ImageUniqueID: images[i].UniqueID,
					PolicyIds:     policyIds,
					Status:        imagesecModel.TaskStatusPending,
					StatusStr:     imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
				}

				subtasks = append(subtasks, subtask)
			}
		}

		if len(subtasks) > 0 {
			if err := s.taskDal.CreateDetectSubtask(ctx, subtasks); err != nil {
				logging.Get().Err(err).Msg("CreateDetectSubtask")
				continue
			}
		}
		logging.Get().Info().Int64("taskID", task.ID).Int("subtaskCnt", len(subtasks)).Msg("CreateDetectSubtask")
	}

	updater := map[string]interface{}{
		"status":     imagesecModel.TaskStatusPending,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
	}

	if err := s.taskDal.UpdateDetectTask(ctx, imagesecModel.UpdateTaskParam{Updater: updater, ID: task.ID}); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("CreateDetectSubtask UpdateDetectTask to TaskStatusSendFinished")
		return err
	}

	return nil
}

func NeedAddDetectSubtask(image *imagesecModel.ImageBaseResponse, policy imagesecModel.PolicyScope) bool {
	if image == nil {
		return false
	}
	if image.ImageFromType != policy.ImageFromType {
		return false
	}
	if policy.ScopeType == imagesecModel.DetectScopeTypeImage {
		compile := regexp.MustCompile(policy.ImageRegexp)
		if compile.FindString(image.GetImageName()) == "" {
			return false
		}
	}

	if policy.ScopeType == imagesecModel.DetectScopeTypeCluster {
		if !policy.AllCluster && !util.ExistInStringSlice(policy.ClusterKey, image.NodeClusterKey) {
			return false
		}
	}

	return true
}
