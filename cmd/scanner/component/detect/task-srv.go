package detect

import (
	"context"
	"fmt"
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
		imageSearchParam imagesecModel.ImageSearchApiParam,
		taskInfo imagesecModel.ImageDetectTask,
		policy []*imagesecModel.SecurityPolicy,
	) error
	DeleteDetectData(ctx context.Context, param imagesecModel.SearchTaskParam) error
}

type ImageDetectTaskSrv struct {
	imageSrv        ImageService
	taskDal         imagesecStore.DetectTaskDal
	policyDal       imagesecStore.DetectPolicyDal
	detectResultDal imagesecStore.ImageDetectResultDal
}

type ImageService interface {
	ListImageWithScanInfo(ctx context.Context, param imagesecModel.ImageSearchApiParam) ([]*imagesecModel.ImageBaseResponse, int64, error)
}

func NewImageDetectTaskSrv(
	imageSrv ImageService,
	taskDal imagesecStore.DetectTaskDal,
	policyDal imagesecStore.DetectPolicyDal,
	detectResultDal imagesecStore.ImageDetectResultDal,
) *ImageDetectTaskSrv {
	srv := &ImageDetectTaskSrv{
		imageSrv:        imageSrv,
		taskDal:         taskDal,
		policyDal:       policyDal,
		detectResultDal: detectResultDal,
	}
	return srv
}

func (s *ImageDetectTaskSrv) CreateImageDetectTask(
	ctx context.Context,
	imageSearchParam imagesecModel.ImageSearchApiParam,
	taskInfo imagesecModel.ImageDetectTask,
	policy []*imagesecModel.SecurityPolicy,
) error {

	task := &imagesecModel.ImageDetectTask{
		Priority:      taskInfo.Priority,
		ScanSubTaskID: taskInfo.ScanSubTaskID,
		Status:        imagesecModel.TaskStatusNotReady,
		StatusStr:     imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusNotReady),
		Updater:       consts.DefaultAdminUser,
		Creator:       consts.DefaultAdminUser,
	}

	if err := s.taskDal.CreateDetectTask(ctx, task); err != nil {
		logging.Get().Err(err).Str("module", "detectImage").Interface("task", task).Msg("CreateDetectTask")
		return err
	}

	go func(taskID int64) {
		_ = s.CreateDetectSubtask(ctx, task, imageSearchParam, policy)
	}(task.ID)

	logging.Get().Info().Str("module", "detectImage").Int64("taskID", task.ID).Msg("CreateDetectTask succeed")

	return nil
}

func (s *ImageDetectTaskSrv) DeleteDetectData(ctx context.Context, param imagesecModel.SearchTaskParam) error {
	_ = s.deleteDetectSubtask(ctx, param.PolicyID)
	_ = s.deleteDetectResult(ctx, param.PolicyID)
	_ = s.deleteDetectBrief(ctx, param.PolicyID)
	return nil
}

func (s *ImageDetectTaskSrv) deleteDetectSubtask(ctx context.Context, policyID int64) error {
	filter := model.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiledByID().SetSortAsc()
	param := imagesecModel.SearchTaskParam{
		PolicyID: policyID,
		Filter:   filter,
		Fields:   []string{"id", "image_unique_id"},
	}
	var startID int64
	for {
		param.StartID = startID
		subtask, _, err := s.taskDal.SearchDetectSubtask(ctx, param)
		if err != nil {
			logging.Get().Err(err).Str("module", "detectImage").Interface("param", param).
				Msg("DeleteDetectSubtask")
			continue
		}
		if len(subtask) == 0 {
			break
		}
		startID = subtask[len(subtask)-1].ID

		subtaskIds := make([]int64, 0)
		for i := range subtask {
			subtaskIds = append(subtaskIds, subtask[i].ID)
		}

		if err := s.taskDal.DeleteDetectSubtask(ctx, imagesecModel.SearchTaskParam{SubtaskIds: subtaskIds}); err != nil {
			logging.Get().Err(err).Str("module", "detectImage").Ints64("subtaskIds", subtaskIds).
				Msg("DeleteDetectSubtask")
			continue
		}
		logging.Get().Info().Str("module", "detectImage").Ints64("subtaskIds", subtaskIds).
			Msg("DeleteDetectSubtask")
	}
	logging.Get().Info().Str("module", "detectImage").Int64("taskID", param.TaskID).
		Msg("DeleteDetectSubtask succeed")
	return nil
}

func (s *ImageDetectTaskSrv) deleteDetectResult(ctx context.Context, policyID int64) error {
	det := imagesecModel.GetDetectTypes()
	for i := range det {
		err := s.detectResultDal.DeleteDetectResult(ctx, imagesecModel.SearchDetectResultParam{
			DetectType: det[i],
			PolicyID:   policyID,
		})
		if err != nil {
			logging.Get().Err(err).Str("module", "detectImage").Int64("policyID", policyID).
				Str("DetectType", det[i]).Msg("deleteDetectResult")
		}
	}
	return nil
}

func (s *ImageDetectTaskSrv) deleteDetectBrief(ctx context.Context, policyID int64) error {
	err := s.detectResultDal.DeleteDetectBrief(ctx, imagesecModel.SearchDetectBriefParam{
		PolicyID: policyID,
	})
	if err != nil {
		logging.Get().Err(err).Str("module", "detectImage").Int64("policyID", policyID).Msg("deleteDetectResult")
		return err
	}
	return nil
}

func (s *ImageDetectTaskSrv) CreateDetectSubtask(
	ctx context.Context,
	task *imagesecModel.ImageDetectTask,
	imageSearchParam imagesecModel.ImageSearchApiParam,
	policy []*imagesecModel.SecurityPolicy,
) error {
	var startId int64
	if len(policy) == 0 {
		po, _, err := s.policyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{Deleted: consts.FalseString})
		if err != nil {
			logging.Get().Err(err).Str("module", "detectImage").Msg("CreateDetectSubtask SearchDetectPolicy")
			return err
		}
		policy = po
	}

	filter := &model.Filter{
		SortBy:    consts.SortByAsc,
		SortFiled: "id",
		Limit:     consts.DefaultMaxLimit,
	}
	for {
		imageSearchParam.StartID = startId
		imageSearchParam.Filter = filter

		images, _, err := s.imageSrv.ListImageWithScanInfo(ctx, imageSearchParam)
		if err != nil {
			logging.Get().Err(err).Str("module", "detectImage").Msg("CreateDetectSubtask SearchImage")
			break
		}

		if len(images) == 0 {
			logging.Get().Info().Str("module", "detectImage").Msg("CreateDetectSubtask finished create subtask")
			break
		}
		startId = images[len(images)-1].ID

		subtasks := make([]*imagesecModel.ImageDetectSubTask, 0)

		for i := range images {
			im := images[i]
			for j := range policy {
				po := policy[j]
				if !NeedAddDetectSubtask(im, po) {
					continue
				}
				subtask := &imagesecModel.ImageDetectSubTask{
					TaskID:        task.ID,
					ImageUniqueID: im.UniqueID,
					PolicyID:      po.ID,
					Status:        imagesecModel.TaskStatusPending,
					StatusStr:     imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
				}

				subtasks = append(subtasks, subtask)
			}
		}

		if len(subtasks) > 0 {
			if err := s.taskDal.CreateDetectSubtask(ctx, subtasks); err != nil {
				logging.Get().Err(err).Str("module", "detectImage").Msg("CreateDetectSubtask")
				continue
			}
		}
		logging.Get().Info().Str("module", "detectImage").Int64("taskID", task.ID).Int("subtaskCnt", len(subtasks)).Msg("CreateDetectSubtask")
	}

	updater := map[string]interface{}{
		"status":     imagesecModel.TaskStatusPending,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
	}

	if err := s.taskDal.UpdateDetectTask(ctx, imagesecModel.UpdateTaskParam{Updater: updater, ID: task.ID}); err != nil {
		logging.Get().Err(err).Str("module", "detectImage").Int64("taskID", task.ID).Msg("CreateDetectSubtask UpdateDetectTask to TaskStatusSendFinished")
		return err
	}

	return nil
}

func NeedAddDetectSubtask(image *imagesecModel.ImageBaseResponse, policy *imagesecModel.SecurityPolicy) bool {

	if image == nil || policy == nil {
		return false
	}

	if image.ImageFromType == imagesecModel.ImageFromRegistry && policy.PolicyType != imagesecModel.ConfigTypeRegScanImage {
		return false
	}

	if image.ImageFromType == imagesecModel.ImageFromNode && policy.PolicyType != imagesecModel.ConfigTypeNodeScanImage {
		return false
	}

	scope := policy.Scope

	if scope.ScopeType == imagesecModel.DetectScopeTypeImage {
		// 所有的正则都只要包含就行
		for i := range policy.Scope.ImageRegexp {
			reg := policy.Scope.ImageRegexp[i]
			if reg != "" {
				com, err := regexp.Compile(reg)
				if err != nil {
					logging.Get().Err(err).Str("module", "detectImage").Msg("NeedAddDetectSubtask")
					continue
				}
				imageName := fmt.Sprintf("%s/%s:%s", image.RegistryUrl, image.FullRepoName, image.Tag)
				if com.FindString(imageName) != "" {
					return true
				}
			}
		}
	}

	if scope.ScopeType == imagesecModel.DetectScopeTypeCluster {
		if scope.AllCluster {
			return true
		}
		if util.ExistInStringSlice(scope.ClusterKey, image.ClusterKey) {
			return true
		}
	}

	if scope.ScopeType == imagesecModel.DetectScopeTypeReg {
		if scope.AllReg {
			return true
		}
		if util.ExistInInt64Slice(scope.RegIds, image.RegistryID) {
			return true
		}
	}

	return false
}
