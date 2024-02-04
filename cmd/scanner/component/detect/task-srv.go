package detect

import (
	"context"
	"fmt"
	"regexp"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageDetectTaskService interface {
	CreateImageDetectTask(ctx context.Context,
		imageSearchParam imagesecModel.ImageSearchApiParam,
		taskInfo imagesecModel.ImageDetectTask,
		policy *imagesecModel.SecurityPolicy,
	) error
	DeleteDetectData(ctx context.Context, param imagesecModel.SearchTaskParam) error
}

type ImageDetectTaskSrv struct {
	imageSrv        ImageService
	taskDal         imagesecStore.DetectTaskDal
	policyDal       imagesecStore.DetectPolicyDal
	detectResultDal imagesecStore.ImageDetectResultDal
	Log             *scannerUtils.LogEvent
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
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("DetectTask"),
			scannerUtils.WithModule(consts.ModuleDetect),
		),
	}
	return srv
}

func (s *ImageDetectTaskSrv) CreateImageDetectTask(
	ctx context.Context,
	imageSearchParam imagesecModel.ImageSearchApiParam,
	taskInfo imagesecModel.ImageDetectTask,
	policy *imagesecModel.SecurityPolicy, // 只加特定策略的镜像
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
		s.Log.Err(err).Interface("task", task).Msg("CreateDetectTask")
		return err
	}

	go func(taskID int64) {
		_ = s.CreateDetectSubtask(ctx, task, imageSearchParam, policy)
	}(task.ID)

	s.Log.Info().Int64("taskID", task.ID).Msg("CreateDetectTask succeed")

	return nil
}

func (s *ImageDetectTaskSrv) DeleteDetectData(ctx context.Context, param imagesecModel.SearchTaskParam) error {
	_ = s.deleteDetectSubtask(ctx, param.PolicyID)
	_ = s.deleteDetectResult(ctx, param.PolicyID)
	_ = s.deleteDetectBrief(ctx, param.PolicyID)
	return nil
}

func (s *ImageDetectTaskSrv) deleteDetectSubtask(ctx context.Context, policyID int64) error {
	filter := imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiledByID().SetSortAsc()
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
			s.Log.Err(err).Interface("param", param).Msg("DeleteDetectSubtask")
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
			s.Log.Err(err).Ints64("subtaskIds", subtaskIds).
				Msg("DeleteDetectSubtask")
			continue
		}
		s.Log.Debug().Ints64("subtaskIds", subtaskIds).Msg("DeleteDetectSubtask")
	}
	s.Log.Info().Int64("taskID", param.TaskID).
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
			s.Log.Err(err).Int64("policyID", policyID).Str("DetectType", det[i]).Msg("deleteDetectResult")
		}
	}
	return nil
}

func (s *ImageDetectTaskSrv) deleteDetectBrief(ctx context.Context, policyID int64) error {
	err := s.detectResultDal.DeleteDetectBrief(ctx, imagesecModel.SearchDetectBriefParam{
		PolicyID: policyID,
	})
	if err != nil {
		s.Log.Err(err).Int64("policyID", policyID).Msg("deleteDetectResult")
		return err
	}
	return nil
}

func (s *ImageDetectTaskSrv) CreateDetectSubtask(
	ctx context.Context,
	task *imagesecModel.ImageDetectTask,
	imageSearchParam imagesecModel.ImageSearchApiParam,
	policy *imagesecModel.SecurityPolicy,
) error {
	var startId int64
	all := make([]*imagesecModel.SecurityPolicy, 0)

	if policy == nil {
		po, _, err := s.policyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{
			Deleted:  consts.FalseString,
			NotCount: true,
		})
		if err != nil {
			s.Log.Err(err).Msg("CreateDetectSubtask SearchDetectPolicy")
			return err
		}
		all = append(all, po...)
	}
	if policy != nil {
		all = append(all, policy)
	}

	filter := &imagesecModel.Filter{
		SortBy:    consts.SortByAsc,
		SortFiled: "id",
		Limit:     consts.DefaultMaxLimit,
	}
	for {
		imageSearchParam.StartID = startId
		imageSearchParam.Filter = filter
		assParam := imagesecModel.ImageAssociateParam{RegistryEnable: true, NodeInfoEnable: true, SubtaskEnable: true, NotNeedCompImageSafe: true}
		imageSearchParam.AssociateParam = assParam

		images, _, err := s.imageSrv.ListImageWithScanInfo(ctx, imageSearchParam)
		if err != nil {
			s.Log.Err(err).Msg("CreateDetectSubtask SearchImage")
			break
		}

		if len(images) == 0 {
			s.Log.Info().Msg("CreateDetectSubtask finished create subtask")
			break
		}
		startId = images[len(images)-1].ID

		subtasks := make([]*imagesecModel.ImageDetectSubTask, 0)

		for i := range images {
			im := images[i]
			if im.LastScanAt <= 0 {
				s.Log.Info().Str("image", im.GetImageName()).Msg("not scan not add detect task")
				// 2.21的新改动， 镜像同步时不检测,
				// 如果镜像没有被扫描过，就不检测
				continue
			}
			// 把这个镜像相关的所有策略都找出来，重新加
			// 可以这样做的原因是：在扫描时，会同时把同一个镜像的所有策略找到一起检测
			added := FindNeedAddPolicy(im, all)
			for j := range added {
				po := added[j]
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
				s.Log.Err(err).Msg("CreateDetectSubtask")
				continue
			}
		}
		s.Log.Info().Int64("taskID", task.ID).Int("subtaskCnt", len(subtasks)).Msg("CreateDetectSubtask")
	}

	updater := map[string]interface{}{
		"status":     imagesecModel.TaskStatusPending,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
	}

	if err := s.taskDal.UpdateDetectTask(ctx, imagesecModel.UpdateTaskParam{Updater: updater, ID: task.ID}); err != nil {
		s.Log.Err(err).Int64("taskID", task.ID).Msg("CreateDetectSubtask UpdateDetectTask to TaskStatusSendFinished")
		return err
	}

	return nil
}

func NeedDetectImage(im *imagesecModel.ImageBaseResponse, po *imagesecModel.SecurityPolicy) bool {

	if im == nil || po == nil {
		return false
	}

	if im.ImageFromType == imagesecModel.ImageFromRegistry && po.PolicyType != imagesecModel.ConfigTypeRegScanImage {
		return false
	}

	if im.ImageFromType == imagesecModel.ImageFromNode && po.PolicyType != imagesecModel.ConfigTypeNodeScanImage {
		return false
	}

	scope := po.Scope

	if scope.ScopeType == imagesecModel.DetectScopeTypeImage {
		// 所有的正则都只要包含就行
		for i := range po.Scope.ImageRegexp {
			reg := po.Scope.ImageRegexp[i]
			if reg == "" {
				continue
			}
			com, err := regexp.Compile(reg)
			if err != nil {
				// 新建策略的时候会验证，这里就不记录日志了
				continue
			}
			imageName := fmt.Sprintf("%s/%s:%s", im.RegistryUrl, im.FullRepoName, im.Tag)
			if com.FindString(imageName) != "" {
				return true
			}
		}
	}

	if scope.ScopeType == imagesecModel.DetectScopeTypeCluster {
		if im.ImageFromType != imagesecModel.ImageFromNode {
			return false
		}
		if scope.AllCluster {
			return true
		}
		if util.ExistInStringSlice(scope.ClusterKey, im.ClusterKey) {
			return true
		}
	}

	if scope.ScopeType == imagesecModel.DetectScopeTypeReg {
		if im.ImageFromType != imagesecModel.ImageFromRegistry {
			return false
		}
		if scope.AllReg {
			return true
		}
		if util.ExistInInt64Slice(scope.RegIds, im.RegistryID) {
			return true
		}
	}

	return false
}

func FindNeedAddPolicy(im *imagesecModel.ImageBaseResponse, policy []*imagesecModel.SecurityPolicy) []*imagesecModel.SecurityPolicy {
	ans := make([]*imagesecModel.SecurityPolicy, 0)
	for i := range policy {
		po := policy[i]
		if NeedDetectImage(im, po) {
			ans = append(ans, po)
		}
	}
	return ans
}
