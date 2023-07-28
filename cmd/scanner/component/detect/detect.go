package detect

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect/detector"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type Detector struct {
	policySrv             SecurityPolicySrv
	detectResultDal       imagesecStore.ImageDetectResultDal
	detectTaskDal         imagesecStore.DetectTaskDal
	scanTaskDal           imagesecStore.ScanTaskDal
	imageDataSrv          GetImageWithCorrelateData
	imageDal              imagesecStore.ImageMetaDal
	checker               ImagePolicyChecker
	updateImageChan       chan UpdateImage
	imageDetectTaskSrv    ImageDetectTaskService
	addDetectTaskEveryDay bool
}

type UpdateImage struct {
	ImageUniqueID uint64
	SubtaskID     int64
	ImageFromType string
	CreateAt      int64
	DetectResult  PolicyDetectResult
}

type GetImageWithCorrelateData interface {
	GetImageCorrelateData(ctx context.Context, param imagesecModel.GetImageAssociateDataParam) (*imagesecModel.ImageWithCorrelateData2, error)
	UpdateImage(ctx context.Context, param imagesecModel.UpdateImageParam) error
}

type SecurityPolicySrv interface {
	SearchPolicy(ctx context.Context, param imagesecModel.SearchSecurityPolicyParam) ([]*imagesecModel.SecurityPolicy, int64, error)
}

func NewDetector(
	policySrv SecurityPolicySrv,
	detectResultDal imagesecStore.ImageDetectResultDal,
	nodeScanTaskDal imagesecStore.ScanTaskDal,
	detectTaskDal imagesecStore.DetectTaskDal,
	imageDataSrv GetImageWithCorrelateData,
	imagePolicyChecker ImagePolicyChecker,
	imageDal imagesecStore.ImageMetaDal,
	imageDetectTaskSrv ImageDetectTaskService,
) *Detector {
	s := &Detector{
		policySrv:             policySrv,
		detectResultDal:       detectResultDal,
		detectTaskDal:         detectTaskDal,
		scanTaskDal:           nodeScanTaskDal,
		imageDataSrv:          imageDataSrv,
		checker:               imagePolicyChecker,
		imageDal:              imageDal,
		imageDetectTaskSrv:    imageDetectTaskSrv,
		updateImageChan:       make(chan UpdateImage),
		addDetectTaskEveryDay: false,
	}
	if os.Getenv("ADD_DETECT_EVERYDAY") == consts.TrueString {
		s.addDetectTaskEveryDay = true
	}

	return s
}

func (s *Detector) Start(ctx context.Context) {

	if os.Getenv("IS_MAIN_CLUSTER") != consts.TrueString {
		logging.Get().Info().Msg("Detector not in main cluster ")
		return
	}

	logging.Get().Info().Msg("Detector in  main cluster")

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("Detector recover")
			}
		}()
		s.ContinueUpdateImage(ctx)
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("Detector recover")
			}
		}()
		s.DetectImage(ctx)
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("Detector recover")
			}
		}()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			_ = s.UpdateDetectTaskFinished(ctx)
			_ = s.AddDetectTaskEveryDay(ctx)
		}
	}()
}

func (s *Detector) DetectImage(ctx context.Context) {
	defer close(s.updateImageChan)

	taskChan := s.GenTaskChan(ctx)

	for task := range taskChan {
		logging.Get().Debug().Int64("taskID", task.ID).Msg("Detector get task")

		if err := s.UpdateTask(ctx, task.ID, getStartUpdater()); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("Detector UpdateTask")
			continue
		}

		subtaskChan := s.GenSubtaskChan(ctx, task)

		for subtask := range subtaskChan {
			logging.Get().Debug().Int64("taskID", task.ID).Interface("subtask", subtask).
				Msg("Detector get subtask")

			_ = s.UpdateSubTask(ctx, subtask.ID, getStartUpdater())
			resultAll := make([]PolicyDetectResult, 0)

			imageData, err := s.GetImageData(ctx, subtask.ImageUniqueID)
			if err != nil {
				_ = s.updateScanSubtask(ctx, task.ScanSubTaskID, imagesecModel.TaskStatusDetectFinished)
				_ = s.UpdateSubTask(ctx, subtask.ID, getEndUpdater(err))
				logging.Get().Err(err).Uint64("ImageUniqueID", subtask.ImageUniqueID).Msg("Detector GetImageData")
				continue
			}

			policy, _, err := s.policySrv.SearchPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{
				Ids:      subtask.PolicyIds,
				NotCount: true,
				Deleted:  consts.FalseString,
			})
			if err != nil {
				_ = s.updateScanSubtask(ctx, task.ScanSubTaskID, imagesecModel.TaskStatusDetectFinished)
				_ = s.UpdateSubTask(ctx, subtask.ID, getEndUpdater(err))
				logging.Get().Err(err).Uint64("ImageUniqueID", subtask.ImageUniqueID).Ints64("policyIds", subtask.PolicyIds).
					Msg("Detector SearchPolicy")
				continue
			}

			for i := range policy {
				result := s.checker.Check(ctx, imageData, policy[i])
				resultAll = append(resultAll, result)

				for dt, data := range result {
					if err := s.detectResultDal.CreateDetectResult(ctx, imagesecModel.CreateDetectResultParam{
						ImageUniqueID: imageData.Image.UniqueID,
						PolicyID:      policy[i].ID,
						DetectType:    dt,
						Data:          data,
					}); err != nil {
						_ = s.UpdateSubTask(ctx, subtask.ID, getEndUpdater(err))
						logging.Get().Err(err).Uint64("ImageUniqueID", subtask.ImageUniqueID).Msg("Detector CreateDetectResult")
						continue
					}
				}

				if err := s.detectResultDal.CreateDetectBrief(ctx, &imagesecModel.ImageDetectBrief{
					ImageUniqueID: imageData.Image.UniqueID,
					PolicyID:      policy[i].ID,
					Flag:          imagesecModel.GetDetectBriefFlag(result),
					Policy:        policy[i],
				}); err != nil {
					logging.Get().Err(err).Uint64("ImageUniqueID", subtask.ImageUniqueID).Msg("Detector CreateDetectBrief")
					_ = s.UpdateSubTask(ctx, subtask.ID, getEndUpdater(err))
					continue
				}
			}

			_ = s.updateScanSubtask(ctx, task.ScanSubTaskID, imagesecModel.TaskStatusDetectFinished)

			up := UpdateImage{
				SubtaskID:     subtask.ID,
				ImageUniqueID: imageData.Image.UniqueID,
				ImageFromType: imageData.Image.ImageFromType,
				CreateAt:      time.Now().UnixMilli(),
				DetectResult:  MergePolicyDetectResult(resultAll),
			}
			go func() { s.updateImageChan <- up }()

			_ = s.UpdateSubTask(ctx, subtask.ID, getEndUpdater(nil))

			logging.Get().Debug().Int64("taskID", task.ID).Int64("subtaskID", subtask.ID).
				Uint64("imageUniqueID", subtask.ImageUniqueID).Str("imageName", imageData.Image.GetImageName()).
				Msg("Detector finished detect image")
		}
	}
}

func (s *Detector) GenSubtaskChan(ctx context.Context, task *imagesecModel.ImageDetectTask) chan *imagesecModel.ImageDetectSubTask {
	out := make(chan *imagesecModel.ImageDetectSubTask)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("GenSubtaskChan")
			}
		}()

		// 检测一批之后，让出调度
		filter := &model.Filter{Limit: consts.DefaultPerPage}
		defer close(out)

		subtask, _, err := s.detectTaskDal.SearchDetectSubtask(ctx, imagesecModel.SearchTaskParam{
			TaskID:     task.ID,
			ScanStatus: []int64{imagesecModel.TaskStatusPending},
			Filter:     filter,
		})
		if err != nil {
			logging.Get().Error().Int64("taskID", task.ID).Str("stack", string(debug.Stack())).
				Msg("Detector SearchDetectSubtask")
			return
		}
		if len(subtask) == 0 {
			_ = s.UpdateTask(ctx, task.ID, getEndUpdater(nil))
			logging.Get().Info().Int64("taskID", task.ID).Msg("Detector GenSubtaskChan send subtask finish")
			return
		}

		logging.Get().Info().Int64("taskID", task.ID).Int("subtaskCnt", len(subtask)).
			Msg("Detector GenSubtaskChan get subtask")
		for i := range subtask {
			out <- subtask[i]
		}
	}()

	return out
}

func (s *Detector) GenTaskChan(ctx context.Context) chan *imagesecModel.ImageDetectTask {
	out := make(chan *imagesecModel.ImageDetectTask)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("Detector GenTaskChan")
			}
		}()

		ticker := time.NewTicker(time.Second * 1)
		defer close(out)
		defer ticker.Stop()

		var startID int64
		filter := &model.Filter{Limit: consts.DefaultLimit, SortFiled: "priority", SortBy: consts.SortByDesc}
		for {
			<-ticker.C
			tasks, _, err := s.detectTaskDal.SearchDetectTask(ctx, imagesecModel.SearchTaskParam{
				StartID:    startID,
				ScanStatus: []int64{imagesecModel.TaskStatusInprogress, imagesecModel.TaskStatusPending},
				Filter:     filter,
			})

			if err != nil {
				ticker.Reset(10 * time.Second)
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("Detector SearchDetectTask")
				continue
			}

			logging.Get().Info().Int64("startID", startID).Int("taskCnt", len(tasks)).Msg("Detector SearchDetectTask")
			if len(tasks) == 0 {
				ticker.Reset(10 * time.Second)
				startID = 0
				continue
			}

			notScanTaskCnt := 0
			for i := range tasks {
				if tasks[i].Priority != imagesecModel.DetectPriorityScan {
					notScanTaskCnt++
				}
				if notScanTaskCnt > consts.DefaultSendSubtaskBatchSize {
					startID = 0
					break
				}
				out <- tasks[i]
			}

			ticker.Reset(time.Second * 1)
		}
	}()

	return out
}

func (s *Detector) GetImageData(ctx context.Context, imageUniqueID uint64) (*imagesecModel.ImageWithCorrelateData2, error) {
	data, err := s.imageDataSrv.GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageUniqueID:   imageUniqueID,
		VulnEnable:      true,
		MalwareEnable:   true,
		EnvEnable:       true,
		PkgEnable:       true,
		LicenseEnable:   true,
		SensitiveEnable: true,
		WebshellEnable:  true,
		ContainerEnable: true,
	})
	return data, err
}

func (s *Detector) GetPolicy(ctx context.Context, policyID int64) (*imagesecModel.SecurityPolicy, error) {
	policy, _, err := s.policySrv.SearchPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{
		Ids:      []int64{policyID},
		NotCount: true,
		Deleted:  consts.FalseString,
	})
	if err != nil {
		return nil, err
	}
	if len(policy) == 0 {
		return nil, fmt.Errorf("not get policy:%d", policyID)
	}
	return policy[0], nil
}

func (s *Detector) UpdateSubTask(ctx context.Context, subtaskID int64, updater map[string]interface{}) error {

	err := s.detectTaskDal.UpdateDetectSubtask(ctx, imagesecModel.UpdateTaskParam{
		ID:      subtaskID,
		Updater: updater,
	})
	if err != nil {
		logging.Get().Err(err).Int64("subtaskID", subtaskID).Msg("Detector UpdateSubTask")
		return err
	}
	return err
}

func (s *Detector) UpdateTask(ctx context.Context, taskID int64, updater map[string]interface{}) error {
	err := s.detectTaskDal.UpdateDetectTask(ctx, imagesecModel.UpdateTaskParam{
		ID:      taskID,
		Updater: updater,
	})
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Msg("Detector UpdateTask")

		return err
	}
	return err
}

func (s *Detector) UpdateDetectTaskFinished(ctx context.Context) error {

	tasks, _, err := s.detectTaskDal.SearchDetectTask(ctx, imagesecModel.SearchTaskParam{
		ScanStatus: []int64{imagesecModel.TaskStatusInprogress},
		Filter:     model.EmptyFilter().SetLimit(consts.DefaultLimit).SetSortFiled("priority").SetSortDesc(),
	})

	if err != nil {
		logging.Get().Err(err).Msg("UpdateDetectTaskFinished Detector SearchScanTask")
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
		group, err := s.detectTaskDal.GroupDetectSubtask(ctx, imagesecModel.SearchTaskParam{TaskID: task.ID})
		if err != nil {
			logging.Get().Err(err).Msg("Detector GroupScanSubtask")
			return err
		}

		if group.DetectFinished+group.Failed >= group.All {
			_ = s.updateScanSubtask(ctx, task.ScanSubTaskID, imagesecModel.TaskStatusDetectFinished)

			if err := s.detectTaskDal.UpdateDetectTask(ctx, imagesecModel.UpdateTaskParam{
				ID:      task.ID,
				Updater: updater,
			}); err != nil {
				logging.Get().Err(err).Msg("Detector UpdateScanTask")
				return err
			}
			logging.Get().Info().Int64("taskID", task.ID).Msg("Detector finished detect")
			continue
		}

		logging.Get().Info().Int64("taskID", task.ID).Msg("UpdateDetectTaskFinished Detector not finished")
	}
	return nil
}

func (s *Detector) ContinueUpdateImage(ctx context.Context) {
	for up := range s.updateImageChan {
		logging.Get().Debug().Uint64("imageUniqueID", up.ImageUniqueID).Msg("Detector UpdateImage get a image")

		// 解决主从同步(现在是强制主库)
		// if time.Now().UnixMilli()-up.CreateAt < consts.DefaultSlaveDelay {
		// 	time.Sleep(consts.DefaultSlaveDelay * time.Millisecond)
		// }
		brief, err := s.detectResultDal.SearchDetectBrief(ctx, imagesecModel.SearchDetectBriefParam{
			ImageUniqueID: up.ImageUniqueID,
		})
		if err != nil {
			logging.Get().Err(err).Uint64("ImageUniqueID", up.ImageUniqueID).Msg("Detector UpdateImage SearchDetectBrief")
			continue
		}
		image, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{
			ImageFromType: up.ImageFromType,
			UniqueId:      up.ImageUniqueID,
		})

		if err != nil {
			logging.Get().Err(err).Uint64("ImageUniqueID", up.ImageUniqueID).Msg("Detector UpdateImage SearchImage")
			continue
		}
		if len(image) == 0 {
			logging.Get().Info().Uint64("ImageUniqueID", up.ImageUniqueID).Msg("Detector SearchImage not find image")
			continue
		}
		flag := imagesecModel.AddImageSafeFlag(brief, image[0].Flag)

		flag = GenIssueFlag(up.DetectResult, flag)

		if image[0].Flag != flag {
			logging.Get().Info().Uint64("imageUniqueID", up.ImageUniqueID).Msg("Detector UpdateImage")
			updater := map[string]interface{}{"flag": flag}
			if err := s.imageDal.UpdateImage(ctx, imagesecModel.UpdateImageParam{
				UniqueID: up.ImageUniqueID,
				Updater:  updater,
			}); err != nil {
				logging.Get().Err(err).Uint64("ImageUniqueID", up.ImageUniqueID).Msg("Detector UpdateImage")
				continue
			}
		}
		logging.Get().Debug().Uint64("imageUniqueID", up.ImageUniqueID).Uint64("flag", flag).Msg("Detector UpdateImage finished")
	}
}

func (s *Detector) AddDetectTaskEveryDay(ctx context.Context) error {
	if !s.addDetectTaskEveryDay {
		logging.Get().Info().Msg("do not add detect task everyday")
		return nil
	}
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			<-ticker.C
			if int64(time.Now().Hour()) == consts.DetectAtHour {
				if err := s.imageDetectTaskSrv.CreateImageDetectTask(ctx,
					imagesecModel.ImageListParam{ImageFromType: imagesecModel.ImageFromNode},
					imagesecModel.ImageDetectTask{Priority: imagesecModel.DetectPriorityCycle},
				); err != nil {
					logging.Get().Err(err).Msg("AddDetectTaskEveryDay")
				}
				logging.Get().Info().Msg("AddDetectTaskEveryDay")
			}
			ticker.Reset(time.Hour)
		}
	}()
	return nil
}

func (s *Detector) updateScanSubtask(ctx context.Context, scanSubtaskID int64, status int64) error {
	if scanSubtaskID <= 0 {
		return nil
	}
	logging.Get().Info().Int64("subtaskID", scanSubtaskID).Str("statusStr", imagesecModel.ScanStatusToStr(status)).
		Msg("Detector detect finished and update scan subtask")

	updater := map[string]interface{}{
		"status":      imagesecModel.TaskStatusDetectFinished,
		"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusDetectFinished),
		"finished_at": time.Now().UnixMilli(),
	}
	if status != imagesecModel.TaskStatusDetectFinished {
		updater["status"] = imagesecModel.TaskStatusFailed
		updater["status_str"] = imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusFailed)
		updater["msg"] = "detect image error"
		updater["reason"] = imagesecModel.TaskFailedReasonSaveData
	}

	if err := s.scanTaskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
		ID:      scanSubtaskID,
		Updater: updater,
		Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause),
	}); err != nil {
		logging.Get().Err(err).Int64("subtaskID", scanSubtaskID).Interface("updater", updater).
			Msg("Detector detect image bug update scan subtask error")
		return err
	}
	logging.Get().Info().Int64("subtaskID", scanSubtaskID).Interface("statusStr", updater["status_str"]).
		Msg("Detector detect image finished and update scan subtask")
	return nil

}

func getStartUpdater() map[string]interface{} {
	updater := map[string]interface{}{
		"started_at": time.Now().UnixMilli(),
		"status":     imagesecModel.TaskStatusInprogress,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusInprogress),
	}
	return updater
}

func getEndUpdater(err error) map[string]interface{} {
	updater := map[string]interface{}{
		"finished_at": time.Now().UnixMilli(),
		"status":      imagesecModel.TaskStatusDetectFinished,
		"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusDetectFinished),
	}

	if err != nil {
		updater["msg"] = err.Error()
		updater["status"] = imagesecModel.TaskStatusFailed
		updater["status_str"] = imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusFailed)
	}
	return updater
}

type Checker func(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) []*imagesecModel.ImageDetectResult

var ruleCheckers map[string]Checker

func GetChecker() map[string]Checker {
	if ruleCheckers == nil {
		ruleCheckers = make(map[string]Checker)
	}
	ruleCheckers[imagesecModel.DetectTypeVulnRule] = detector.CheckImageVuln
	ruleCheckers[imagesecModel.DetectTypeSensRule] = detector.CheckImageSensitive
	ruleCheckers[imagesecModel.DetectTypePkgVersionRule] = detector.CheckImagePkg
	ruleCheckers[imagesecModel.DetectTypePkgLicenseRule] = detector.CheckImageLicense
	ruleCheckers[imagesecModel.DetectTypeMalwareRule] = detector.CheckImageMalware
	ruleCheckers[imagesecModel.DetectTypeEnvRule] = detector.CheckImageEnv
	ruleCheckers[imagesecModel.DetectTypeRootRule] = detector.CheckImageUser
	ruleCheckers[imagesecModel.DetectTypeWebshellRule] = detector.CheckImageWebshell

	return ruleCheckers
}

type PolicyDetectResult map[string][]*imagesecModel.ImageDetectResult

func MergePolicyDetectResult(res []PolicyDetectResult) PolicyDetectResult {
	ans := make(map[string][]*imagesecModel.ImageDetectResult)
	for i := range res {
		da := res[i]
		for k, v := range da {
			if ans[k] == nil {
				ans[k] = make([]*imagesecModel.ImageDetectResult, 0)
			}
			ans[k] = append(ans[k], v...)
		}
	}

	return ans
}

func check(res PolicyDetectResult, flag uint64, ruleType string, exceptFlag uint64) uint64 {
	flag = util.SetBit0(flag, exceptFlag)
	for i := range res[ruleType] {
		data := res[ruleType][i]
		if util.ExistBit1(data.Flag, imagesecModel.FlagDetectException) {
			flag = util.SetBit1(flag, exceptFlag)
			break
		}
	}
	return flag
}

func GenIssueFlag(res PolicyDetectResult, flag uint64) uint64 {
	flag = check(res, flag, imagesecModel.DetectTypeVulnRule, model.FlagHasVuln)
	flag = check(res, flag, imagesecModel.DetectTypeSensRule, model.FlagHasSensitive)
	flag = check(res, flag, imagesecModel.DetectTypeMalwareRule, model.FlagHasMalicious)
	flag = check(res, flag, imagesecModel.DetectTypePkgVersionRule, model.FlagHasExceptPKG)
	flag = check(res, flag, imagesecModel.DetectTypePkgLicenseRule, model.FlagHasExceptLicense)
	flag = check(res, flag, imagesecModel.DetectTypeWebshellRule, model.FlagHasWebshell)
	flag = check(res, flag, imagesecModel.DetectTypeRootRule, model.FlagPrivilegedBoot)
	flag = check(res, flag, imagesecModel.DetectTypeEnvRule, model.FlagHasExceptEnv)

	return flag
}

type ImagePolicyChecker interface {
	Check(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
		policy *imagesecModel.SecurityPolicy) PolicyDetectResult
}

type ImagePolicyCheck struct {
}

func NewImagePolicyCheck() *ImagePolicyCheck {
	return &ImagePolicyCheck{}
}

func (s *ImagePolicyCheck) Check(ctx context.Context, data *imagesecModel.ImageWithCorrelateData2,
	policy *imagesecModel.SecurityPolicy) PolicyDetectResult {
	res := make(map[string][]*imagesecModel.ImageDetectResult)
	checkers := GetChecker()
	for ruleType := range checkers {
		ans := ruleCheckers[ruleType](ctx, data, policy)
		for i := range ans {
			ans[i].DetectType = ruleType
		}

		res[ruleType] = ruleCheckers[ruleType](ctx, data, policy)
	}
	return res
}
