package detect

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect/detector"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
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
	if !scannerUtils.MainCluster() {
		logging.Get().Info().Str("module", "detectImage").Msg("Detector not in main cluster ")
		return
	}

	logging.Get().Info().Str("module", "detectImage").Msg("Detector in  main cluster")

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
		logging.Get().Debug().Str("module", "detectImage").Int64("taskID", task.ID).Msg("Detector get task")

		if err := s.UpdateTask(ctx, task.ID, getStartUpdater()); err != nil {
			logging.Get().Err(err).Str("module", "detectImage").Int64("taskID", task.ID).Msg("Detector UpdateTask")
			continue
		}

		subtaskChan := s.GenSubtaskChan(ctx, task)

		for subData := range subtaskChan {
			logging.Get().Debug().Str("module", "detectImage").Int64("taskID", task.ID).Interface("subData", subData).
				Msg("Detector get subData")
			for i := range subData.SubtaskIds {
				_ = s.UpdateDetectSubTask(ctx, subData.SubtaskIds[i], getStartUpdater())
			}
			resultAll := make([]PolicyDetectResult, 0)

			imageData, err := s.GetImageData(ctx, subData.ImageUniqueID)
			if err != nil {
				_ = s.updateScanSubtask(ctx, task.ScanSubTaskID, imagesecModel.TaskStatusDetectFinished)
				for i := range subData.SubtaskIds {
					_ = s.UpdateDetectSubTask(ctx, subData.SubtaskIds[i], getEndUpdater(err))
				}
				logging.Get().Err(err).Str("module", "detectImage").Uint64("ImageUniqueID", subData.ImageUniqueID).
					Msg("Detector GetImageData")
				continue
			}

			param1 := imagesecModel.SearchSecurityPolicyParam{PolicyType: GetImagePolicyType(imageData.Image)}
			allPolicy, _, err := s.policySrv.SearchPolicy(ctx, param1)

			if err != nil {
				logging.Get().Err(err).Str("module", "detectImage").Uint64("ImageUniqueID", subData.ImageUniqueID).
					Msg("Detector SearchPolicy")
				continue
			}
			policy := make([]*imagesecModel.SecurityPolicy, 0)
			for i := range allPolicy {
				bas := imageData.ToImageBaseResponse()
				if NeedAddDetectSubtask(&bas, allPolicy[i]) {
					policy = append(policy, allPolicy[i])
				}
			}

			for _, po := range policy {
				result := s.checker.Check(ctx, imageData, po)
				resultAll = append(resultAll, result)

				for dt, data := range result {
					if err := s.detectResultDal.CreateDetectResult(ctx, imagesecModel.CreateDetectResultParam{
						ImageUniqueID: imageData.Image.UniqueID,
						PolicyID:      po.ID,
						DetectType:    dt,
						Data:          data,
					}); err != nil {
						// _ = s.UpdateDetectSubTask(ctx, subData.ID, getEndUpdater(err))
						logging.Get().Err(err).Str("module", "detectImage").Uint64("ImageUniqueID", subData.ImageUniqueID).
							Msg("Detector CreateDetectResult")
						continue
					}
				}
				err2 := s.detectResultDal.CreateDetectBrief(ctx, &imagesecModel.ImageDetectBrief{
					ImageUniqueID: imageData.Image.UniqueID,
					Flag:          imagesecModel.GetDetectBriefFlag(result),
					Policy:        po,
				})
				if err2 != nil {
					logging.Get().Err(err2).Str("module", "detectImage").Uint64("ImageUniqueID", subData.ImageUniqueID).
						Msg("Detector CreateDetectBrief")
					// _ = s.UpdateDetectSubTask(ctx, subData.ID, getEndUpdater(err))
					continue
				}
			}

			up := UpdateImage{
				ImageUniqueID: imageData.Image.UniqueID,
				ImageFromType: imageData.Image.ImageFromType,
				CreateAt:      time.Now().UnixMilli(),
				DetectResult:  MergePolicyDetectResult(resultAll),
			}
			go func() { s.updateImageChan <- up }()

			for _, subID := range subData.SubtaskIds {
				_ = s.UpdateDetectSubTask(ctx, subID, getEndUpdater(nil))
			}

			logging.Get().Debug().Str("module", "detectImage").Int64("taskID", task.ID).
				Uint64("imageUniqueID", subData.ImageUniqueID).Str("imageName", imageData.Image.GetImageName()).
				Msg("Detector finished detect image")
		}

		_ = s.updateScanSubtask(ctx, task.ScanSubTaskID, imagesecModel.TaskStatusDetectFinished)
	}
}

func (s *Detector) GenSubtaskChan(ctx context.Context, task *imagesecModel.ImageDetectTask) chan SubtaskData {
	out := make(chan SubtaskData)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("GenSubtaskChan")
			}
		}()

		// 检测一批之后，让出调度
		filter := &model.Filter{Limit: consts.DefaultPerPage, SortFiled: "id", SortBy: consts.SortByAsc}
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
			logging.Get().Debug().Str("module", "detectImage").Int64("taskID", task.ID).Msg("Detector scan image subtask finish")
			return
		}
		// 获取该镜像的所有任务
		for i := range subtask {
			im := subtask[i].ImageUniqueID
			data := SubtaskData{
				TaskID:        task.ID,
				ImageUniqueID: im,
			}
			detectSubtask, _, err := s.detectTaskDal.SearchDetectSubtask(ctx, imagesecModel.SearchTaskParam{
				ScanStatus:    []int64{imagesecModel.TaskStatusPending},
				ImageUniqueID: im,
				Filter:        filter,
			})
			if err != nil {
				logging.Get().Error().Int64("taskID", task.ID).Str("stack", string(debug.Stack())).
					Msg("Detector SearchDetectSubtask")
				return
			}
			if len(detectSubtask) == 0 {
				_ = s.UpdateTask(ctx, task.ID, getEndUpdater(nil))
				logging.Get().Debug().Str("module", "detectImage").Int64("taskID", task.ID).Msg("Detector scan image subtask finish")
				return
			}
			subtaskIds := make([]int64, 0)
			for j := range detectSubtask {
				sb := detectSubtask[j]
				subtaskIds = append(subtaskIds, sb.ID)
			}
			if len(subtaskIds) == 0 {
				_ = s.UpdateTask(ctx, task.ID, getEndUpdater(nil))
				logging.Get().Debug().Str("module", "detectImage").Int64("taskID", task.ID).Msg("Detector scan image subtask finish")
				return
			}
			data.SubtaskIds = subtaskIds

			out <- data

			logging.Get().Info().Str("module", "detectImage").Int64("taskID", task.ID).
				Int64("subtaskID", subtask[i].ID).Uint64("ImageUniqueID", im).
				Msg("Detector GenSubtaskChan get subtask")
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

		ticker := time.NewTicker(time.Second * 5)
		defer close(out)
		defer ticker.Stop()

		var startID int64
		priorityOrder := clause.OrderByColumn{
			Column: clause.Column{Name: "priority"},
			Desc:   true,
		}
		idOrder := clause.OrderByColumn{
			Column: clause.Column{Name: "id"},
			Desc:   false,
		}

		filter := &model.Filter{Limit: consts.DefaultPerPage, OrderByColumns: []clause.OrderByColumn{priorityOrder, idOrder}}
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

			if len(tasks) == 0 {
				ticker.Reset(30 * time.Second)
				startID = 0
				continue
			}

			logging.Get().Info().Str("module", "detectImage").Int64("startID", startID).
				Int("taskCnt", len(tasks)).Msg("Detector SearchDetectTask")

			for i := range tasks {
				out <- tasks[i]
				if tasks[i].Priority != imagesecModel.DetectPriorityScan {
					startID = 0
					break
				}
			}
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

func (s *Detector) UpdateDetectSubTask(ctx context.Context, subtaskID int64, updater map[string]interface{}) error {

	err := s.detectTaskDal.UpdateDetectSubtask(ctx, imagesecModel.UpdateTaskParam{
		ID:      subtaskID,
		Updater: updater,
	})
	if err != nil {
		logging.Get().Err(err).Str("module", "detectImage").Int64("subtaskID", subtaskID).
			Msg("Detector UpdateDetectSubTask")
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
		logging.Get().Err(err).Str("module", "detectImage").Int64("taskID", taskID).Msg("Detector UpdateTask")

		return err
	}
	return err
}

func (s *Detector) UpdateDetectTaskFinished(ctx context.Context) error {

	tasks, _, err := s.detectTaskDal.SearchDetectTask(ctx, imagesecModel.SearchTaskParam{
		ScanStatus: []int64{imagesecModel.TaskStatusInprogress},
		Filter:     model.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiled("priority").SetSortDesc(),
	})

	if err != nil {
		logging.Get().Err(err).Str("module", "detectImage").Msg("UpdateDetectTaskFinished Detector SearchScanTask")
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
			logging.Get().Err(err).Str("module", "detectImage").Msg("Detector GroupScanSubtask")
			return err
		}

		if group.DetectFinished+group.Failed >= group.All {
			_ = s.updateScanSubtask(ctx, task.ScanSubTaskID, imagesecModel.TaskStatusDetectFinished)

			if err := s.detectTaskDal.UpdateDetectTask(ctx, imagesecModel.UpdateTaskParam{
				ID:      task.ID,
				Updater: updater,
			}); err != nil {
				logging.Get().Err(err).Str("module", "detectImage").Msg("Detector UpdateScanTask")
				return err
			}
			logging.Get().Info().Str("module", "detectImage").Int64("taskID", task.ID).
				Msg("Detector finished detect")
			continue
		}

		logging.Get().Info().Str("module", "detectImage").Int64("taskID", task.ID).
			Msg("UpdateDetectTaskFinished Detector not finished")
	}
	return nil
}

func (s *Detector) ContinueUpdateImage(ctx context.Context) {
	for up := range s.updateImageChan {
		logging.Get().Debug().Str("module", "detectImage").Uint64("imageUniqueID", up.ImageUniqueID).
			Msg("Detector UpdateImage get a image")

		// 解决主从同步
		// if time.Now().UnixMilli()-up.CreateAt < consts.DefaultSlaveDelay {
		// 	time.Sleep(consts.DefaultSlaveDelay * time.Millisecond)
		// }
		brief, err := s.detectResultDal.SearchDetectBrief(ctx, imagesecModel.SearchDetectBriefParam{
			ImageUniqueID: up.ImageUniqueID,
		})
		if err != nil {
			logging.Get().Err(err).Str("module", "detectImage").Uint64("ImageUniqueID", up.ImageUniqueID).
				Msg("Detector UpdateImage SearchDetectBrief")
			continue
		}
		image, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
			ImageFromType: up.ImageFromType,
			UniqueId:      up.ImageUniqueID,
		})

		if err != nil {
			logging.Get().Err(err).Str("module", "detectImage").Uint64("ImageUniqueID", up.ImageUniqueID).
				Msg("Detector UpdateImage SearchImage")
			continue
		}
		if len(image) == 0 {
			logging.Get().Info().Str("module", "detectImage").Uint64("ImageUniqueID", up.ImageUniqueID).
				Msg("Detector not find image")
			continue
		}

		flag := imagesecModel.AddImageSafeFlag(brief, image[0].Flag)

		flag = GenImageIssueFlag(up.DetectResult, flag)

		policyUniqueID := make([]uint64, 0)
		for i := range brief {
			if util.ExistBit1(brief[i].Flag, imagesecModel.FlagDetectException) {
				policyUniqueID = append(policyUniqueID, brief[i].PolicyUniqueID)
			}
		}
		policyUniqueStr := Uint64ToString(policyUniqueID)

		if image[0].Flag != flag || image[0].PolicyUniqueJson != policyUniqueStr {
			logging.Get().Debug().Str("module", "detectImage").Uint64("imageUniqueID", up.ImageUniqueID).
				Msg("Detector finished image changed and UpdateImage")

			updater := map[string]interface{}{"flag": flag, "policy_unique_id": policyUniqueStr}
			if err := s.imageDal.UpdateImage(ctx, imagesecModel.UpdateImageParam{
				UniqueID: up.ImageUniqueID,
				Updater:  updater,
			}); err != nil {
				logging.Get().Err(err).Str("module", "detectImage").Uint64("ImageUniqueID", up.ImageUniqueID).
					Msg("Detector UpdateImage")
				continue
			}
		}
	}
}

func (s *Detector) AddDetectTaskEveryDay(ctx context.Context) error {
	if !s.addDetectTaskEveryDay {
		logging.Get().Info().Str("module", "detectImage").Msg("do not add detect task everyday")
		return nil
	}
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			<-ticker.C
			if int64(time.Now().Hour()) == consts.DetectAtHour {
				if err := s.imageDetectTaskSrv.CreateImageDetectTask(ctx,
					imagesecModel.ImageSearchApiParam{ImageFromType: imagesecModel.ImageFromNode},
					imagesecModel.ImageDetectTask{Priority: imagesecModel.DetectPriorityCycle},
					make([]*imagesecModel.SecurityPolicy, 0),
				); err != nil {
					logging.Get().Err(err).Str("module", "detectImage").Msg("AddDetectTaskEveryDay")
				}
				logging.Get().Info().Str("module", "detectImage").Msg("AddDetectTaskEveryDay")
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
		logging.Get().Err(err).Str("module", "detectImage").Int64("subtaskID", scanSubtaskID).Interface("updater", updater).
			Msg("Detector detect image bug update scan subtask error")
		return err
	}
	logging.Get().Info().Str("module", "detectImage").Int64("subtaskID", scanSubtaskID).Interface("statusStr", updater["status_str"]).
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

func GetChecker() map[string]Checker {

	ruleCheckers := make(map[string]Checker)
	ruleCheckers[imagesecModel.DetectTypeVulnRule] = detector.CheckImageVuln
	ruleCheckers[imagesecModel.DetectTypeSensRule] = detector.CheckImageSensitive
	ruleCheckers[imagesecModel.DetectTypePkgRule] = detector.CheckImagePkg
	ruleCheckers[imagesecModel.DetectTypeLicenseRule] = detector.CheckImageLicense
	ruleCheckers[imagesecModel.DetectTypeMalwareRule] = detector.CheckImageMalware
	ruleCheckers[imagesecModel.DetectTypeEnvRule] = detector.CheckImageEnv
	ruleCheckers[imagesecModel.DetectTypeRootRule] = detector.CheckImageUser
	ruleCheckers[imagesecModel.DetectTypeWebshellRule] = detector.CheckImageWebshell
	ruleCheckers[imagesecModel.DetectTypeBaseImageRule] = detector.CheckBaseImage
	ruleCheckers[imagesecModel.DetectTypeTrustedImageRule] = detector.CheckTrustedImage
	ruleCheckers[imagesecModel.DetectTypeExistInRegRule] = detector.CheckExistInReg

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

	// 对于软件包，需要判断软件包版本号和license
	if ruleType == imagesecModel.DetectTypePkgRule {
		flag = util.SetBit0(flag, imagesecModel.FlagHasExceptionPkgLicense)
		for i := range res[ruleType] {
			data := res[ruleType][i]
			if util.ExistBit1(data.Flag, imagesecModel.FlagDetectExceptionPkgLicense) {
				flag = util.SetBit1(flag, imagesecModel.FlagHasExceptionPkgLicense)
				break
			}
		}
	}

	return flag
}

func GenImageIssueFlag(res PolicyDetectResult, flag uint64) uint64 {
	flag = check(res, flag, imagesecModel.DetectTypeVulnRule, imagesecModel.FlagHasExceptionVuln)
	flag = check(res, flag, imagesecModel.DetectTypeSensRule, imagesecModel.FlagHasExceptionSensitive)
	flag = check(res, flag, imagesecModel.DetectTypeMalwareRule, imagesecModel.FlagHasExceptionMalware)
	flag = check(res, flag, imagesecModel.DetectTypePkgRule, imagesecModel.FlagHasExceptionPKG)
	flag = check(res, flag, imagesecModel.DetectTypeWebshellRule, imagesecModel.FlagHasExceptionWebshell)
	flag = check(res, flag, imagesecModel.DetectTypeRootRule, imagesecModel.FlagExceptionBoot)
	flag = check(res, flag, imagesecModel.DetectTypeEnvRule, imagesecModel.FlagHasExceptionEnv)
	flag = check(res, flag, imagesecModel.DetectTypeBaseImageRule, imagesecModel.FlagNotExitBaseImage)
	flag = check(res, flag, imagesecModel.DetectTypeTrustedImageRule, imagesecModel.FlagImageUnTrusted)
	flag = check(res, flag, imagesecModel.DetectTypeLicenseRule, imagesecModel.FlagHasExceptionLicense)

	return flag
}

func GenDeployActionFlag(res PolicyDetectResult, flag uint64) uint64 {
	flag = check(res, flag, imagesecModel.DetectTypeVulnRule, imagesecModel.FlagImageDeployPassed)
	flag = check(res, flag, imagesecModel.DetectTypeSensRule, imagesecModel.FlagImageDeployBlock)
	flag = check(res, flag, imagesecModel.DetectTypeMalwareRule, imagesecModel.FlagImageDeployAlarm)

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
		ans := checkers[ruleType](ctx, data, policy)
		for i := range ans {
			ans[i].DetectType = ruleType
		}

		res[ruleType] = checkers[ruleType](ctx, data, policy)
	}
	return res
}

type SubtaskData struct {
	TaskID        int64
	ImageUniqueID uint64
	SubtaskIds    []int64
}
