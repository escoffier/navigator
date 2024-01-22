package detect

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect/detector"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type Detector struct {
	policySrv             SecurityPolicyService
	detectResultDal       imagesecStore.ImageDetectResultDal
	detectTaskDal         imagesecStore.DetectTaskDal
	scanTaskDal           imagesecStore.ScanTaskDal
	imageDataSrv          GetImageWithCorrelateData
	imageDal              imagesecStore.ImageMetaDal
	checker               ImagePolicyChecker
	updateImageChan       chan UpdateImage
	imageDetectTaskSrv    ImageDetectTaskService
	addDetectTaskEveryDay bool
	Log                   *scannerUtils.LogEvent
}

type UpdateImage struct {
	ImageUniqueID uint64
	ImageFromType string
	CreateAt      int64
	DetectResult  PolicyDetectResult2 // 当前镜像所有策略的匹配结果
}

type GetImageWithCorrelateData interface {
	GetImageCorrelateData(ctx context.Context, param imagesecModel.ImageAssociateParam) (*imagesecModel.ImageWithCorrelateData2, error)
	UpdateImage(ctx context.Context, param imagesecModel.UpdateImageParam) error
}

func NewDetector(
	policySrv SecurityPolicyService,
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
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("Detector"),
			scannerUtils.WithModule(consts.ModuleDetect),
		),
	}
	if os.Getenv("ADD_DETECT_EVERYDAY") == consts.TrueString {
		s.addDetectTaskEveryDay = true
	}

	return s
}

func (s *Detector) Start(ctx context.Context) {
	if !scannerUtils.MainCluster() {
		s.Log.Info().Msg("not in main cluster ")
		return
	}

	s.Log.Info().Msg("in  main cluster")

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("stack", string(debug.Stack())).Msg("recover")
			}
		}()
		s.ContinueUpdateImage(ctx)
	}()

	// go func() {
	// 	defer func() {
	// 		if r := recover(); r != nil {
	// 			s.Log.Error().Str("stack", string(debug.Stack())).Msg("recover")
	// 		}
	// 	}()
	// 	s.ContinueUpdateTaskFinished(ctx)
	// }()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("stack", string(debug.Stack())).Msg("recover")
			}
		}()
		s.DetectImage(ctx)
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("stack", string(debug.Stack())).Msg("recover")
			}
		}()
		ticker := time.NewTicker(time.Minute * 2)
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

	taskChan1 := s.GenCommonTaskChan(ctx)
	taskChan2 := s.GenScanTaskChan(ctx)
	for {
		select {
		case task1 := <-taskChan1:
			_ = s.detectTask(ctx, task1)
		case task2 := <-taskChan2:
			_ = s.detectTask(ctx, task2)
		}
	}
}

func (s *Detector) detectTask(ctx context.Context, task *imagesecModel.ImageDetectTask) error {
	s.Log.Debug().Str("task", task.LogStr()).Msg("get task")

	if err := s.UpdateTask(ctx, task.ID, getStartUpdater()); err != nil {
		s.Log.Err(err).Int64("taskID", task.ID).Msg("UpdateTask")
		return err
	}

	subtaskChan := s.GenSubtaskChan(ctx, task)

	for subData := range subtaskChan {
		s.Log.Debug().Int64("taskID", task.ID).Interface("subData", subData).
			Msg("get subData")
		for i := range subData.SubtaskIds {
			_ = s.UpdateDetectSubTask(ctx, subData.SubtaskIds[i], getStartUpdater())
		}
		resultAll := make(map[string]map[uint64]*imagesecModel.ImageDetectResult)

		imageData, err := s.GetImageData(ctx, subData.ImageUniqueID)
		if err != nil {
			_ = s.updateScanSubtask(ctx, task.ScanSubTaskID, imagesecModel.TaskStatusDetectFinished)
			for i := range subData.SubtaskIds {
				_ = s.UpdateDetectSubTask(ctx, subData.SubtaskIds[i], getEndUpdater(err))
			}
			s.Log.Err(err).Uint64("ImageUniqueID", subData.ImageUniqueID).
				Msg("GetImageData")
			continue
		}
		if len(allPolicy) == 0 {
			param1 := imagesecModel.SearchSecurityPolicyParam{
				Deleted: consts.FalseString,
			}
			allPolicy1, _, err := s.policySrv.SearchPolicy(ctx, param1)
			if err != nil {
				s.Log.Err(err).Uint64("ImageUniqueID", subData.ImageUniqueID).
					Msg("SearchPolicy")
				continue
			}
			allPolicy = allPolicy1
		}

		policy := make([]*imagesecModel.SecurityPolicy, 0)
		for i := range allPolicy {
			bas := imageData.ToImageBaseResponse()
			if NeedDetectImage(&bas, allPolicy[i]) {
				policy = append(policy, allPolicy[i])
			}
		}

		detectResults := make(map[string][]*imagesecModel.ImageDetectResult)
		// 如果策略有变动，就需要把原来的数据删除，所以这里全量增加
		for dt := range GetChecker() {
			detectResults[dt] = make([]*imagesecModel.ImageDetectResult, 0)
		}

		briefs := make([]*imagesecModel.ImageDetectBrief, 0)

		s.Log.Debug().Int("policyCnt", len(policy)).Msg("NeedDetectImage find policy")

		for i := range policy {
			po := policy[i]
			result := s.checker.Check(ctx, imageData, po)
			resultAll = MergeDetectResult(resultAll, result)

			for dt, data := range result {
				if detectResults[dt] == nil {
					detectResults[dt] = make([]*imagesecModel.ImageDetectResult, 0)
				}
				detectResults[dt] = append(detectResults[dt], data...)
			}
			bre := &imagesecModel.ImageDetectBrief{
				ImageUniqueID: imageData.Image.UniqueID,
				Flag:          imagesecModel.GetDetectBriefFlag(result),
				Policy:        po,
			}
			briefs = append(briefs, bre)
		}

		err = s.detectResultDal.CreateDetectBrief(ctx, imageData.Image.UniqueID, briefs)
		if err != nil {
			s.Log.Err(err).Uint64("ImageUniqueID", subData.ImageUniqueID).Msg("CreateDetectBrief")
		}

		for dt, res := range detectResults {
			if err := s.detectResultDal.CreateDetectResult(ctx, imagesecModel.CreateDetectResultParam{
				ImageUniqueID: imageData.Image.UniqueID,
				DetectType:    dt,
				Data:          res,
			}); err != nil {
				s.Log.Err(err).Uint64("ImageUniqueID", subData.ImageUniqueID).Msg("CreateDetectResult")
				continue
			}
		}

		up := UpdateImage{
			ImageUniqueID: imageData.Image.UniqueID,
			ImageFromType: imageData.Image.ImageFromType,
			CreateAt:      time.Now().UnixMilli(),
			DetectResult:  resultAll,
		}

		go func() { s.updateImageChan <- up }()

		for _, subID := range subData.SubtaskIds {
			_ = s.UpdateDetectSubTask(ctx, subID, getEndUpdater(nil))
		}

		s.Log.Debug().Int64("taskID", task.ID).
			Uint64("imageUniqueID", subData.ImageUniqueID).Str("imageName", imageData.Image.GetImageName()).
			Msg("finished detect image")
	}
	// 更新的扫描任务,因为一个扫描的任务的检测任务最多只有一个子任务，所以这样写不会出错
	_ = s.updateScanSubtask(ctx, task.ScanSubTaskID, imagesecModel.TaskStatusDetectFinished)
	return nil
}

func (s *Detector) GenSubtaskChan(ctx context.Context, task *imagesecModel.ImageDetectTask) chan SubtaskData {
	out := make(chan SubtaskData)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("stack", string(debug.Stack())).Msg("GenSubtaskChan")
			}
		}()

		// 检测一批之后，让出调度
		filter := &imagesecModel.Filter{Limit: consts.DefaultPerPage, SortFiled: "id", SortBy: consts.SortByAsc}
		defer close(out)

		subtask, _, err := s.detectTaskDal.SearchDetectSubtask(ctx, imagesecModel.SearchTaskParam{
			TaskID:     task.ID,
			ScanStatus: []int64{imagesecModel.TaskStatusPending},
			Filter:     filter,
		})
		if err != nil {
			s.Log.Err(err).Int64("taskID", task.ID).Str("stack", string(debug.Stack())).
				Msg("SearchDetectSubtask")
			return
		}
		if len(subtask) == 0 {
			_ = s.UpdateTask(ctx, task.ID, getEndUpdater(nil))
			s.Log.Debug().Int64("taskID", task.ID).Msg("scan image subtask finish")
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
				s.Log.Err(err).Int64("taskID", task.ID).Str("stack", string(debug.Stack())).
					Msg("SearchDetectSubtask")
				continue
			}
			if len(detectSubtask) == 0 {
				s.Log.Debug().Int64("taskID", task.ID).
					Msg("scan image subtask finish")
				continue
			}
			subtaskIds := make([]int64, 0)
			for j := range detectSubtask {
				sb := detectSubtask[j]
				subtaskIds = append(subtaskIds, sb.ID)
			}
			if len(subtaskIds) == 0 {
				s.Log.Debug().Int64("taskID", task.ID).
					Msg("scan image subtask finish")
				continue
			}
			data.SubtaskIds = subtaskIds

			out <- data

			s.Log.Debug().Int64("taskID", task.ID).
				Ints64("subtaskIds", subtaskIds).Uint64("ImageUniqueID", im).
				Msg("GenSubtaskChan get subtask")
		}
		s.Log.Info().Int64("taskID", task.ID).
			Int("subtaskCnt", len(subtask)).Msg("GenSubtaskChan get subtask")
	}()

	return out
}

func (s *Detector) GenCommonTaskChan(ctx context.Context) chan *imagesecModel.ImageDetectTask {
	out := make(chan *imagesecModel.ImageDetectTask)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("stack", string(debug.Stack())).Msg("GenCommonTaskChan")
			}
		}()

		ticker := time.NewTicker(time.Second)
		defer close(out)
		defer ticker.Stop()

		priorityOrder := clause.OrderByColumn{
			Column: clause.Column{Name: "priority"},
			Desc:   true,
		}
		idOrder := clause.OrderByColumn{
			Column: clause.Column{Name: "id"},
			Desc:   false,
		}

		filter := &imagesecModel.Filter{Limit: consts.DefaultPerPage, OrderByColumns: []clause.OrderByColumn{priorityOrder, idOrder}}
		for {
			<-ticker.C

			runTasks, _, err := s.detectTaskDal.SearchDetectTask(ctx, imagesecModel.SearchTaskParam{
				ScanStatus: []int64{imagesecModel.TaskStatusInprogress, imagesecModel.TaskStatusPending},
				Filter:     filter,
			})

			if err != nil {
				time.Sleep(time.Minute)
				s.Log.Err(err).Msg("SearchDetectTask")
				continue
			}

			if len(runTasks) == 0 {
				time.Sleep(time.Second * 30)
				continue
			}

			for i := range runTasks {
				if runTasks[i].ScanSubTaskID > 0 {
					// 优先保证扫描任务的检测
					time.Sleep(time.Second * 30)
					break
				}
				out <- runTasks[i]
			}
			s.Log.Info().Int("taskCnt", len(runTasks)).Msg("SearchDetectTask")
		}
	}()

	return out
}

func (s *Detector) GenScanTaskChan(ctx context.Context) chan *imagesecModel.ImageDetectTask {
	out := make(chan *imagesecModel.ImageDetectTask)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("stack", string(debug.Stack())).Msg("GenCommonTaskChan")
			}
		}()

		ticker := time.NewTicker(time.Second)
		defer close(out)
		defer ticker.Stop()

		filter := imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortAsc().SetSortFiledByID()
		for {
			<-ticker.C
			runTasks, _, err := s.detectTaskDal.SearchDetectTask(ctx, imagesecModel.SearchTaskParam{
				ScanStatus: []int64{imagesecModel.TaskStatusInprogress, imagesecModel.TaskStatusPending},
				Priority:   imagesecModel.DetectPriorityScan,
				Filter:     filter,
			})

			if err != nil {
				time.Sleep(5 * time.Minute)
				s.Log.Err(err).Msg("GenScanTaskChan")
				continue
			}

			if len(runTasks) == 0 {
				time.Sleep(time.Second * 30)
			}

			for i := range runTasks {
				if runTasks[i].ScanSubTaskID > 0 {
					out <- runTasks[i]
				}
			}
			s.Log.Info().Int("taskCnt", len(runTasks)).Msg("GenScanTaskChan")
		}
	}()

	return out
}

func (s *Detector) GetImageData(ctx context.Context, imageUniqueID uint64) (*imagesecModel.ImageWithCorrelateData2, error) {
	data, err := s.imageDataSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageUniqueID:   imageUniqueID,
		VulnEnable:      true,
		MalwareEnable:   true,
		EnvEnable:       true,
		PkgEnable:       true,
		LicenseEnable:   true,
		SensitiveEnable: true,
		WebshellEnable:  true,
		ContainerEnable: true,
		ImageInReg:      true,
		TrustedEnable:   true,
		BaseImageEnable: true,
		RegistryEnable:  true,
		NodeInfoEnable:  true,
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
		s.Log.Err(err).Int64("subtaskID", subtaskID).
			Msg("UpdateDetectSubTask")
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
		s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateTask")

		return err
	}
	return err
}

func (s *Detector) UpdateDetectTaskFinished(ctx context.Context) error {

	tasks, _, err := s.detectTaskDal.SearchDetectTask(ctx, imagesecModel.SearchTaskParam{
		ScanStatus: []int64{imagesecModel.TaskStatusInprogress},
		Filter:     imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiled("priority").SetSortDesc(),
	})

	if err != nil {
		s.Log.Err(err).Msg("UpdateDetectTaskFinished Detector SearchScanTask")
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
			s.Log.Err(err).Msg("GroupScanSubtask")
			return err
		}

		if group.DetectFinished+group.Failed >= group.All {
			// 即使删除了子任务，这里也不会卡住扫描任务
			_ = s.updateScanSubtask(ctx, task.ScanSubTaskID, imagesecModel.TaskStatusDetectFinished)

			if err := s.detectTaskDal.UpdateDetectTask(ctx, imagesecModel.UpdateTaskParam{
				ID:      task.ID,
				Updater: updater,
			}); err != nil {
				s.Log.Err(err).Msg("UpdateScanTask")
				return err
			}
			s.Log.Info().Int64("taskID", task.ID).
				Msg("finished detect")
			continue
		}

		s.Log.Info().Int64("taskID", task.ID).
			Msg("UpdateDetectTaskFinished Detector not finished")
	}
	return nil
}

func (s *Detector) ContinueUpdateImage(ctx context.Context) {
	for up := range s.updateImageChan {
		s.Log.Debug().Uint64("imageUniqueID", up.ImageUniqueID).
			Msg("UpdateImage get a image")

		// 解决主从同步
		// if time.Now().UnixMilli()-up.CreateAt < consts.DefaultSlaveDelay {
		// 	time.Sleep(consts.DefaultSlaveDelay * time.Millisecond)
		// }
		brief, err := s.detectResultDal.SearchDetectBrief(ctx, imagesecModel.SearchDetectBriefParam{
			ImageUniqueID: up.ImageUniqueID,
		})
		if err != nil {
			s.Log.Err(err).Uint64("ImageUniqueID", up.ImageUniqueID).
				Msg("UpdateImage SearchDetectBrief")
			continue
		}
		image, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
			ImageFromType: up.ImageFromType,
			UniqueId:      up.ImageUniqueID,
		})

		if err != nil {
			s.Log.Err(err).Uint64("ImageUniqueID", up.ImageUniqueID).
				Msg("UpdateImage SearchImage")
			continue
		}
		if len(image) == 0 {
			s.Log.Info().Uint64("ImageUniqueID", up.ImageUniqueID).
				Msg("not find image")
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
			s.Log.Debug().Uint64("imageUniqueID", up.ImageUniqueID).
				Msg("finished image changed and UpdateImage")

			updater := map[string]interface{}{"flag": flag, "policy_unique_id": policyUniqueStr}
			if err := s.imageDal.UpdateImage(ctx, imagesecModel.UpdateImageParam{
				UniqueID: up.ImageUniqueID,
				Updater:  updater,
			}); err != nil {
				s.Log.Err(err).Uint64("ImageUniqueID", up.ImageUniqueID).
					Msg("UpdateImage")
				continue
			}
		}
	}
}

func (s *Detector) AddDetectTaskEveryDay(ctx context.Context) error {
	if !s.addDetectTaskEveryDay {
		s.Log.Info().Msg("do not add detect task everyday")
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
					nil,
				); err != nil {
					s.Log.Err(err).Msg("AddDetectTaskEveryDay")
				}
				s.Log.Info().Msg("AddDetectTaskEveryDay")
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
		"updated_at": time.Now().Unix(),
		"status":     imagesecModel.TaskStatusDetectFinished,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusDetectFinished),
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
		s.Log.Err(err).Int64("subtaskID", scanSubtaskID).Interface("updater", updater).
			Msg("detect image bug update scan subtask error")
		return err
	}
	s.Log.Debug().Int64("subtaskID", scanSubtaskID).Interface("statusStr", updater["status_str"]).
		Msg("detect image finished and update scan subtask")
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
