package libimagetask

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type RegImageScanQueue struct {
	nodeScanTaskDal           imagesecStore.ScanTaskDal
	nodeImageSrv              types.ImageService
	updateSubtaskChan         chan types.UpdateSubTask
	scanInstanceDal           imagesecStore.ScanInstanceDal
	scanImageConfigDal        imagesecStore.ScanImageConfigDal
	sensitiveRuleDal          imagesecStore.SensitiveRuleDal
	maxProgressTask           int64
	maxProgressSubtaskPerNode int64
}

func (s *RegImageScanQueue) GenUpdateSubtaskChan(ctx context.Context) chan types.UpdateSubTask {
	return s.updateSubtaskChan
}

func (s *RegImageScanQueue) updateSubtask(ctx context.Context) {

	for up := range s.updateSubtaskChan {
		if up.RetryCnt > consts.DefaultMaxRetryCount {
			logging.Get().Info().Str("module", "imagescan").Int64("subtaskID", up.SubtaskID).
				Msg("RegImageScanQueue UpdateScanSubtask exceed max retry count")
			continue
		}

		updater := map[string]interface{}{
			"status":     up.Status,
			"status_str": imagesecModel.ScanStatusToStr(up.Status),
		}
		if up.Err != nil {
			updater["status"] = imagesecModel.TaskStatusFailed
			updater["status_str"] = imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusFailed)
			updater["msg"] = up.Err.Error()
			updater["reason"] = up.Reason
			updater["finished_at"] = time.Now().UnixMilli()
		}
		if up.Status == imagesecModel.TaskStatusSendFinished {
			updater["started_at"] = time.Now().UnixMilli()
		}

		param := imagesecModel.UpdateTaskParam{
			ID:      up.SubtaskID,
			Updater: updater,
		}
		if up.Status != imagesecModel.TaskStatusFailed {
			param.Where = fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause)
		}

		if err := s.nodeScanTaskDal.UpdateScanSubtask(ctx, param); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Int64("subtaskID", up.SubtaskID).
				Interface("updater", updater).
				Msg("RegImageScanQueue UpdateScanSubtask")

			up.RetryCnt++
			go func() { s.updateSubtaskChan <- up }()
			continue
		}
		logging.Get().Debug().Str("module", "imagescan").Int64("subtaskID", up.SubtaskID).
			Interface("statusStr", updater["status_str"]).
			Msg("RegImageScanQueue UpdateScanSubtask succeed")
	}
}

func (s *RegImageScanQueue) GenTaskChan(ctx context.Context) chan *imagesecModel.ImageScanTask {
	out := make(chan *imagesecModel.ImageScanTask, 1)

	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Str("module", "imagescan").Stack().Msg("RegImageScanQueue recover")
			}
		}()

		defer close(out)

		ticker := time.NewTicker(time.Second * 5)
		defer ticker.Stop()

		for {
			<-ticker.C
			task, inCnt, err := s.nodeScanTaskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				ImageFromType: imagesecModel.ImageFromRegistry,
				ScanStatusStr: []string{imagesecModel.TaskStatusInprogressStr},
				Filter:        &model.Filter{Limit: s.maxProgressTask, SortFiled: "id", SortBy: consts.SortByAsc},
			})
			if err != nil {
				ticker.Reset(time.Minute)
				logging.Get().Err(err).Str("module", "imagescan").
					Msg("RegImageScanQueue find inprogress scan task")
				continue
			}
			logging.Get().Debug().Str("module", "imagescan").Int64("inCnt", inCnt).
				Msg("RegImageScanQueue find inprogress task")

			if len(task) == 0 || inCnt < s.maxProgressTask {
				pending, pendCnt, err := s.nodeScanTaskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
					ImageFromType: imagesecModel.ImageFromRegistry,
					ScanStatusStr: []string{imagesecModel.TaskStatusPendingStr},
					Filter:        &model.Filter{Limit: s.maxProgressTask - inCnt, SortFiled: "status", SortBy: consts.SortByDesc},
				})
				if err != nil {
					logging.Get().Err(err).Str("module", "imagescan").Msg("RegImageScanQueue find inprogress scan task")
					continue
				}
				logging.Get().Debug().Str("module", "imagescan").Int64("pendingTaskCnt", pendCnt).
					Msg("RegImageScanQueue search pending task")

				task = append(task, pending...)
			}
			logging.Get().Info().Str("module", "imagescan").Int("taskCnt", len(task)).
				Msg("RegImageScanQueue find scan task")

			for i := range task {
				out <- task[i]
			}

			if len(task) == 0 {
				ticker.Reset(time.Second * 20)
			}
		}
	}()
	return out
}

func (s *RegImageScanQueue) GenSubtaskChan(ctx context.Context) chan imagesecTypes.ScanSubTask {

	subtaskChan := make(chan imagesecTypes.ScanSubTask)

	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Stack().Msg("RegImageScanQueue recover")
			}
		}()
		defer close(subtaskChan)

		taskChan := s.GenTaskChan(ctx)

		for task := range taskChan {
			logging.Get().Info().Str("module", "imagescan").Int64("taskID", task.ID).
				Msg("RegImageScanQueue get a scan task")

			if err := s.UpdateTaskInprogress(ctx, task.ID); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", task.ID).
					Msg("RegImageScanQueue start task")
				continue
			}

			if err := s.SearchSubtaskAndSendToChan(ctx, task, subtaskChan); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Interface("task", task).
					Msg("RegImageScanQueue SearchSubtaskAndSendToChan")
				continue
			}
			logging.Get().Info().Str("module", "imagescan").Int64("taskID", task.ID).
				Msg("RegImageScanQueue send subtask finish")
		}
	}()

	return subtaskChan
}

func (s *RegImageScanQueue) SearchSubtaskAndSendToChan(ctx context.Context, task *imagesecModel.ImageScanTask,
	subtaskChan chan imagesecTypes.ScanSubTask) error {

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	instance, err := s.scanInstanceDal.SearchScannerInfo(ctx, imagesecModel.ScanInstanceParam{})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("RegImageScanQueue SearchNodeInfo")
		return err
	}

	config, err := s.scanImageConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeRegScanImage)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("RegImageScanQueue GetScanImageConfig")
		return err
	}

	for i := range instance {
		no := instance[i]
		logging.Get().Debug().Str("module", "imagescan").Str("scannerInstance", no.ScannerInstance).
			Msg("RegImageScanQueue find instance")

		_, sendSubtask, err := s.nodeScanTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			NodeUniqueID:    uint64(no.ID),
			ScanStatusStr:   []string{imagesecModel.TaskStatusInprogressStr},
			IsSearchSubtask: true,
			Filter:          model.EmptyFilter().SetLimit(1),
		})
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", task.ID).
				Msg("RegImageScanQueue SearchScanSubtask")
			return err
		}
		maxed := false
		if sendSubtask >= s.maxProgressSubtaskPerNode {
			maxed = true
			logging.Get().Debug().Str("module", "imagescan").Str("scannerInstance", no.ScannerInstance).
				Int64("runningTask", sendSubtask).
				Msg("RegImageScanQueue the instance has scan task scanning")
		}
		subtaskParam := imagesecModel.SearchTaskParam{
			TaskID:          task.ID,
			NodeUniqueID:    uint64(no.ID),
			ScanStatus:      []int64{imagesecModel.TaskStatusPending},
			IsSearchSubtask: true,
			// 这里一次不取更多，是因为前端更新 task 任务之后需要快速感知
			Filter: model.EmptyFilter().SetSortAsc().SetSortFiledByID().
				SetLimit(util.MinInt64(consts.DefaultSendSubtaskBatchSize, s.maxProgressSubtaskPerNode-sendSubtask)),
		}
		// 防止子集群重启动
		if maxed {
			// 防止持续发
			<-ticker.C
			subtaskParam.ScanStatus = []int64{imagesecModel.TaskStatusSendFinished, imagesecModel.TaskStatusInprogress}
		}

		subtask, _, err := s.nodeScanTaskDal.SearchScanSubtask(ctx, subtaskParam)
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", task.ID).
				Msg("RegImageScanQueue SearchScanSubtask")
			continue
		}

		for j := range subtask {
			imageDate, err := s.nodeImageSrv.GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
				ImageFromType:      imagesecModel.ImageFromRegistry,
				ImageUniqueID:      subtask[j].ImageUniqueID,
				RegistryEnable:     true,
				ScanInstanceEnable: true,
			})
			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", task.ID).Uint64("ImageUniqueID",
					subtask[0].ImageUniqueID).Msg("RegImageScanQueue GetImageCorrelateData")

				up := types.UpdateSubTask{
					SubtaskID: subtask[j].ID,
					Status:    imagesecModel.TaskStatusFailed,
					Err:       err,
					Reason:    imagesecModel.TaskFailedReasonNotFindImage,
					CreatedAt: time.Now().Unix(),
				}

				go func() { s.updateSubtaskChan <- up }()

				continue
			}

			if imageDate.ScanInstance == nil {
				e := fmt.Errorf("not get scan instance info:%d", subtask[j].ImageUniqueID)

				logging.Get().Err(e).Uint64("ImageUniqueID", subtask[j].ImageUniqueID).Msg("RegImageScanQueue not get instance info")

				up := types.UpdateSubTask{
					SubtaskID: subtask[j].ID,
					Status:    imagesecModel.TaskStatusFailed,
					Err:       e,
					Reason:    imagesecModel.TaskFailedReasonNotFindScanner,
					CreatedAt: time.Now().Unix(),
				}

				go func() { s.updateSubtaskChan <- up }()

				continue
			}

			// 未升级的集群也要开始任务,然后超时失败，不然可能会一直卡住
			if !util.ThanVersion(imageDate.ToImageBaseResponse().ScanInsVer, consts.ScannerVersion220) {
				up := types.UpdateSubTask{
					SubtaskID: subtask[j].ID,
					Status:    imagesecModel.TaskStatusInprogress,
					CreatedAt: time.Now().Unix(),
				}

				go func() { s.updateSubtaskChan <- up }()

				continue
			}

			// 查询配置
			// 为啥要实时查呢，因为配置更新之后要快速感知
			typesSubTask := modelToType(subtask[j], imageDate, s.SearchAllSensitiveRule(ctx), config.ImageScanConfig)

			subtaskChan <- typesSubTask

			logging.Get().Debug().Str("module", "imagescan").Int64("subtask", subtask[j].ID).
				Int64("taskID", subtask[j].TaskID).
				Interface("RegInfo", typesSubTask.RegInfo).
				Interface("ScanInstance", typesSubTask.ScanInstance).
				Msg("RegImageScanQueue get subtask and send to chan")

			logging.Get().Info().Str("module", "imagescan").Int64("subtask", subtask[j].ID).
				Int64("taskID", subtask[j].TaskID).
				Str("RegInfo", typesSubTask.RegInfo.Name).Str("ScannerInstance", typesSubTask.ScanInstance.ScannerInstance).
				Msg("RegImageScanQueue get subtask and send to chan")
		}
	}

	return nil
}

func (s *RegImageScanQueue) UpdateTaskInprogress(ctx context.Context, taskID int64) error {
	updater := map[string]interface{}{
		"status":     imagesecModel.TaskStatusInprogress,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusInprogress),
		"started_at": time.Now().UnixMilli(),
	}
	if err := s.nodeScanTaskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
		ID:      taskID,
		Updater: updater,
		Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusInprogress),
	}); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("updater", updater).
			Int64("taskID", taskID).Msg("UpdateTaskInprogress")
		return err
	}
	logging.Get().Debug().Str("module", "imagescan").Interface("updater", updater).
		Int64("taskID", taskID).Msg("RegImageScanQueue UpdateTaskInprogress")
	return nil
}

func (s *RegImageScanQueue) SearchAllSensitiveRule(ctx context.Context) []string {
	ans := make([]string, 0)
	rule, _, err := s.sensitiveRuleDal.SearchSensitiveRule(ctx, imagesecModel.SearchSensitiveRuleParam{
		RuleType:  imagesecModel.SensitiveRuleTypeFilename,
		Enable:    consts.TrueString,
		IsDefault: consts.FalseString,
		Filed:     []string{"id", "value"},
	})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("ScanImageQueue SearchAllSensitiveRule")
		return ans
	}
	for i := range rule {
		ans = append(ans, rule[i].Value)
	}
	return ans
}

func modelToType(
	subtask *imagesecModel.ImageScanSubTask,
	data *imagesecModel.ImageWithCorrelateData2,
	ses []string,
	config *imagesecModel.ImageScanConfig,
) imagesecTypes.ScanSubTask {
	sub := imagesecTypes.ScanSubTask{
		TaskID:    subtask.TaskID,
		SubTaskID: subtask.ID,
		RegImageMeta: imagesecTypes.ScanImageMeta{
			ImageUUID: data.Image.ImageUUID,
			UniqueID:  data.Image.UniqueID,
			Host:      data.Image.Host,
			Digest:    data.Image.Digest,
			Repo:      data.Image.Repo,
			Tag:       data.Image.Tag,
		},
		SensitiveRules: ses,
	}
	if config != nil {
		sub.ScanTimeout = config.ScanTimeout
		sub.DeepScan = config.DeepScan
	}

	if data.ScanInstance != nil {
		sub.ScanInstance = imagesecTypes.ScanInstance{
			ClusterKey:      data.ScanInstance.ClusterKey,
			ClusterName:     data.ScanInstance.ClusterName,
			ScannerPodID:    data.ScanInstance.ScannerPodID,
			ScannerInstance: data.ScanInstance.ScannerInstance,
			ScannerVersion:  data.ScanInstance.ScannerVersion,
		}
	}
	if data.Registry != nil {
		sub.RegInfo = imagesecTypes.RegInfo{
			RegID:    data.Registry.ID,
			Url:      data.Registry.Url,
			Username: data.Registry.Username,
			Password: data.Registry.PasswordString,
		}
	}

	sub.UniqueID = sub.GenUniqueID()
	return sub
}

func NewScanLibImageQueue(
	nodeScanTaskDal imagesecStore.ScanTaskDal,
	nodeImageSrv types.ImageService,
	instanceDal imagesecStore.ScanInstanceDal,
	sensitiveRuleDal imagesecStore.SensitiveRuleDal,
	scanImageConfigDal imagesecStore.ScanImageConfigDal,
) *RegImageScanQueue {
	nodeQueue := &RegImageScanQueue{
		nodeScanTaskDal:           nodeScanTaskDal,
		nodeImageSrv:              nodeImageSrv,
		updateSubtaskChan:         make(chan types.UpdateSubTask),
		scanInstanceDal:           instanceDal,
		sensitiveRuleDal:          sensitiveRuleDal,
		scanImageConfigDal:        scanImageConfigDal,
		maxProgressTask:           consts.MaxInprogressTask,
		maxProgressSubtaskPerNode: consts.MaxInprogressSubtaskPerNode,
	}

	cnt1, err := strconv.ParseInt(os.Getenv("MAX_PROGRESS_TASK"), 10, 64)
	if err != nil && cnt1 > 0 {
		nodeQueue.maxProgressTask = cnt1
	}

	cnt2, err := strconv.ParseInt(os.Getenv("MAX_PROGRESS_SUBTASK"), 10, 64)
	if err != nil && cnt2 > 0 {
		nodeQueue.maxProgressSubtaskPerNode = cnt2
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("updateSubtask")
			}
		}()

		nodeQueue.updateSubtask(context.Background())
	}()

	return nodeQueue
}
