package libimagetask

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm/clause"
	"k8s.io/apimachinery/pkg/util/rand"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type RegImageScanQueue struct {
	ScanTaskDal        imagesecStore.ScanTaskDal
	ScanResultDal      imagesecStore.ScanResultDal
	ImageSrv           types.ImageService
	updateSubtaskChan  chan types.UpdateSubTask
	scanInstanceDal    imagesecStore.ScanInstanceDal
	scanImageConfigDal imagesecStore.ScanImageConfigDal
	sensitiveRuleDal   imagesecStore.SensitiveRuleDal
	dbMetaDal          imagesecStore.ScanDbMetaDal
	Config             ScanConfig
	Log                *scannerUtils.LogEvent
}

type ScanConfig struct {
	MaxProTask       int64
	MaxProSubtaskPer int64
	MalWareScanAll   bool // 扫描病毒时是否扫描全部文件
}

func (s *RegImageScanQueue) GenUpdateSubtaskChan(ctx context.Context) chan types.UpdateSubTask {
	return s.updateSubtaskChan
}

func (s *RegImageScanQueue) updateSubtask(ctx context.Context) {

	for up := range s.updateSubtaskChan {
		if up.RetryCnt > consts.DefaultMaxRetryCount {
			s.Log.Info().Int64("subtaskID", up.SubtaskID).
				Msg("UpdateScanSubtask exceed max retry count")
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
			updater["scan_uuid"] = up.ScanUUID
		}
		// 直接使用缓存
		if up.Status == imagesecModel.TaskStatusDetectFinished {
			updater["finished_at"] = time.Now().UnixMilli() + rand.Int63nRange(2000, 5000)
			updater["started_at"] = time.Now().UnixMilli()
		}

		param := imagesecModel.UpdateTaskParam{
			ID:      up.SubtaskID,
			Updater: updater,
		}
		if up.Status > 0 {
			param.Where = fmt.Sprintf("status < %d", up.Status)
		}

		if err := s.ScanTaskDal.UpdateScanSubtask(ctx, param); err != nil {
			s.Log.Err(err).Int64("subtaskID", up.SubtaskID).
				Interface("updater", updater).
				Msg("UpdateScanSubtask")

			up.RetryCnt++
			go func() { s.updateSubtaskChan <- up }()
			continue
		}
		s.Log.Debug().Int64("subtaskID", up.SubtaskID).
			Interface("statusStr", updater["status_str"]).
			Msg("UpdateScanSubtask succeed")
	}
}

func (s *RegImageScanQueue) GenTaskChan(ctx context.Context) chan *imagesecModel.ImageScanTask {
	out := make(chan *imagesecModel.ImageScanTask, 1)

	go func() {
		defer func() {
			if err := recover(); err != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("RegImageScanQueue recover")
			}
		}()

		defer close(out)

		ticker := time.NewTicker(time.Second * 5)
		defer ticker.Stop()

		statusOrder := clause.OrderByColumn{
			Column: clause.Column{Name: "status"},
			Desc:   false,
		}
		idOrder := clause.OrderByColumn{
			Column: clause.Column{Name: "id"},
			Desc:   false,
		}

		filter := &imagesecModel.Filter{Limit: s.Config.MaxProTask, OrderByColumns: []clause.OrderByColumn{statusOrder, idOrder}}

		for {
			<-ticker.C
			runTask, cnt, err := s.ScanTaskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				ImageFromType: imagesecModel.ImageFromRegistry,
				ScanStatus:    []int64{imagesecModel.TaskStatusInprogress},
				Filter:        filter,
			})
			if err != nil {
				time.Sleep(time.Minute)
				s.Log.Err(err).Msg("find inprogress scan runTask")
				continue
			}
			s.Log.Debug().Int64("runningTaskCnt", cnt).Msg("find registry image scan runTask")

			for i := range runTask {
				out <- runTask[i]
			}

			if cnt >= s.Config.MaxProTask {
				s.Log.Info().Int64("runningTaskCnt", cnt).Msg("has max running task")
				continue
			}

			pending, cnt, err := s.ScanTaskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				ImageFromType: imagesecModel.ImageFromRegistry,
				ScanStatus:    []int64{imagesecModel.TaskStatusPending},
				Filter:        filter.SetLimit(util.MinInt64(s.Config.MaxProTask, s.Config.MaxProTask-int64(len(runTask)))),
			})
			if err != nil {
				time.Sleep(time.Minute)
				s.Log.Err(err).Msg("find inprogress scan pending")
				continue
			}
			s.Log.Debug().Int64("pendTaskCnt", cnt).Msg("find registry image scan pending")

			for i := range pending {
				out <- pending[i]
			}

			if len(pending) == 0 {
				time.Sleep(time.Second * 20)
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
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("RegImageScanQueue recover")
			}
		}()
		defer close(subtaskChan)

		taskChan := s.GenTaskChan(ctx)

		for task := range taskChan {
			s.Log.Info().Int64("taskID", task.ID).Msg("get a scan task")
			if err := s.SearchSubtaskAndSendToChan(ctx, task, subtaskChan); err != nil {
				s.Log.Err(err).Interface("task", task).Msg("SearchSubtaskAndSendToChan")
				continue
			}
		}
	}()

	return subtaskChan
}

func (s *RegImageScanQueue) SearchSubtaskAndSendToChan(ctx context.Context, task *imagesecModel.ImageScanTask,
	subtaskChan chan imagesecTypes.ScanSubTask) error {

	instance, err := s.scanInstanceDal.SearchScannerInfo(ctx, imagesecModel.ScanInstanceParam{})
	if err != nil {
		s.Log.Err(err).Msg("SearchNodeInfo")
		return err
	}

	filter := imagesecModel.EmptyFilter().SetSortDesc().SetSortFiled("status")

	for i := range instance {
		no := instance[i]
		s.Log.Debug().Str("ClusterName", no.ClusterName).Msg("find instance")
		subtaskParam := imagesecModel.SearchTaskParam{
			TaskID:       task.ID,
			NodeUniqueID: uint64(no.ID),
			// TaskStatusInprogress 可能发送失败
			ScanStatus:      []int64{imagesecModel.TaskStatusPending, imagesecModel.TaskStatusInprogress, imagesecModel.TaskStatusSendFinished},
			IsSearchSubtask: true,
			// 这里一次不取更多，是因为前端更新 task 任务之后需要快速感知
			Filter: filter.SetLimit(s.Config.MaxProSubtaskPer),
		}

		subtask, _, err := s.ScanTaskDal.SearchScanSubtask(ctx, subtaskParam)
		if err != nil {
			s.Log.Err(err).Int64("taskID", task.ID).Msg("SearchScanSubtask")
			continue
		}

		if len(subtask) > 0 {
			// 已开始发送子任务时才更新任务已开始
			// 如果任务开始了，但是扫描的有其他子任务在执行，不能执行该任务下的子任务，这时不应该认为该任务已开始
			if err := s.UpdateTaskInprogress(ctx, task.ID); err != nil {
				s.Log.Err(err).Int64("taskID", task.ID).Msg("start task")
				continue
			}
		}
		var sendSubtask int64
		for j := range subtask {
			sub := subtask[j]
			imageData, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
				ImageFromType:      imagesecModel.ImageFromRegistry,
				ImageUniqueID:      sub.ImageUniqueID,
				RegistryEnable:     true,
				ScanInstanceEnable: true,
			})
			if err != nil {
				s.Log.Err(err).Int64("taskID", task.ID).Uint64("ImageUniqueID",
					sub.ImageUniqueID).Msg("GetImageCorrelateData")

				up := types.UpdateSubTask{
					SubtaskID: sub.ID,
					Status:    imagesecModel.TaskStatusFailed,
					Err:       err,
					Reason:    imagesecModel.TaskFailedReasonNotFindImage,
					CreatedAt: time.Now().UnixMilli(),
				}

				go func() { s.updateSubtaskChan <- up }()

				continue
			}

			if imageData.ScanInstance == nil {
				e := fmt.Errorf("not get scan instance info:%d", sub.ImageUniqueID)

				s.Log.Err(e).Uint64("ImageUniqueID", sub.ImageUniqueID).Msg("not get instance info")

				up := types.UpdateSubTask{
					SubtaskID: sub.ID,
					Status:    imagesecModel.TaskStatusFailed,
					Err:       e,
					Reason:    imagesecModel.TaskFailedReasonNotFindScanner,
					CreatedAt: time.Now().UnixMilli(),
				}

				go func() { s.updateSubtaskChan <- up }()

				continue
			}

			// 未升级的集群也要开始任务,然后超时失败，不然可能会一直卡住,结束不了，但是就会存在一个问题：老集群和新版本调度执行的任务不同
			if !util.ThanVersion(imageData.ToImageBaseResponse().ScanInsVer, consts.ScannerVersion220) {
				// 对于老版本的扫描器，只能发送一次，不然会一直更新扫描开始时间
				if sub.StatusStr == imagesecModel.TaskStatusPendingStr {
					up := types.UpdateSubTask{
						SubtaskID: sub.ID,
						Status:    imagesecModel.TaskStatusSendFinished,
						CreatedAt: time.Now().Unix(),
					}

					go func() { s.updateSubtaskChan <- up }()
				}
				continue
			}
			if sub.ScanUUID == imageData.ScanInstance.ScannerPodID && sub.StatusStr == imagesecModel.TaskStatusSendFinishedStr {
				sendSubtask++
				// 已经发送过，不再发送
				// 如果pod重启，就会再一次发送
				s.Log.Debug().Str("scanInstance", no.LogStr()).Str("subtask", sub.LogInfo()).Msg("subtask has being sent")
				if sendSubtask >= s.Config.MaxProSubtaskPer {
					// 如果任务队列满了，就休眠一段时间，减少数据库压力,
					s.Log.Info().Str("scanInstance", no.LogStr()).Int64("cnt", sendSubtask).Msg("has subtask running")
					time.Sleep(time.Second * 30)
				}
				continue
			}

			typesSubTask, err2 := s.BuildScanTask(ctx, sub, imageData)
			if err2 != nil {
				up := types.UpdateSubTask{
					SubtaskID: sub.ID,
					Status:    imagesecModel.TaskStatusFailed,
					Err:       err2,
					Reason:    imagesecModel.TaskFailedReasonSendNode,
					CreatedAt: time.Now().Unix(),
				}

				go func() { s.updateSubtaskChan <- up }()
				continue
			}

			go func() {
				up := types.UpdateSubTask{
					SubtaskID: sub.ID,
					Status:    imagesecModel.TaskStatusInprogress,
					CreatedAt: time.Now().Unix(),
				}
				s.updateSubtaskChan <- up
			}()

			subtaskChan <- typesSubTask

			s.Log.Debug().Int64("subtask", sub.ID).
				Int64("taskID", sub.TaskID).
				Interface("RegInfo", typesSubTask.RegInfo).
				Interface("ScanInstance", typesSubTask.ScanInstance).
				Msg("get subtask and send to chan")

			s.Log.Info().Int64("subtask", sub.ID).
				Int64("taskID", sub.TaskID).
				Str("RegInfo", typesSubTask.RegInfo.Name).Str("ScannerCluster", typesSubTask.ScanInstance.ClusterName).
				Msg("get subtask and send to chan")
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
	if err := s.ScanTaskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
		ID:      taskID,
		Updater: updater,
		Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusInprogress),
	}); err != nil {
		s.Log.Err(err).Interface("updater", updater).
			Int64("taskID", taskID).Msg("UpdateTaskInprogress")
		return err
	}
	s.Log.Debug().Interface("updater", updater).
		Int64("taskID", taskID).Msg("UpdateTaskInprogress")
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
		s.Log.Err(err).Msg("ScanImageQueue SearchAllSensitiveRule")
		return ans
	}
	for i := range rule {
		ans = append(ans, rule[i].Value)
	}
	return ans
}

func NewScanRegImageQueue(
	nodeScanTaskDal imagesecStore.ScanTaskDal,
	nodeImageSrv types.ImageService,
	instanceDal imagesecStore.ScanInstanceDal,
	sensitiveRuleDal imagesecStore.SensitiveRuleDal,
	scanImageConfigDal imagesecStore.ScanImageConfigDal,
	scanResultDal imagesecStore.ScanResultDal,
	dbMetaDal imagesecStore.ScanDbMetaDal,
) *RegImageScanQueue {
	scanQueue := &RegImageScanQueue{
		ScanTaskDal:        nodeScanTaskDal,
		ImageSrv:           nodeImageSrv,
		updateSubtaskChan:  make(chan types.UpdateSubTask),
		scanInstanceDal:    instanceDal,
		sensitiveRuleDal:   sensitiveRuleDal,
		scanImageConfigDal: scanImageConfigDal,
		ScanResultDal:      scanResultDal,
		dbMetaDal:          dbMetaDal,
		Config: ScanConfig{
			MaxProTask:       consts.MaxInprogressTask,
			MaxProSubtaskPer: consts.MaxInprogressSubtaskPerNode,
			MalWareScanAll:   os.Getenv("SCAN_ALL") == consts.TrueString,
		},
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("RegImageScanQueue"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		),
	}
	if global.ScannerOpts.ParallelTaskNum > 0 {
		scanQueue.Config.MaxProTask = int64(global.ScannerOpts.ParallelTaskNum)
	}

	if global.ScannerOpts.ParallelSubTaskNum > 0 {
		scanQueue.Config.MaxProSubtaskPer = int64(global.ScannerOpts.ParallelSubTaskNum)
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("Stack", string(debug.Stack())).Msg("updateSubtask")
			}
		}()

		scanQueue.updateSubtask(context.Background())
	}()

	return scanQueue
}
