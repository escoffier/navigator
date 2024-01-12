package libimagetask

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm/clause"

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
	ScanTaskDal               imagesecStore.ScanTaskDal
	ScanResultDal             imagesecStore.ScanResultDal
	ImageSrv                  types.ImageService
	updateSubtaskChan         chan types.UpdateSubTask
	scanInstanceDal           imagesecStore.ScanInstanceDal
	scanImageConfigDal        imagesecStore.ScanImageConfigDal
	sensitiveRuleDal          imagesecStore.SensitiveRuleDal
	maxProgressTask           int64
	maxProgressSubtaskPerNode int64
	Log                       *scannerUtils.LogEvent
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

		param := imagesecModel.UpdateTaskParam{
			ID:      up.SubtaskID,
			Updater: updater,
		}
		if up.Status != imagesecModel.TaskStatusFailed {
			param.Where = fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause)
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

		filter := &imagesecModel.Filter{Limit: s.maxProgressTask, OrderByColumns: []clause.OrderByColumn{statusOrder, idOrder}}

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

			if cnt >= s.maxProgressTask {
				s.Log.Info().Int64("runningTaskCnt", cnt).Msg("has max running task")
				continue
			}

			pending, cnt, err := s.ScanTaskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				ImageFromType: imagesecModel.ImageFromRegistry,
				ScanStatus:    []int64{imagesecModel.TaskStatusPending},
				Filter:        filter.SetLimit(util.MinInt64(s.maxProgressTask, s.maxProgressTask-int64(len(runTask)))),
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

	config, err := s.scanImageConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeRegScanImage)
	if err != nil {
		s.Log.Err(err).Msg("GetScanImageConfig")
		return err
	}
	filter := imagesecModel.EmptyFilter().SetSortDesc().SetSortFiled("status")

	for i := range instance {
		no := instance[i]
		s.Log.Debug().Str("ClusterName", no.ClusterName).Msg("find instance")
		subtaskParam := imagesecModel.SearchTaskParam{
			TaskID:       task.ID,
			NodeUniqueID: uint64(no.ID),
			// TaskStatusInprogress 但是可能发送失败
			ScanStatus:      []int64{imagesecModel.TaskStatusPending, imagesecModel.TaskStatusInprogress, imagesecModel.TaskStatusSendFinished},
			IsSearchSubtask: true,
			// 这里一次不取更多，是因为前端更新 task 任务之后需要快速感知
			Filter: filter.SetLimit(s.maxProgressSubtaskPerNode),
		}

		subtask, _, err := s.ScanTaskDal.SearchScanSubtask(ctx, subtaskParam)
		if err != nil {
			s.Log.Err(err).Int64("taskID", task.ID).Msg("SearchScanSubtask")
			continue
		}

		if len(subtask) > 0 {
			// 已开始发送子任务时才更新任务已开始
			// 如果任务1开始了，但是扫描的有其他子任务在执行，不能执行该任务下的子任务，这时不应该认为该任务已开始
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
					CreatedAt: time.Now().Unix(),
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
					CreatedAt: time.Now().Unix(),
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
				s.Log.Info().Str("scanInstance", no.LogStr()).Str("subtask", sub.LogInfo()).Msg("subtask has being send")
				if sendSubtask >= s.maxProgressSubtaskPerNode {
					// 如果任务队列满了，就休眠一段时间，减少数据库压力,
					s.Log.Info().Str("scanInstance", no.LogStr()).Int64("cnt", sendSubtask).Msg("has subtask running")
					time.Sleep(time.Second * 30)
				}
				continue
			}

			// 查询缓存
			imageLayer := make([]string, 0)
			for _, ly := range imageData.Image.Layer {
				imageLayer = append(imageLayer, ly.Digest)
			}
			// 加缓存
			cacheLayer, _ := s.ScanResultDal.SearchScanLayerData(ctx, imagesecModel.SearchScanLayerParam{Layers: imageLayer})
			// 查询配置
			// 为啥要实时查呢，因为配置更新之后要快速感知
			typesSubTask := modelToType(sub, imageData, s.SearchAllSensitiveRule(ctx), config.ImageScanConfig, cacheLayer)

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

func modelToType(
	subtask *imagesecModel.ImageScanSubTask,
	data *imagesecModel.ImageWithCorrelateData2,
	ses []string,
	config *imagesecModel.ImageScanConfig,
	cache []*imagesecModel.ScanLayerData,
) imagesecTypes.ScanSubTask {
	sub := imagesecTypes.ScanSubTask{
		TaskID:        subtask.TaskID,
		SubTaskID:     subtask.ID,
		NodeInfo:      imagesecTypes.NodeInfo{},
		NodeImageMeta: imagesecTypes.ImageMeta{},
		RegImageMeta: imagesecTypes.ScanImageMeta{
			ImageUUID: data.Image.ImageUUID,
			UniqueID:  data.Image.UniqueID,
			Host:      data.Image.Host,
			Digest:    data.Image.Digest,
			Repo:      data.Image.Repo,
			Tag:       data.Image.Tag,
		},
		ScanInstance:   imagesecTypes.ScanInstance{},
		RegInfo:        imagesecTypes.RegInfo{},
		SensitiveRules: ses,
		UniqueID:       "",
		ScanTimeout:    0,
		WebshellCache:  make(imagesecTypes.LayerInCache),
		LicenseCache:   make(imagesecTypes.LayerInCache),
		SensitiveCache: make(imagesecTypes.LayerInCache),
		MalwareCache:   make(imagesecTypes.LayerInCache),
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
			Name:     data.Registry.Name,
			RegID:    data.Registry.ID,
			Url:      data.Registry.Url,
			Username: data.Registry.Username,
			Password: data.Registry.PasswordString,
		}
	}

	sub.UniqueID = sub.GenUniqueID()
	// 加缓存
	// 加一个环境变量，便于测试
	if os.Getenv("SCAN_NOT_USE_CACHE") != consts.TrueString {
		for i := range cache {
			ca := cache[i]
			switch ca.Issue {
			case imagesecModel.WebshellCacheData:
				sub.WebshellCache[ca.Layer] = true
			case imagesecModel.MalwareCacheData:
				sub.MalwareCache[ca.Layer] = true
			case imagesecModel.SensitiveCacheData:
				sub.SensitiveCache[ca.Layer] = true
			case imagesecModel.LicenseCacheData:
				sub.LicenseCache[ca.Layer] = true
			}
		}
	}

	return sub
}

func NewScanRegImageQueue(
	nodeScanTaskDal imagesecStore.ScanTaskDal,
	nodeImageSrv types.ImageService,
	instanceDal imagesecStore.ScanInstanceDal,
	sensitiveRuleDal imagesecStore.SensitiveRuleDal,
	scanImageConfigDal imagesecStore.ScanImageConfigDal,
	scanResultDal imagesecStore.ScanResultDal,
) *RegImageScanQueue {
	nodeQueue := &RegImageScanQueue{
		ScanTaskDal:               nodeScanTaskDal,
		ImageSrv:                  nodeImageSrv,
		updateSubtaskChan:         make(chan types.UpdateSubTask),
		scanInstanceDal:           instanceDal,
		sensitiveRuleDal:          sensitiveRuleDal,
		scanImageConfigDal:        scanImageConfigDal,
		ScanResultDal:             scanResultDal,
		maxProgressTask:           consts.MaxInprogressTask,
		maxProgressSubtaskPerNode: consts.MaxInprogressSubtaskPerNode,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("RegImageScanQueue"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		),
	}
	if global.ScannerOpts.ParallelTaskNum > 0 {
		nodeQueue.maxProgressTask = int64(global.ScannerOpts.ParallelTaskNum)
	}

	if global.ScannerOpts.ParallelSubTaskNum > 0 {
		nodeQueue.maxProgressSubtaskPerNode = int64(global.ScannerOpts.ParallelSubTaskNum)
	}

	cnt1, err := strconv.ParseInt(os.Getenv("MAX_PROGRESS_TASK"), 10, 64)
	if err == nil && cnt1 > 0 {
		nodeQueue.maxProgressTask = cnt1
	}

	cnt2, err := strconv.ParseInt(os.Getenv("MAX_PROGRESS_SUBTASK"), 10, 64)
	if err == nil && cnt2 > 0 {
		nodeQueue.maxProgressSubtaskPerNode = cnt2
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("Stack", string(debug.Stack())).Msg("updateSubtask")
			}
		}()

		nodeQueue.updateSubtask(context.Background())
	}()

	return nodeQueue
}
