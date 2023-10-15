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

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	global2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type RegImageScanQueue struct {
	ScanTaskDal               imagesecStore.ScanTaskDal
	ImageSrv                  types.ImageService
	updateSubtaskChan         chan types.UpdateSubTask
	scanInstanceDal           imagesecStore.ScanInstanceDal
	scanImageConfigDal        imagesecStore.ScanImageConfigDal
	sensitiveRuleDal          imagesecStore.SensitiveRuleDal
	maxProgressTask           int64
	maxProgressSubtaskPerNode int64
	PodID                     string
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

		filter := &model.Filter{Limit: s.maxProgressTask, OrderByColumns: []clause.OrderByColumn{statusOrder, idOrder}}

		for {
			<-ticker.C
			task, cnt, err := s.ScanTaskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				ImageFromType: imagesecModel.ImageFromRegistry,
				ScanStatus:    []int64{imagesecModel.TaskStatusInprogress, imagesecModel.TaskStatusPending},
				Filter:        filter,
			})
			if err != nil {
				ticker.Reset(time.Minute)
				s.Log.Err(err).
					Msg("find inprogress scan task")
				continue
			}
			s.Log.Info().Int64("taskCnt", cnt).Msg("find registry image scan task")

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
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("RegImageScanQueue recover")
			}
		}()
		defer close(subtaskChan)

		taskChan := s.GenTaskChan(ctx)

		for task := range taskChan {
			s.Log.Info().Int64("taskID", task.ID).Msg("get a scan task")

			if err := s.UpdateTaskInprogress(ctx, task.ID); err != nil {
				s.Log.Err(err).Int64("taskID", task.ID).Msg("start task")
				continue
			}

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

	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

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

	for i := range instance {
		no := instance[i]
		s.Log.Debug().Str("ClusterName", no.ClusterName).
			Msg("find instance")
		// 查找当前扫描器在执行的所有子任务
		param := imagesecModel.SearchTaskParam{
			NodeUniqueID: uint64(no.ID),
			// 发送完成扫描过程中 Pod 重启，那就只能等超时失败了
			// 不能持续发送，因为任务可能重启动，扫描器不能对任务去重
			ScanStatus:      []int64{imagesecModel.TaskStatusSendFinished},
			IsSearchSubtask: true,
			Filter:          model.EmptyFilter().SetLimit(1),
		}

		_, sendSubtask, err := s.ScanTaskDal.SearchScanSubtask(ctx, param)
		if err != nil {
			s.Log.Err(err).Int64("taskID", task.ID).Msg("SearchScanSubtask")
			return err
		}
		if sendSubtask >= s.maxProgressSubtaskPerNode {
			// 缓一下
			<-ticker.C
			continue
		}

		subtaskParam := imagesecModel.SearchTaskParam{
			TaskID:       task.ID,
			NodeUniqueID: uint64(no.ID),
			// TaskStatusInprogress 但是可能发送失败
			// 对于执行中的子任务持续发送,防止子集群重启动
			// 扫描器会做去重处理，对于正在扫描的任务会忽略
			ScanStatus:      []int64{imagesecModel.TaskStatusPending, imagesecModel.TaskStatusInprogress},
			IsSearchSubtask: true,
			// 这里一次不取更多，是因为前端更新 task 任务之后需要快速感知
			Filter: model.EmptyFilter().SetSortAsc().SetSortFiled("status").SetLimit(s.maxProgressSubtaskPerNode - sendSubtask),
		}

		if s.PodID == "" {
			subtaskParam.ScanStatus = append(subtaskParam.ScanStatus, imagesecModel.TaskStatusSendFinished)
			s.PodID = global2.ScannerPodID
		}

		subtask, _, err := s.ScanTaskDal.SearchScanSubtask(ctx, subtaskParam)
		if err != nil {
			s.Log.Err(err).Int64("taskID", task.ID).
				Msg("SearchScanSubtask")
			continue
		}

		for j := range subtask {
			imageDate, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
				ImageFromType:      imagesecModel.ImageFromRegistry,
				ImageUniqueID:      subtask[j].ImageUniqueID,
				RegistryEnable:     true,
				ScanInstanceEnable: true,
			})
			if err != nil {
				s.Log.Err(err).Int64("taskID", task.ID).Uint64("ImageUniqueID",
					subtask[0].ImageUniqueID).Msg("GetImageCorrelateData")

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

				s.Log.Err(e).Uint64("ImageUniqueID", subtask[j].ImageUniqueID).Msg("not get instance info")

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

			go func() {
				up := types.UpdateSubTask{
					SubtaskID: subtask[j].ID,
					Status:    imagesecModel.TaskStatusInprogress,
					CreatedAt: time.Now().Unix(),
				}
				s.updateSubtaskChan <- up
			}()

			subtaskChan <- typesSubTask

			s.Log.Debug().Int64("subtask", subtask[j].ID).
				Int64("taskID", subtask[j].TaskID).
				Interface("RegInfo", typesSubTask.RegInfo).
				Interface("ScanInstance", typesSubTask.ScanInstance).
				Msg("get subtask and send to chan")

			s.Log.Info().Int64("subtask", subtask[j].ID).
				Int64("taskID", subtask[j].TaskID).
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
			Name:     data.Registry.Name,
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
		ScanTaskDal:               nodeScanTaskDal,
		ImageSrv:                  nodeImageSrv,
		updateSubtaskChan:         make(chan types.UpdateSubTask),
		scanInstanceDal:           instanceDal,
		sensitiveRuleDal:          sensitiveRuleDal,
		scanImageConfigDal:        scanImageConfigDal,
		maxProgressTask:           consts.MaxInprogressTask,
		maxProgressSubtaskPerNode: consts.MaxInprogressSubtaskPerNode,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("RegImageScanQueue"),
			scannerUtils.WithModule(consts.ModelImageScan),
		),
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
