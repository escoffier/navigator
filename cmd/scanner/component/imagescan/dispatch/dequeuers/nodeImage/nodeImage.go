package nodeimagetask

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"gorm.io/gorm/clause"

	global2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type NodeImageScanQueue struct {
	ScanTaskDal       imagesecStore.ScanTaskDal
	ImageSrv          types.ImageService
	updateSubtaskChan chan types.UpdateSubTask
	nodeInfoDal       imagesecStore.NodeInfoDal
	sensitiveRuleDal  imagesecStore.SensitiveRuleDal
	Config            ScanConfig
	PodID             string
	Log               *scannerUtils.LogEvent
}

type ScanConfig struct {
	MaxProTask       int64
	MaxProSubtaskPer int64
}

func (s *NodeImageScanQueue) GenUpdateSubtaskChan(ctx context.Context) chan types.UpdateSubTask {
	return s.updateSubtaskChan
}

func (s *NodeImageScanQueue) updateSubtask(ctx context.Context) {

	for up := range s.updateSubtaskChan {
		if up.RetryCnt > consts.DefaultMaxRetryCount {
			s.Log.Info().Int64("subtaskID", up.SubtaskID).
				Msg("UpdateScanSubtask exceed max retry")
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
		s.Log.Info().Int64("subtaskID", up.SubtaskID).
			Interface("statusStr", updater["status_str"]).
			Msg("UpdateScanSubtask succeed")
	}
}

func (s *NodeImageScanQueue) GenTaskChan(ctx context.Context) chan *imagesecModel.ImageScanTask {
	out := make(chan *imagesecModel.ImageScanTask, 1)

	go func() {
		defer func() {
			if err := recover(); err != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("NodeImageScanQueue recover")
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
				ImageFromType: imagesecModel.ImageFromNode,
				ScanStatus:    []int64{imagesecModel.TaskStatusInprogress},
				Filter:        filter,
			})
			if err != nil {
				time.Sleep(time.Minute)
				s.Log.Err(err).Msg("find inprogress scan runTask")
				continue
			}
			s.Log.Debug().Int64("taskCnt", cnt).Msg("find node image scan running Task")

			for i := range runTask {
				out <- runTask[i]
			}
			if cnt >= s.Config.MaxProTask {
				s.Log.Info().Int64("runningTaskCnt", cnt).Msg("has max running task")
				continue
			}

			pendTask, cnt, err := s.ScanTaskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				ImageFromType: imagesecModel.ImageFromNode,
				ScanStatus:    []int64{imagesecModel.TaskStatusPending},
				Filter:        filter,
			})
			if err != nil {
				time.Sleep(time.Minute)
				s.Log.Err(err).Msg("find scan pend Task")
				continue
			}
			s.Log.Debug().Int64("taskCnt", cnt).Msg("find node image scan pendTask")

			for i := range pendTask {
				out <- pendTask[i]
			}

			if len(pendTask) == 0 {
				time.Sleep(time.Minute)
			}
		}
	}()
	return out
}

func (s *NodeImageScanQueue) GenSubtaskChan(ctx context.Context) chan imagesecTypes.ScanSubTask {

	subtaskChan := make(chan imagesecTypes.ScanSubTask)

	go func() {
		defer func() {
			if err := recover(); err != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("recover")
			}
		}()
		defer close(subtaskChan)

		taskChan := s.GenTaskChan(ctx)

		for task := range taskChan {
			if err := s.SearchSubtaskAndSendToChan(ctx, task, subtaskChan); err != nil {
				s.Log.Err(err).Interface("task", task).Msg("SearchSubtaskAndSendToChan")
				continue
			}

			s.Log.Debug().Int64("taskID", task.ID).Msg("send subtask finish")
		}
	}()

	return subtaskChan
}

func (s *NodeImageScanQueue) SearchSubtaskAndSendToChan(ctx context.Context, task *imagesecModel.ImageScanTask,
	subtaskChan chan imagesecTypes.ScanSubTask) error {

	node, _, err := s.nodeInfoDal.SearchNodeInfo(ctx, imagesecModel.SearchNodeInfoParam{
		Filter: imagesecModel.EmptyFilterForTotalQuery(),
	})
	if err != nil {
		s.Log.Err(err).Msg("SearchNodeInfo")
		return err
	}

	for i := range node {
		no := node[i]
		param := imagesecModel.SearchTaskParam{
			// 查找当前节点在执行的所有子任务
			NodeUniqueID: no.UniqueID,
			// 发送完成扫描过程中 Pod 重启，那就只能等超时失败了
			// 不能持续发送，因为任务可能重启动，节点不能对任务去重
			ScanStatus: []int64{imagesecModel.TaskStatusSendFinished},
			Filter:     imagesecModel.EmptyFilter().SetLimit(1),
		}
		_, sendSubtask, err := s.ScanTaskDal.SearchScanSubtask(ctx, param)

		if err != nil {
			s.Log.Err(err).Int64("taskID", task.ID).
				Msg("SearchScanSubtask")
			return err
		}
		if sendSubtask >= s.Config.MaxProSubtaskPer {
			s.Log.Debug().Str("node", no.LogStr()).Msg("node has scan task scanning")
			continue
		}
		subtaskParam := imagesecModel.SearchTaskParam{
			TaskID:       task.ID,
			NodeUniqueID: no.UniqueID,
			// TaskStatusInprogress 但是可能发送失败
			// 对于执行中的子任务持续发送,防止子集群重启动
			// 扫描器会做去重处理，对于正在扫描的任务会忽略
			ScanStatus: []int64{imagesecModel.TaskStatusPending, imagesecModel.TaskStatusInprogress},
			// 这里一次不取更多，是因为前端更新 task 任务之后需要快速感知
			Filter: imagesecModel.EmptyFilter().SetSortAsc().SetSortFiled("status").SetLimit(s.Config.MaxProSubtaskPer - sendSubtask),
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
		if len(subtask) > 0 {
			// 已开始发送子任务时才更新任务已开始
			// 如果任务1开始了，但是节点的有其他子任务在执行，不能执行该任务下的子任务，这时不应该认为该任务已开始
			if err := s.UpdateTaskInprogress(ctx, task.ID); err != nil {
				s.Log.Err(err).Int64("taskID", task.ID).Msg("start task")
				continue
			}
		}

		for j := range subtask {

			imageDate, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
				ImageUniqueID:  subtask[j].ImageUniqueID,
				NodeInfoEnable: true,
			})
			if err != nil {
				s.Log.Err(err).Int64("taskID", task.ID).Uint64("ImageUniqueID",
					subtask[0].ImageUniqueID).Msg("GetImageCorrelateData")
				up := types.UpdateSubTask{SubtaskID: subtask[j].ID, Status: imagesecModel.TaskStatusFailed,
					Err: err, Reason: imagesecModel.TaskFailedReasonNotFindImage, CreatedAt: time.Now().UnixMilli()}
				go func() { s.updateSubtaskChan <- up }()
				continue
			}

			if imageDate.NodeInfo == nil {
				s.Log.Info().Uint64("ImageUniqueID", subtask[j].ImageUniqueID).
					Msg("not get node info")

				up := types.UpdateSubTask{SubtaskID: subtask[j].ID, Status: imagesecModel.TaskStatusFailed,
					Err: err, Reason: imagesecModel.TaskFailedReasonNotFindNodeInfo, CreatedAt: time.Now().UnixMilli()}

				go func() { s.updateSubtaskChan <- up }()

				continue
			}

			typesSubTask := modelToType(subtask[j], imageDate, s.SearchAllSensitiveRule(ctx))

			go func() {
				up := types.UpdateSubTask{
					SubtaskID: subtask[j].ID,
					Status:    imagesecModel.TaskStatusInprogress,
					CreatedAt: time.Now().UnixMilli(),
				}
				s.updateSubtaskChan <- up
			}()

			subtaskChan <- typesSubTask

			s.Log.Info().Int64("subtask", subtask[j].ID).
				Int64("taskID", subtask[j].TaskID).
				Str("nodeName", subtask[j].Hostname).Msg("get subtask and send to chan")
		}
	}

	return nil
}

func (s *NodeImageScanQueue) UpdateTaskInprogress(ctx context.Context, taskID int64) error {
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

func (s *NodeImageScanQueue) SearchAllSensitiveRule(ctx context.Context) []string {
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
) imagesecTypes.ScanSubTask {
	sub := imagesecTypes.ScanSubTask{
		TaskID:    subtask.TaskID,
		SubTaskID: subtask.ID,
		NodeImageMeta: imagesecTypes.ImageMeta{
			UniqueID:  data.Image.UniqueID,
			ImageId:   data.Image.ImageID,
			Digests:   []string{data.Image.Digest},
			RepoTags:  []string{data.Image.GetImageName()},
			Namespace: data.Image.Namespace,
		},

		SensitiveRules: ses,
	}
	if data.NodeInfo != nil {
		sub.NodeInfo = imagesecTypes.NodeInfo{
			ClusterKey: data.NodeInfo.ClusterKey,
			Ip:         data.NodeInfo.IP,
			HostName:   data.NodeInfo.Hostname,
		}
	}

	sub.UniqueID = sub.GenUniqueID()
	return sub
}

func NewScanImageQueue(
	nodeScanTaskDal imagesecStore.ScanTaskDal,
	nodeImageSrv types.ImageService,
	nodeInfoDal imagesecStore.NodeInfoDal,
	sensitiveRuleDal imagesecStore.SensitiveRuleDal,
) *NodeImageScanQueue {
	scanQueue := &NodeImageScanQueue{
		ScanTaskDal:       nodeScanTaskDal,
		ImageSrv:          nodeImageSrv,
		updateSubtaskChan: make(chan types.UpdateSubTask),
		nodeInfoDal:       nodeInfoDal,
		sensitiveRuleDal:  sensitiveRuleDal,
		Config: ScanConfig{
			MaxProTask:       consts.MaxInprogressTask,
			MaxProSubtaskPer: consts.MaxInprogressSubtaskPerNode,
		},
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("NodeImageScanQueue"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		),
	}

	if global2.ScannerOpts.ParallelTaskNum > 0 {
		scanQueue.Config.MaxProTask = int64(global2.ScannerOpts.ParallelTaskNum)
	}

	if global2.ScannerOpts.ParallelSubTaskNum > 0 {
		scanQueue.Config.MaxProSubtaskPer = int64(global2.ScannerOpts.ParallelSubTaskNum)
	}

	go scanQueue.updateSubtask(context.Background())
	return scanQueue
}
