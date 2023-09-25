package nodeimagetask

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

type NodeImageScanQueue struct {
	nodeScanTaskDal           imagesecStore.ScanTaskDal
	nodeImageSrv              types.ImageService
	updateSubtaskChan         chan types.UpdateSubTask
	nodeInfoDal               imagesecStore.NodeInfoDal
	sensitiveRuleDal          imagesecStore.SensitiveRuleDal
	maxProgressTask           int64
	maxProgressSubtaskPerNode int64
}

func (s *NodeImageScanQueue) GenUpdateSubtaskChan(ctx context.Context) chan types.UpdateSubTask {
	return s.updateSubtaskChan
}

func (s *NodeImageScanQueue) updateSubtask(ctx context.Context) {

	for up := range s.updateSubtaskChan {
		if up.RetryCnt > consts.DefaultMaxRetryCount {
			logging.Get().Info().Str("module", "imagescan").Int64("subtaskID", up.SubtaskID).
				Msg("NodeImageScanQueue UpdateScanSubtask exceed max retry")
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
				Msg("NodeImageScanQueue UpdateScanSubtask")
			up.RetryCnt++
			go func() { s.updateSubtaskChan <- up }()
			continue
		}
		logging.Get().Info().Str("module", "imagescan").Int64("subtaskID", up.SubtaskID).
			Interface("statusStr", updater["status_str"]).
			Msg("NodeImageScanQueue UpdateScanSubtask succeed")
	}
}

func (s *NodeImageScanQueue) GenTaskChan(ctx context.Context) chan *imagesecModel.ImageScanTask {
	out := make(chan *imagesecModel.ImageScanTask, 1)

	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Stack().Msg("NodeImageScanQueue recover")
			}
		}()

		defer close(out)

		ticker := time.NewTicker(time.Second * 5)
		defer ticker.Stop()

		for {
			<-ticker.C
			task, inCnt, err := s.nodeScanTaskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				ImageFromType: imagesecModel.ImageFromNode,
				ScanStatus:    []int64{imagesecModel.TaskStatusInprogress},
				Filter:        &model.Filter{Limit: s.maxProgressTask, SortFiled: "id", SortBy: consts.SortByAsc},
			})
			if err != nil {
				ticker.Reset(time.Minute)
				logging.Get().Err(err).Str("module", "imagescan").
					Msg("NodeImageScanQueue find inprogress scan task")
				continue
			}
			logging.Get().Debug().Str("module", "imagescan").Int64("inCnt", inCnt).
				Msg("NodeImageScanQueue  inprogress task")

			if len(task) == 0 || inCnt < s.maxProgressTask {
				pending, pendCnt, err := s.nodeScanTaskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
					ImageFromType: imagesecModel.ImageFromNode,
					ScanStatus:    []int64{imagesecModel.TaskStatusPending, imagesecModel.TaskStatusSendFinished},
					Filter:        &model.Filter{Limit: s.maxProgressTask - inCnt, SortFiled: "status", SortBy: consts.SortByDesc},
				})
				if err != nil {
					logging.Get().Err(err).Str("module", "imagescan").
						Msg("NodeImageScanQueue find inprogress scan task")
					continue
				}
				logging.Get().Debug().Str("module", "imagescan").Int64("pendingTaskCnt", pendCnt).
					Msg("NodeImageScanQueue search pending task")

				task = append(task, pending...)
			}
			logging.Get().Info().Str("module", "imagescan").Int("taskCnt", len(task)).
				Msg("NodeImageScanQueue search scan task")
			for i := range task {
				out <- task[i]
			}

			if len(task) == 0 {
				ticker.Reset(20 * time.Second)
				continue
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
				logging.Get().Error().Stack().Msg("NodeImageScanQueue recover")
			}
		}()
		defer close(subtaskChan)

		taskChan := s.GenTaskChan(ctx)

		for task := range taskChan {
			logging.Get().Info().Str("module", "imagescan").Int64("taskID", task.ID).
				Msg("NodeImageScanQueue get a scan task")
			if err := s.UpdateTaskInprogress(ctx, task.ID); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", task.ID).
					Msg("NodeImageScanQueue start task")
				continue
			}

			if err := s.SearchSubtaskAndSendToChan(ctx, task, subtaskChan); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Interface("task", task).
					Msg("NodeImageScanQueue SearchSubtaskAndSendToChan")
				continue
			}

			logging.Get().Info().Str("module", "imagescan").Interface("taskID", task.ID).
				Msg("NodeImageScanQueue send subtask finish")
		}
	}()

	return subtaskChan
}

func (s *NodeImageScanQueue) SearchSubtaskAndSendToChan(ctx context.Context, task *imagesecModel.ImageScanTask,
	subtaskChan chan imagesecTypes.ScanSubTask) error {

	node, _, err := s.nodeInfoDal.SearchNodeInfo(ctx, imagesecModel.SearchNodeInfoParam{
		Filter: model.EmptyFilterForTotalQuery(),
	})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("NodeImageScanQueue SearchNodeInfo")
		return err
	}

	for i := range node {
		no := node[i]
		_, sendSubtask, err := s.nodeScanTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			NodeUniqueID:  no.UniqueID,
			ScanStatusStr: []string{imagesecModel.TaskStatusInprogressStr},
			Filter:        model.EmptyFilter().SetLimit(1),
		})
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", task.ID).
				Msg("NodeImageScanQueue SearchScanSubtask")
			return err
		}
		if sendSubtask >= s.maxProgressSubtaskPerNode {
			logging.Get().Info().Str("module", "imagescan").Str("nodeHostName", no.Hostname).
				Int64("runningTask", sendSubtask).
				Msg("NodeImageScanQueue node has scan task scanning")
			continue
		}

		subtask, _, err := s.nodeScanTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			TaskID:       task.ID,
			NodeUniqueID: no.UniqueID,
			ScanStatus:   []int64{imagesecModel.TaskStatusPending},
			// 这里一次不取更多，是因为前端更新 task 任务之后需要快速感知
			Filter: model.EmptyFilter().SetSortFiledByID().SetSortAsc().
				SetLimit(util.MinInt64(consts.DefaultSendSubtaskBatchSize, s.maxProgressSubtaskPerNode-sendSubtask)),
		})
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", task.ID).
				Msg("NodeImageScanQueue SearchScanSubtask")
			continue
		}

		for j := range subtask {

			imageDate, err := s.nodeImageSrv.GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
				ImageUniqueID:  subtask[j].ImageUniqueID,
				NodeInfoEnable: true,
			})
			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", task.ID).Uint64("ImageUniqueID",
					subtask[0].ImageUniqueID).Msg("NodeImageScanQueue GetImageCorrelateData")
				up := types.UpdateSubTask{SubtaskID: subtask[j].ID, Status: imagesecModel.TaskStatusFailed,
					Err: err, Reason: imagesecModel.TaskFailedReasonNotFindImage, CreatedAt: time.Now().Unix()}
				go func() { s.updateSubtaskChan <- up }()
				continue
			}

			if imageDate.NodeInfo == nil {
				logging.Get().Info().Str("module", "imagescan").Uint64("ImageUniqueID", subtask[j].ImageUniqueID).
					Msg("NodeImageScanQueue not get node info")

				up := types.UpdateSubTask{SubtaskID: subtask[j].ID, Status: imagesecModel.TaskStatusFailed,
					Err: err, Reason: imagesecModel.TaskFailedReasonNotFindNodeInfo, CreatedAt: time.Now().Unix()}

				go func() { s.updateSubtaskChan <- up }()

				continue
			}

			typesSubTask := modelToType(subtask[j], imageDate, s.SearchAllSensitiveRule(ctx))

			subtaskChan <- typesSubTask

			logging.Get().Info().Str("module", "imagescan").Int64("subtask", subtask[j].ID).
				Int64("taskID", subtask[j].TaskID).
				Str("nodeName", subtask[j].Hostname).Msg("NodeImageScanQueue get subtask and send to chan")
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
	if err := s.nodeScanTaskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
		ID:      taskID,
		Updater: updater,
		Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusInprogress),
	}); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("updater", updater).
			Int64("taskID", taskID).Msg("UpdateTaskInprogress")
		return err
	}
	logging.Get().Info().Str("module", "imagescan").Interface("updater", updater).
		Int64("taskID", taskID).Msg("NodeImageScanQueue UpdateTaskInprogress")
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
) imagesecTypes.ScanSubTask {
	sub := imagesecTypes.ScanSubTask{
		TaskID:    subtask.TaskID,
		SubTaskID: subtask.ID,
		NodeImageMeta: imagesecTypes.ImageMeta{
			UniqueID: data.Image.UniqueID,
			ImageId:  data.Image.ImageID,
			Digests:  []string{data.Image.Digest},
			RepoTags: []string{data.Image.GetImageName()},
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
	nodeQueue := &NodeImageScanQueue{
		nodeScanTaskDal:           nodeScanTaskDal,
		nodeImageSrv:              nodeImageSrv,
		updateSubtaskChan:         make(chan types.UpdateSubTask),
		nodeInfoDal:               nodeInfoDal,
		sensitiveRuleDal:          sensitiveRuleDal,
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

	go nodeQueue.updateSubtask(context.Background())
	return nodeQueue
}
