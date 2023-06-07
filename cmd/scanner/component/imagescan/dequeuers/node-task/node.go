package nodetask

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

type NodeImageQueue struct {
	nodeScanTaskDal             imagesecStore.ScanTaskDal
	nodeImageSrv                types.ImageService
	updateSubtaskChan           chan types.UpdateSubTask
	nodeInfoDal                 imagesecStore.NodeInfoDal
	maxInprogressTask           int64
	maxInprogressSubtaskPerNode int64
}

func (s *NodeImageQueue) Type() string {
	return imagesecModel.ImageFromNode
}

func (s *NodeImageQueue) GenUpdateSubtaskChan(ctx context.Context) chan types.UpdateSubTask {
	return s.updateSubtaskChan
}

func (s *NodeImageQueue) updateSubtask(ctx context.Context) {

	for up := range s.updateSubtaskChan {
		if up.RetryCnt > consts.DefaultMaxRetryCount {
			logging.Get().Info().Int64("subtaskID", up.SubtaskID).Msg("NodeImageQueue UpdateScanSubtask exceed max retry")
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
			logging.Get().Err(err).Int64("subtaskID", up.SubtaskID).Interface("updater", updater).
				Msg("NodeImageQueue UpdateScanSubtask")
			up.RetryCnt++
			go func() { s.updateSubtaskChan <- up }()
			continue
		}
		logging.Get().Info().Int64("subtaskID", up.SubtaskID).Interface("statusStr", updater["status_str"]).
			Msg("NodeImageQueue UpdateScanSubtask succeed")
	}
}

func (s *NodeImageQueue) GenTaskChan(ctx context.Context) chan *imagesecModel.ImageScanTask {
	out := make(chan *imagesecModel.ImageScanTask, 1)

	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Stack().Msg("NodeImageQueue recover")
			}
		}()

		defer close(out)

		ticker := time.NewTicker(time.Second * 2)
		defer ticker.Stop()

		for {
			<-ticker.C
			task, inCnt, err := s.nodeScanTaskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
				// 这里一定要把TaskStatusSendFinished这个状态加上，因为前端可以重新扫描
				ScanStatus: []int64{imagesecModel.TaskStatusInprogress, imagesecModel.TaskStatusSendFinished},
				Filter:     &model.Filter{Limit: 1},
			})
			if err != nil {
				ticker.Reset(time.Second * 20)
				logging.Get().Err(err).Msg("NodeImageQueue SearchScanTask find inprogress scan task")
				continue
			}
			logging.Get().Info().Int64("inCnt", inCnt).Msg("NodeImageQueue SearchScanTask inprogress")
			if inCnt >= s.maxInprogressTask {
				ticker.Reset(time.Second * 20)
				logging.Get().Info().Int64("inprogressCount", inCnt).Msg("NodeImageQueue has inprogress scan task")
				continue
			}

			if len(task) == 0 || inCnt < s.maxInprogressTask {
				pending, pendCnt, err := s.nodeScanTaskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{
					ScanStatus: []int64{imagesecModel.TaskStatusPending},
					Filter:     &model.Filter{Limit: 1, SortFiled: "status", SortBy: consts.SortByDesc},
				})
				if err != nil {
					logging.Get().Err(err).Msg("NodeImageQueue SearchScanTask find inprogress scan task")
					continue
				}
				logging.Get().Info().Int64("pendingTaskCnt", pendCnt).Msg("NodeImageQueue search pending task")

				task = append(task, pending...)
			}

			if len(task) == 0 {
				ticker.Reset(time.Second * 20)
				logging.Get().Info().Msg("NodeImageQueue SearchScanTask not find scan task")
				continue
			}
			for i := range task {
				out <- task[i]
			}
			ticker.Reset(time.Second * 2)
		}
	}()
	return out
}

func (s *NodeImageQueue) GenSubtaskChan(ctx context.Context) chan imagesecTypes.ScanSubTask {

	subtaskChan := make(chan imagesecTypes.ScanSubTask)

	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Stack().Msg("NodeImageQueue recover")
			}
		}()
		defer close(subtaskChan)

		taskChan := s.GenTaskChan(ctx)

		for task := range taskChan {
			logging.Get().Info().Int64("taskID", task.ID).Msg("NodeImageQueue get a scan task")
			if err := s.UpdateTaskInprogress(ctx, task.ID); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("NodeImageQueue start task")
				continue
			}

			if err := s.SearchSubtaskAndSendToChan(ctx, task, subtaskChan); err != nil {
				logging.Get().Err(err).Interface("task", task).Msg("NodeImageQueue SearchSubtaskAndSendToChan")
				continue
			}
			logging.Get().Info().Interface("taskID", task.ID).Msg("NodeImageQueue SearchSubtaskAndSendToChan finish")
		}
	}()

	return subtaskChan
}

func (s *NodeImageQueue) SearchSubtaskAndSendToChan(ctx context.Context, task *imagesecModel.ImageScanTask,
	subtaskChan chan imagesecTypes.ScanSubTask) error {

	node, _, err := s.nodeInfoDal.SearchNodeInfo(ctx, imagesecModel.SearchNodeInfoParam{
		Filter: model.EmptyFilterForTotalQuery(),
	})
	if err != nil {
		logging.Get().Err(err).Msg("NodeImageQueue SearchNodeInfo")
		return err
	}

	for i := range node {
		no := node[i]
		_, sendSubtask, err := s.nodeScanTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			NodeUniqueID:   no.UniqueID,
			NodeClusterKey: no.ClusterKey,
			ScanStatus:     []int64{imagesecModel.TaskStatusSendFinished},
			Filter:         model.EmptyFilter().SetLimit(1),
		})
		if err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("NodeImageQueue SearchScanSubtask")
			return err
		}
		if sendSubtask >= s.maxInprogressSubtaskPerNode {
			logging.Get().Info().Str("nodeHostName", no.Hostname).Int64("runningTask", sendSubtask).
				Msg("NodeImageQueue the node has scan task scanning")
			continue
		}

		subtask, _, err := s.nodeScanTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			TaskID:       task.ID,
			NodeUniqueID: no.UniqueID,
			ScanStatus:   []int64{imagesecModel.TaskStatusPending},
			// 这里一次不取更多，是因为前端更新 task 任务之后需要快速感知
			Filter: model.EmptyFilter().SetLimit(util.MinInt64(consts.DefaultSendSubtaskBatchSize, s.maxInprogressSubtaskPerNode-sendSubtask)),
		})
		if err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("NodeImageQueue SearchScanSubtask")
			continue
		}

		for j := range subtask {

			imageDate, err := s.nodeImageSrv.GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
				ImageUniqueID:  subtask[j].ImageUniqueID,
				NodeInfoEnable: true,
			})
			if err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Uint64("ImageUniqueID",
					subtask[0].ImageUniqueID).Msg("NodeImageQueue GetImageCorrelateData")
				up := types.UpdateSubTask{SubtaskID: subtask[j].ID, Status: imagesecModel.TaskStatusFailed,
					Err: err, Reason: imagesecModel.TaskFailedReasonNotFindImage, CreatedAt: time.Now().Unix()}
				go func() { s.updateSubtaskChan <- up }()
				continue
			}

			if imageDate.NodeInfo == nil {
				logging.Get().Info().Uint64("ImageUniqueID", subtask[j].ImageUniqueID).Msg("NodeImageQueue not get node info")

				up := types.UpdateSubTask{SubtaskID: subtask[j].ID, Status: imagesecModel.TaskStatusFailed,
					Err: err, Reason: imagesecModel.TaskFailedReasonNotFindNodeInfo, CreatedAt: time.Now().Unix()}

				go func() { s.updateSubtaskChan <- up }()

				continue
			}
			typesSubTask := modelToType(subtask[j], imageDate.Image, imageDate.NodeInfo)

			subtaskChan <- typesSubTask

			logging.Get().Info().Int64("subtask", subtask[j].ID).Int64("taskID", subtask[j].TaskID).
				Str("nodeName", subtask[j].NodeHostname).Msg("NodeImageQueue get subtask and send to chan")

			up := types.UpdateSubTask{SubtaskID: subtask[j].ID, Status: imagesecModel.TaskStatusInprogress, CreatedAt: time.Now().Unix()}
			go func() { s.updateSubtaskChan <- up }()
		}
	}

	return nil
}

func (s *NodeImageQueue) UpdateTaskInprogress(ctx context.Context, taskID int64) error {
	updater := map[string]interface{}{
		"status":     imagesecModel.TaskStatusInprogress,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusInprogress),
		"started_at": time.Now().UnixMilli(),
	}
	if err := s.nodeScanTaskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
		ID:      taskID,
		Updater: updater,
		Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusSendFinished),
	}); err != nil {
		logging.Get().Err(err).Interface("updater", updater).Int64("taskID", taskID).Msg("UpdateTaskInprogress")
		return err
	}
	logging.Get().Info().Interface("updater", updater).Int64("taskID", taskID).Msg("NodeImageQueue UpdateTaskInprogress")
	return nil
}

func modelToType(subtask *imagesecModel.ImageScanSubTask, image imagesecModel.Image,
	node *imagesecModel.NodeInfo) imagesecTypes.ScanSubTask {

	sub := imagesecTypes.ScanSubTask{
		TaskID:    subtask.TaskID,
		SubTaskID: subtask.ID,
		NodeInfo: imagesecTypes.NodeInfo{
			ClusterKey: node.ClusterKey,
			Ip:         node.IP,
			HostName:   node.Hostname,
		},
		ImageMeta: imagesecTypes.ImageMeta{
			ImageId:  image.ImageID,
			Digests:  []string{image.Digest},
			RepoTags: []string{image.GetImageName()},
		},
	}
	return sub
}

func NewNodeImageQueue(
	nodeScanTaskDal imagesecStore.ScanTaskDal,
	nodeImageSrv types.ImageService,
	nodeInfoDal imagesecStore.NodeInfoDal,
) *NodeImageQueue {
	nodeQueue := &NodeImageQueue{
		nodeScanTaskDal:             nodeScanTaskDal,
		nodeImageSrv:                nodeImageSrv,
		updateSubtaskChan:           make(chan types.UpdateSubTask),
		nodeInfoDal:                 nodeInfoDal,
		maxInprogressTask:           consts.MaxInprogressTask,
		maxInprogressSubtaskPerNode: consts.MaxInprogressSubtaskPerNode,
	}

	cnt1, err := strconv.ParseInt(os.Getenv("MaxInprogressTask"), 10, 64)
	if err != nil && cnt1 > 0 {
		nodeQueue.maxInprogressTask = cnt1
	}

	cnt2, err := strconv.ParseInt(os.Getenv("MaxInprogressSubtaskPerNode"), 10, 64)
	if err != nil && cnt2 > 0 {
		nodeQueue.maxInprogressSubtaskPerNode = cnt2
	}

	go nodeQueue.updateSubtask(context.Background())
	return nodeQueue
}
