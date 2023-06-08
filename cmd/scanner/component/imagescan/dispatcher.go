package imagescan

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/stream"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	rpcStream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type TaskDispatcherService interface {
	PublishSubtask(ctx context.Context) error
}

type TaskDispatcher struct {
	streamClient rpcStream.MessageStream
	taskDal      imagesecStore.ScanTaskDal
	dequeues     map[string]types.Dequeue
}

func NewImageScanTaskDispatcher(
	taskDal imagesecStore.ScanTaskDal,
	dequeues map[string]types.Dequeue,
) *TaskDispatcher {
	return &TaskDispatcher{
		taskDal:  taskDal,
		dequeues: dequeues,
	}
}

func (s *TaskDispatcher) PublishSubtaskHelper(ctx context.Context, subTaskChan chan imagesecTypes.ScanSubTask,
	upChan chan types.UpdateSubTask) {
	logging.Get().Info().Msg("Dispatcher start PublishSubtask")

	ticker := time.NewTicker(time.Second * 1) // 限速

	defer ticker.Stop()

	for subtask := range subTaskChan {
		<-ticker.C
		logging.Get().Info().Int64("subtaskID", subtask.SubTaskID).Int64("taskID", subtask.TaskID).
			Strs("image", subtask.ImageMeta.RepoTags).Str("nodeHostname", subtask.NodeInfo.HostName).
			Msg("Dispatcher get a scan subtask")

		clusterKey := subtask.NodeInfo.ClusterKey
		dstNodes := []string{subtask.NodeInfo.HostName}

		data, err := json.Marshal(subtask)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", subtask.TaskID).Int64("subtaskID", subtask.SubTaskID).
				Msg("Dispatcher failed to marshal task")

			up := types.UpdateSubTask{SubtaskID: subtask.SubTaskID, Err: err,
				Status: imagesecModel.TaskStatusFailed,
				Reason: imagesecModel.TaskFailedReasonScanner,
			}

			go func() { upChan <- up }()

			continue
		}
		req := &pb.ImageSecReq{
			ImageSecReqType: pb.ImageSecReqType_NodeImageScan,
			ClusterKey:      clusterKey,
			NodeName:        dstNodes,
			RequestID:       uuid.New().String(),
			Payload:         data,
		}
		logging.Get().Debug().Interface("reg", req).Msg("Dispatcher sendMsg")

		if err := s.sendScanSubtask(ctx, req); err != nil {
			logging.Get().Err(err).Str("msgID", req.RequestID).Int64("taskID", subtask.TaskID).
				Int64("subtaskID", subtask.SubTaskID).Interface("image", subtask.ImageMeta).
				Msg("Dispatcher failed to publish task by grpc stream")
			up := types.UpdateSubTask{SubtaskID: subtask.SubTaskID, Err: err, Status: imagesecModel.TaskStatusFailed,
				Reason: imagesecModel.TaskFailedReasonSendNode}
			go func() { upChan <- up }()
			continue
		}

		up := types.UpdateSubTask{SubtaskID: subtask.SubTaskID, Status: imagesecModel.TaskStatusSendFinished}
		go func() { upChan <- up }()

		logging.Get().Info().Str("msgID", req.RequestID).Int64("taskID", subtask.TaskID).
			Int64("subtaskID", subtask.SubTaskID).Msg("Dispatcher publish scan subtask succeed")
	}
}

func (s *TaskDispatcher) sendScanSubtask(ctx context.Context, req *pb.ImageSecReq) error {
	timeOutCxt, timeOutFunc := context.WithTimeout(ctx, 10*time.Second)

	defer timeOutFunc()

	rsp, err := s.streamClient.ScannerPushImageSecMsg(timeOutCxt, req)
	if err != nil {
		logging.Get().Err(err).Interface("req", req).Msg("Dispatcher sendScanSubtask")
		return err
	}
	if rsp.Status != 0 {
		err = fmt.Errorf("publish task response err code:%v", rsp.Status)
		return err
	}
	return nil
}

func (s *TaskDispatcher) PublishSubtask(ctx context.Context) error {
	// 一定要在这一步执行，不能在新建服务的时候执行，因为 grpc 还没有建立好
	s.streamClient = stream.MustGetGrpcClient()

	logging.Get().Info().Msg("Dispatcher task dispatcher started")

	for i := range s.dequeues {
		go func(dequeue types.Dequeue) {
			defer func() {
				if err := recover(); err != nil {
					logging.Get().Error().Stack().Msg("Dispatcher recover")
				}
			}()
			logging.Get().Info().Str("queueType", dequeue.Type()).Msg("Dispatcher start")
			subtaskChan := dequeue.GenSubtaskChan(ctx)
			upSubtaskChan := dequeue.GenUpdateSubtaskChan(ctx)
			s.PublishSubtaskHelper(ctx, subtaskChan, upSubtaskChan)
		}(s.dequeues[i])
	}
	return nil
}
