package dispatch

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"gitlab.com/security-rd/go-pkg/logging"

	nodeImageTask "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/dispatch/dequeuers/node-image-scan"
	regImageTask "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/dispatch/dequeuers/reg-image-scan"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	imagesecStream "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/stream"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	rpcStream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type TaskDispatcherService interface {
	PublishSubtask(ctx context.Context) error
}

type TaskDispatcher struct {
	streamClient       rpcStream.MessageStream
	taskDal            imagesecStore.ScanTaskDal
	nodeImageSrv       types.ImageService
	nodeInfoDal        imagesecStore.NodeInfoDal
	scannerInstanceDal imagesecStore.ScanInstanceDal
	sensitiveRuleDal   imagesecStore.SensitiveRuleDal
	scanImageConfigDal imagesecStore.ScanImageConfigDal
}

func NewImageScanTaskDispatcher(
	taskDal imagesecStore.ScanTaskDal,
	nodeImageSrv types.ImageService,
	nodeInfoDal imagesecStore.NodeInfoDal,
	scannerInstanceDal imagesecStore.ScanInstanceDal,
	sensitiveRuleDal imagesecStore.SensitiveRuleDal,
	scanImageConfigDal imagesecStore.ScanImageConfigDal,
) *TaskDispatcher {
	return &TaskDispatcher{
		taskDal:            taskDal,
		nodeImageSrv:       nodeImageSrv,
		nodeInfoDal:        nodeInfoDal,
		scannerInstanceDal: scannerInstanceDal,
		sensitiveRuleDal:   sensitiveRuleDal,
		scanImageConfigDal: scanImageConfigDal,
	}
}

func (s *TaskDispatcher) PublishNodeImageSubtaskHelper(ctx context.Context, subTaskChan chan imagesecTypes.ScanSubTask,
	upChan chan types.UpdateSubTask) {
	logging.Get().Info().Str("module", "imagescan").Msg("Dispatcher start PublishSubtask")

	ticker := time.NewTicker(time.Second * 1) // 限速

	defer ticker.Stop()

	for subtask := range subTaskChan {
		<-ticker.C
		logging.Get().Info().Str("module", "imagescan").Int64("subtaskID", subtask.SubTaskID).Int64("taskID", subtask.TaskID).
			Strs("image", subtask.NodeImageMeta.RepoTags).Str("nodeHostname", subtask.NodeInfo.HostName).
			Msg("Dispatcher get node image scan subtask")

		clusterKey := subtask.NodeInfo.ClusterKey
		dstNodes := []string{subtask.NodeInfo.HostName}

		data, err := json.Marshal(subtask)
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", subtask.TaskID).Int64("subtaskID", subtask.SubTaskID).
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
			Payload:         data,
		}
		req.RequestID = s.GenReqID(req)

		logging.Get().Info().Str("module", "imagescan").Interface("reg", req).Msg("Dispatcher sendMsg")

		if err := s.DoSendSubtaskRpc(ctx, req); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Str("msgID", req.RequestID).Int64("taskID", subtask.TaskID).
				Int64("subtaskID", subtask.SubTaskID).Interface("image", subtask.RegImageMeta).
				Msg("Dispatcher failed to publish task by grpc stream")

			up := types.UpdateSubTask{SubtaskID: subtask.SubTaskID, Err: err, Status: imagesecModel.TaskStatusFailed,
				Reason: imagesecModel.TaskFailedReasonSendNode}
			go func() { upChan <- up }()
			continue
		}

		up := types.UpdateSubTask{SubtaskID: subtask.SubTaskID, Status: imagesecModel.TaskStatusSendFinished}
		go func() { upChan <- up }()

		logging.Get().Info().Str("module", "imagescan").Str("msgID", req.RequestID).Int64("taskID", subtask.TaskID).
			Int64("subtaskID", subtask.SubTaskID).Msg("Dispatcher publish scan subtask succeed")
	}
}

func (s *TaskDispatcher) PublishRegImageSubtaskHelper(ctx context.Context, subTaskChan chan imagesecTypes.ScanSubTask,
	upChan chan types.UpdateSubTask) {
	logging.Get().Info().Str("module", "imagescan").Msg("Dispatcher start PublishSubtask")

	ticker := time.NewTicker(time.Second * 1) // 限速

	defer ticker.Stop()

	for subtask := range subTaskChan {
		<-ticker.C
		logging.Get().Info().Str("module", "imagescan").Int64("subtaskID", subtask.SubTaskID).Int64("taskID", subtask.TaskID).
			Str("image", subtask.RegImageMeta.ImageName()).Str("scannerClusterName", subtask.ScanInstance.ClusterName).
			Msg("Dispatcher get registry image scan subtask")

		data, err := json.Marshal(subtask)
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", subtask.TaskID).Int64("subtaskID", subtask.SubTaskID).
				Msg("Dispatcher failed to marshal task")

			up := types.UpdateSubTask{SubtaskID: subtask.SubTaskID, Err: err,
				Status: imagesecModel.TaskStatusFailed,
				Reason: imagesecModel.TaskFailedReasonScanner,
			}

			go func() { upChan <- up }()

			continue
		}
		req := &pb.ImageSecReq{
			ImageSecReqType: pb.ImageSecReqType_RegistryImageScan,
			ClusterKey:      subtask.ScanInstance.ClusterKey,
			Payload:         data,
		}
		req.RequestID = s.GenReqID(req)

		logging.Get().Debug().Str("module", "imagescan").Interface("reg", req).Msg("Dispatcher sendMsg")

		if err := s.DoSendSubtaskRpc(ctx, req); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Str("msgID", req.RequestID).Int64("taskID", subtask.TaskID).
				Int64("subtaskID", subtask.SubTaskID).Interface("image", subtask.RegImageMeta).
				Msg("Dispatcher failed to publish task by grpc stream")

			up := types.UpdateSubTask{SubtaskID: subtask.SubTaskID, Err: err, Status: imagesecModel.TaskStatusFailed,
				Reason: imagesecModel.TaskFailedReasonSendScanner}

			go func() { upChan <- up }()

			continue
		}

		up := types.UpdateSubTask{SubtaskID: subtask.SubTaskID, Status: imagesecModel.TaskStatusSendFinished}

		go func() { upChan <- up }()

		logging.Get().Info().Str("module", "imagescan").Str("msgID", req.RequestID).Int64("taskID", subtask.TaskID).
			Int64("subtaskID", subtask.SubTaskID).Msg("Dispatcher publish scan subtask succeed")
	}
}

func (s *TaskDispatcher) PublishSubtask(ctx context.Context) error {
	if !scannerUtils.MainCluster() {
		logging.Get().Info().Str("module", "imagescan").Msg("Dispatcher not in main cluster did not PublishSubtask")
		return nil
	}

	s.streamClient = imagesecStream.MustGetGrpcStream()

	logging.Get().Info().Str("module", "imagescan").Msg("Dispatcher PublishSubtask task dispatcher started")

	scanNodeImageQueue := nodeImageTask.NewScanImageQueue(s.taskDal, s.nodeImageSrv, s.nodeInfoDal, s.sensitiveRuleDal)
	go func(dequeue types.ScanImageTaskDequeue) {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Stack().Msg("Dispatcher recover")
			}
		}()
		logging.Get().Info().Str("module", "imagescan").Str("scanTaskType", imagesecModel.ImageFromNode).Msg("Dispatcher start")
		subtaskChan := dequeue.GenSubtaskChan(ctx)
		upSubtaskChan := dequeue.GenUpdateSubtaskChan(ctx)
		s.PublishNodeImageSubtaskHelper(ctx, subtaskChan, upSubtaskChan)
	}(scanNodeImageQueue)

	scanRegImageQueue := regImageTask.NewScanLibImageQueue(s.taskDal, s.nodeImageSrv, s.scannerInstanceDal, s.sensitiveRuleDal, s.scanImageConfigDal)
	go func(dequeue types.ScanImageTaskDequeue) {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Stack().Msg("Dispatcher recover")
			}
		}()
		logging.Get().Info().Str("module", "imagescan").Str("scanTaskType", imagesecModel.ImageFromRegistry).Msg("Dispatcher start")
		subtaskChan := dequeue.GenSubtaskChan(ctx)
		upSubtaskChan := dequeue.GenUpdateSubtaskChan(ctx)
		s.PublishRegImageSubtaskHelper(ctx, subtaskChan, upSubtaskChan)
	}(scanRegImageQueue)

	return nil
}

func (s *TaskDispatcher) sendRpcTask(ctx context.Context, req *pb.ImageSecReq) chan error {
	out := make(chan error)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("ExecutorScanMalicious panic")
			}
		}()

		err := s.sendScanSubtask(ctx, req)
		out <- err
	}()
	return out
}

func (s *TaskDispatcher) DoSendSubtaskRpc(ctx context.Context, req *pb.ImageSecReq) error {
	timeOutCxt, timeOutFunc := context.WithTimeout(ctx, 10*time.Second)
	defer timeOutFunc()

	for {
		select {
		case <-timeOutCxt.Done():
			logging.Get().Error().Str("module", "imagescan").Interface("reg", req).Msg("send scan subtask to rpc")
			return fmt.Errorf("time out")
		case res := <-s.sendRpcTask(timeOutCxt, req):
			return res
		}
	}
}

func (s *TaskDispatcher) sendScanSubtask(ctx context.Context, req *pb.ImageSecReq) error {
	timeOutCxt, timeOutFunc := context.WithTimeout(ctx, 10*time.Second)

	defer timeOutFunc()

	rsp, err := s.streamClient.ScannerPushImageSecMsg(timeOutCxt, req)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("req", req).Msg("Dispatcher sendScanSubtask")
		return err
	}
	if rsp.Status != 0 {
		err = fmt.Errorf("publish task response err code:%v", rsp.Status)
		return err
	}
	return nil
}

func (s *TaskDispatcher) GenReqID(req *pb.ImageSecReq) string {
	return fmt.Sprintf("%s-%s", req.ImageSecReqType.String(), uuid.New().String())
}
