package dispatch

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/google/uuid"

	nodeImageTask "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/dispatch/dequeuers/nodeImage"
	regImageTask "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/dispatch/dequeuers/regImage"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	imagesecStream "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/stream"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
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
	scanResultDal      imagesecStore.ScanResultDal
	dbMetaDal          imagesecStore.ScanDbMetaDal
	scanImageConfigDal imagesecStore.ScanImageConfigDal
	Log                *scannerUtils.LogEvent
}

func NewImageScanTaskDispatcher(
	taskDal imagesecStore.ScanTaskDal,
	nodeImageSrv types.ImageService,
	nodeInfoDal imagesecStore.NodeInfoDal,
	scannerInstanceDal imagesecStore.ScanInstanceDal,
	sensitiveRuleDal imagesecStore.SensitiveRuleDal,
	scanImageConfigDal imagesecStore.ScanImageConfigDal,
	scanResultDal imagesecStore.ScanResultDal,
	dbMetaDal imagesecStore.ScanDbMetaDal,
) *TaskDispatcher {
	return &TaskDispatcher{
		taskDal:            taskDal,
		nodeImageSrv:       nodeImageSrv,
		nodeInfoDal:        nodeInfoDal,
		scannerInstanceDal: scannerInstanceDal,
		sensitiveRuleDal:   sensitiveRuleDal,
		scanImageConfigDal: scanImageConfigDal,
		scanResultDal:      scanResultDal,
		dbMetaDal:          dbMetaDal,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("ScanTaskDispatcher"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		),
	}
}

func (s *TaskDispatcher) PublishNodeImageSubtaskHelper(ctx context.Context, subTaskChan chan imagesecTypes.ScanSubTask,
	upChan chan types.UpdateSubTask) {
	s.Log.Info().Msg("Dispatcher start PublishSubtask")

	ticker := time.NewTicker(time.Second * 1) // 限速

	defer ticker.Stop()

	for subtask := range subTaskChan {
		<-ticker.C
		s.Log.Info().Int64("subtaskID", subtask.SubTaskID).Int64("taskID", subtask.TaskID).
			Strs("image", subtask.NodeImageMeta.RepoTags).Str("nodeHostname", subtask.NodeInfo.HostName).
			Msg("Dispatcher get node image scan subtask")

		clusterKey := subtask.NodeInfo.ClusterKey

		data, err := json.Marshal(subtask)
		if err != nil {
			s.Log.Err(err).Int64("taskID", subtask.TaskID).Int64("subtaskID", subtask.SubTaskID).
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
			NodeName:        subtask.NodeInfo.HostName,
			Payload:         data,
		}
		req.MsgID = s.GenReqID(req)

		s.Log.Info().Str("reg", ReqLogStr(req)).Msg("Dispatcher sendMsg")

		if err := s.DoSendSubtaskRpc(ctx, req); err != nil {
			s.Log.Err(err).Str("msgID", req.MsgID).Int64("taskID", subtask.TaskID).
				Int64("subtaskID", subtask.SubTaskID).Interface("image", subtask.RegImageMeta).
				Msg("Dispatcher failed to publish task by grpc stream")

			up := types.UpdateSubTask{SubtaskID: subtask.SubTaskID, Err: err, Status: imagesecModel.TaskStatusFailed,
				Reason: imagesecModel.TaskFailedReasonSendNode}
			go func() { upChan <- up }()
			continue
		}

		up := types.UpdateSubTask{SubtaskID: subtask.SubTaskID, Status: imagesecModel.TaskStatusSendFinished}
		// 发送成功的状态要同步更新，可能会重复发送
		// 同步更新任务状态状态，不然会重复发送
		upChan <- up

		s.Log.Info().Str("msgID", req.MsgID).Int64("taskID", subtask.TaskID).
			Int64("subtaskID", subtask.SubTaskID).Msg("Dispatcher publish scan subtask succeed")
	}
}

func (s *TaskDispatcher) PublishRegImageSubtaskHelper(ctx context.Context, subTaskChan chan imagesecTypes.ScanSubTask,
	upChan chan types.UpdateSubTask) {
	s.Log.Info().Msg("Dispatcher start PublishSubtask")

	ticker := time.NewTicker(time.Second * 1) // 限速

	defer ticker.Stop()

	for subtask := range subTaskChan {
		<-ticker.C
		s.Log.Info().Int64("subtaskID", subtask.SubTaskID).Int64("taskID", subtask.TaskID).
			Str("image", subtask.RegImageMeta.ImageName()).Str("scannerClusterName", subtask.ScanInstance.ClusterName).
			Msg("Dispatcher get registry image scan subtask")

		data, err := json.Marshal(subtask)
		if err != nil {
			s.Log.Err(err).Int64("taskID", subtask.TaskID).Int64("subtaskID", subtask.SubTaskID).
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
		req.MsgID = s.GenReqID(req)

		s.Log.Debug().Str("reg", ReqLogStr(req)).Msg("Dispatcher sendMsg")

		if err := s.DoSendSubtaskRpc(ctx, req); err != nil {
			s.Log.Err(err).Str("msgID", req.MsgID).Int64("taskID", subtask.TaskID).
				Int64("subtaskID", subtask.SubTaskID).Interface("image", subtask.RegImageMeta).
				Msg("Dispatcher failed to publish task by grpc stream")

			up := types.UpdateSubTask{SubtaskID: subtask.SubTaskID, Err: err, Status: imagesecModel.TaskStatusFailed,
				Reason: imagesecModel.TaskFailedReasonSendScanner}

			go func() { upChan <- up }()

			continue
		}

		up := types.UpdateSubTask{SubtaskID: subtask.SubTaskID, Status: imagesecModel.TaskStatusSendFinished, ScanUUID: subtask.ScanInstance.ScannerPodID}
		// 发送成功的状态及 scanUUID,要同步更新ScanUUID，不然会重复发送任务
		upChan <- up

		s.Log.Info().Str("msgID", req.MsgID).Str("subtask", subtask.LogStr()).Msg("Dispatcher publish scan subtask succeed")
	}
}

func (s *TaskDispatcher) PublishSubtask(ctx context.Context) error {
	if !scannerUtils.MainCluster() {
		s.Log.Info().Msg("Dispatcher not in main cluster did not PublishSubtask")
		return nil
	}

	s.streamClient = imagesecStream.MustGetGrpcStream()

	s.Log.Info().Msg("Dispatcher PublishSubtask task dispatcher started")

	scanNodeImageQueue := nodeImageTask.NewScanImageQueue(s.taskDal, s.nodeImageSrv, s.nodeInfoDal, s.sensitiveRuleDal)
	go func(dequeue types.ScanImageTaskDequeue) {
		defer func() {
			if err := recover(); err != nil {
				s.Log.Error().Stack().Str("Stack", string(debug.Stack())).Msg("Dispatcher recover")
			}
		}()
		s.Log.Info().Str("scanTaskType", imagesecModel.ImageFromNode).Msg("Dispatcher start")
		subtaskChan := dequeue.GenSubtaskChan(ctx)
		upSubtaskChan := dequeue.GenUpdateSubtaskChan(ctx)
		s.PublishNodeImageSubtaskHelper(ctx, subtaskChan, upSubtaskChan)
	}(scanNodeImageQueue)

	scanRegImageQueue := regImageTask.NewScanRegImageQueue(
		s.taskDal, s.nodeImageSrv, s.scannerInstanceDal,
		s.sensitiveRuleDal, s.scanImageConfigDal, s.scanResultDal,
		s.dbMetaDal,
	)

	go func(dequeue types.ScanImageTaskDequeue) {
		defer func() {
			if err := recover(); err != nil {
				s.Log.Error().Stack().Str("Stack", string(debug.Stack())).Msg("Dispatcher recover")
			}
		}()
		s.Log.Info().Str("scanTaskType", imagesecModel.ImageFromRegistry).Msg("Dispatcher start")
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
				s.Log.Error().Stack().Str("Stack", string(debug.Stack())).Msg("ExecutorScanMalicious panic")
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
			s.Log.Error().Str("reg", ReqLogStr(req)).Msg("send scan subtask to rpc")
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
		s.Log.Err(err).Interface("req", req).Msg("Dispatcher sendScanSubtask")
		return err
	}
	if rsp.Status != consts.StreamStatusOK {
		s.Log.Error().Str("req", ReqLogStr(req)).Interface("resp", rsp).Msg("Dispatcher sendScanSubtask")
		return err
	}
	// if rsp.GetBizCode() != consts.StreamStatusStartScanTask {
	// 	err = fmt.Errorf("publish task response err code:%v", rsp.Status)
	// 	return err
	// }
	return nil
}

func (s *TaskDispatcher) GenReqID(req *pb.ImageSecReq) string {
	return fmt.Sprintf("%s-%s", req.ImageSecReqType.String(), uuid.New().String())
}

func ReqLogStr(reg *pb.ImageSecReq) string {
	ss := fmt.Sprintf("ClusterKey:%s,MsgID:%s,NodeName:%s", reg.ClusterKey, reg.MsgID, reg.NodeName)
	return ss
}
