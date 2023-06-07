// Package dispatcher dispatch task to daemon or scanner
package dispatcher

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/dispatcher/dequeuers"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/stream"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	imageModel "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	serviceName        = "test-task-dispatcher"
	dispatchInterval   = 30
	defaultGrpcTimeout = 60
)

type Dispatcher struct {
	streamClient rpcstream.MessageStream
}

func (d *Dispatcher) Start(_ context.Context) error {
	logging.Get().Info().Msg("task dispatcher started")

	// get grpc client
	d.streamClient = stream.MustGetGrpcClient()
	logging.Get().Debug().Msg("get grpc client ok")

	updateTaskDBStatusFunc := func(taskID int64, err error) {
		// todo:
	}

	publishTaskFunc := func(t imageModel.ScanSubTask) error {
		logging.Get().Debug().Int64("taskID", t.TaskID).Msg("ready to publish task")

		var err error

		defer func() {
			updateTaskDBStatusFunc(t.TaskID, err)
		}()

		clusterKey := t.NodeInfo.ClusterKey
		dstNodes := make([]string, 0)
		dstNodes = append(dstNodes, t.NodeInfo.HostName)

		data, err := json.Marshal(t)
		if err != nil {
			logging.Get().Err(err).Msg("failed to marshal task")
			return err
		}
		req := &pb.ImageSecReq{
			ImageSecReqType: pb.ImageSecReqType_NodeImageScan,
			ClusterKey:      clusterKey,
			NodeName:        dstNodes,
			Payload:         data,
		}
		ctx, cancel := context.WithTimeout(context.Background(), defaultGrpcTimeout*time.Second)
		defer cancel()
		rsp, err := d.streamClient.ScannerPushImageSecMsg(ctx, req)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", t.TaskID).Msg("failed to publish task by grpc stream")
			return err
		}
		if rsp.Status != 0 {
			err = fmt.Errorf("publish task response err code:%v", rsp.Status)
			logging.Get().Err(err).Int64("taskID", t.TaskID).Msg("failed to publish task,rsp err code")
			return err
		}
		logging.Get().Info().Int64("taskID", t.TaskID).Msg("publish node image task ok")
		return nil
	}

	// all dequeuer pop tasks.each dequeuer has different dequeue policy
	for {
		time.Sleep(dispatchInterval * time.Second)

		tasks, err := dequeuers.PopTasks()
		if err != nil {
			logging.Get().Err(err).Msg("failed to pop tasks.")
			continue
		}
		logging.Get().Debug().Interface("tasks", tasks).Msg("pop tasks")

		for _, t := range tasks {
			_ = publishTaskFunc(t)
		}
	}

}

func (d *Dispatcher) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.Get().Err(err).Str("serviceName", serviceName).Msg("failed to register service")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	d := &Dispatcher{}
	return d, nil
}
