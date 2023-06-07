package resultsync

import (
	"context"
	"encoding/json"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/stream"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	imageModel "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

const (
	serviceName = "result-sync"
)

type ResultSync struct {
}

func (r *ResultSync) Start(ctx context.Context) error {
	// get grpc stream client
	streamClient := stream.MustGetGrpcClient()

	// todo: get all cluster and nodes
	clusterKeys := make([]string, 0)
	nodes := make([]imageModel.NodeInfo, 0)
	for _, v := range clusterKeys {
		n := imageModel.NodeInfo{
			ClusterKey: v,
			HostName:   "a",
		}
		nodes = append(nodes, n)
	}

	//todo: select all scanned node images
	// only use node images scanned result for now
	scannedResults := make([]imageModel.SyncScannedResult, 0)
	for k := range scannedResults {
		scannedResults[k].Nodes = nodes
	}

	// push to all cluster
	data, _ := json.Marshal(scannedResults)
	req := &pb.ImageSecReq{
		Payload:         data,
		ImageSecReqType: pb.ImageSecReqType_SyncResult,
	}

	for _, v := range nodes {
		_, err := streamClient.DeliverImageSecMsg(context.Background(), v.HostName, req)
		if err != nil {
			logging.GetLogger().Err(err).Str("node", v.HostName).Msg("failed to sync scanned result")
		}
	}

	return nil
}

func (r *ResultSync) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("register service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	r := &ResultSync{}

	return r, nil
}
