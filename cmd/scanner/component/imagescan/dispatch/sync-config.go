package dispatch

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	imagesecStream "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/stream"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanImageConfigSyncService interface {
	SyncConfig(ctx context.Context) error
}

type ScanImageConfigSyncSrv struct {
	configDal   imagesecStore.ScanImageConfigDal
	nodeInfoSrv types.NodeReportService
}

func (s *ScanImageConfigSyncSrv) SyncConfig(ctx context.Context) error {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("panic: %v.stack:%s", r, debug.Stack())
			}
		}()

		ticker := time.NewTicker(time.Minute * 5)
		defer ticker.Stop()
		for {
			t := <-ticker.C
			logging.Get().Info().Str("module", "imagescan").Int64("syncTime", t.Unix()).Msg("ScanImageConfigSyncSrv start sync config")
			if err := s.syncConfig(ctx); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Int64("syncTime", t.Unix()).Msg("ScanImageConfigSyncSrv start sync scan config fail")
				continue
			}
			logging.Get().Info().Str("module", "imagescan").Int64("syncTime", t.Unix()).Msg("ScanImageConfigSyncSrv sync scan config succeed")
		}
	}()
	return nil
}

func (s *ScanImageConfigSyncSrv) syncConfig(ctx context.Context) error {
	grpcClient := imagesecStream.MustGetGrpcStream()

	scanImageCfg, err := s.configDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("ScanImageConfigSyncSrv failed to get scan image config")
		return err
	}

	// get all cluster nodes
	nodes, _, err := s.nodeInfoSrv.SearchNode(ctx, imagesecModel.SearchNodeInfoParam{})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("ScanImageConfigSyncSrv failed to get nodes")
		return err
	}

	// group by cluster
	clusterNodes := make(map[string][]string)
	for _, n := range nodes {
		clusterNodes[n.ClusterKey] = append(clusterNodes[n.ClusterKey], n.Hostname)
	}
	logging.Get().Info().Str("module", "imagescan").Int("clusterCnt", len(clusterNodes)).Msg("ready to publish config to cluster")

	// publish config by cluster
	msgData, err := json.Marshal(scanImageCfg.ImageScanConfig)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("ScanImageConfigSyncSrv failed to marshal node image config")
		return err
	}
	_ = s.publishConfigByCluster(grpcClient, clusterNodes, msgData)
	logging.Get().Info().Str("module", "imagescan").Int("clusterCnt", len(clusterNodes)).Msg("ScanImageConfigSyncSrv publish config to all cluster end")
	return nil
}

func (s *ScanImageConfigSyncSrv) publishConfigByCluster(grpcClient rpcstream.MessageStream, clusterNodes map[string][]string, msgData []byte) error {
	var retErr error
	for k, ns := range clusterNodes {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(util.ImageSecGrpcTimeOut())*time.Second)
			defer cancel()
			reqID := uuid.New().String()
			req := &pb.ImageSecReq{
				ImageSecReqType: pb.ImageSecReqType_SyncConfig,
				ClusterKey:      k,
				NodeName:        ns,
				RequestID:       reqID,
				Payload:         msgData,
			}
			rsp, err := grpcClient.ScannerPushImageSecMsg(ctx, req)
			if err != nil {
				retErr = multierror.Append(retErr, err)
				logging.Get().Err(err).Str("module", "imagescan").Str("cluster", k).Msg("ScanImageConfigSyncSrv failed to publish config to cluster")
				return
			}
			if rsp.Status != 0 {
				retErr = multierror.Append(retErr, fmt.Errorf("rsp status err.%v", rsp.Status))
				logging.Get().Error().Str("cluster", k).Int32("status", rsp.Status).
					Msg("ScanImageConfigSyncSrv failed to publish config to cluster,status err")
				return
			}
			logging.Get().Info().Str("module", "imagescan").Str("cluster", k).Msg("ScanImageConfigSyncSrv publish config to cluster ok")
		}()
	}
	return retErr
}

func NewScannerConfigSyncSrv(configDal imagesecStore.ScanImageConfigDal, nodeInfoSrv types.NodeReportService) *ScanImageConfigSyncSrv {
	return &ScanImageConfigSyncSrv{configDal: configDal, nodeInfoSrv: nodeInfoSrv}
}
