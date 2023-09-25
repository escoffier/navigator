package mainscanner

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/google/uuid"
	"gitlab.com/security-rd/go-pkg/logging"

	imagesecStream "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/stream"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

type DispatchDBSrv struct {
	ScanDbMetaDal   imagesecStore.ScanDbMetaDal
	NodeInfoDal     imagesecStore.NodeInfoDal
	ScanInstanceDal imagesecStore.ScanInstanceDal
	RpcClient       rpcstream.MessageStream
}

func NewDispatchDBSrv(
	scanDbMetaDal imagesecStore.ScanDbMetaDal,
	nodeInfoDal imagesecStore.NodeInfoDal,
	scanInstanceDal imagesecStore.ScanInstanceDal,
) *DispatchDBSrv {
	srv := &DispatchDBSrv{
		ScanDbMetaDal:   scanDbMetaDal,
		NodeInfoDal:     nodeInfoDal,
		ScanInstanceDal: scanInstanceDal,
	}
	return srv
}

func (s *DispatchDBSrv) SendToSubScanner(ctx context.Context) error {

	if !scannerUtils.MainCluster() {
		logging.Get().Info().Str("module", "imagescan").Msg("not in main cluster do not send db")
		return nil
	}

	if s.RpcClient == nil {
		s.RpcClient = imagesecStream.MustGetGrpcStream()
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("SendToSubScanner recover")
			}
		}()

		ticker := time.NewTicker(time.Minute * 10)
		defer ticker.Stop()

		for {
			<-ticker.C
			lastDb, err := s.ScanDbMetaDal.GetLastDBVersion(ctx)
			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("SendToSubScanner")
				continue
			}

			ins, err := s.ScanInstanceDal.SearchScannerInfo(ctx, imagesecModel.ScanInstanceParam{})

			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("SendToSubScanner")
				continue
			}
			for i := range ins {
				if ins[i].AviraDB != lastDb.AviraDB.DBVersion {
					_ = s.sendToSubScannerHelper(ctx, lastDb.AviraDB.DBMeta.DBPathInfo, ins[i], pb.ImageSecReqType_AviraDBUpdate)
				}
				if ins[i].AviraDB != lastDb.ClamavDB.DBVersion {
					_ = s.sendToSubScannerHelper(ctx, lastDb.AviraDB.DBMeta.DBPathInfo, ins[i], pb.ImageSecReqType_ClamavDBUpdate)
				}
			}
		}
	}()
	return nil
}

func (s *DispatchDBSrv) SendToNode(ctx context.Context) error {
	if !scannerUtils.MainCluster() {
		logging.Get().Info().Str("module", "imagescan").Msg("not in main cluster do not send db")
		return nil
	}
	if s.RpcClient == nil {
		s.RpcClient = imagesecStream.MustGetGrpcStream()
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("SendToSubScanner recover")
			}
		}()

		ticker := time.NewTicker(time.Minute * 10)
		defer ticker.Stop()
		for {
			<-ticker.C
			lastDb, err := s.ScanDbMetaDal.GetLastDBVersion(ctx)
			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("SendToSubScanner")
				continue
			}

			nodes, _, err := s.NodeInfoDal.SearchNodeInfo(ctx, imagesecModel.SearchNodeInfoParam{})

			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("SendToSubScanner")
				continue
			}
			for i := range nodes {
				if nodes[i].AviraDB != lastDb.AviraDB.DBVersion {
					_ = s.sendToNodeHelper(ctx, lastDb.AviraDB.DBMeta.DBPathInfo, nodes[i], pb.ImageSecReqType_AviraDBUpdate)
				}
				if nodes[i].ClamavDB != lastDb.ClamavDB.DBVersion {
					_ = s.sendToNodeHelper(ctx, lastDb.AviraDB.DBMeta.DBPathInfo, nodes[i], pb.ImageSecReqType_ClamavDBUpdate)
				}
			}
		}
	}()
	return nil
}

func (s *DispatchDBSrv) sendToSubScannerHelper(ctx context.Context, dbPath imagesecModel.DBPathInfo, node imagesecModel.ScannerInstanceInfo,
	imageSecReqType pb.ImageSecReqType) error {
	// 重新加载之后要删除
	fileContent, err := os.ReadFile(dbPath.UpdateZipFilename)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("filename", dbPath.UpdateZipFilename).Msg("ReadFile")
		return err
	}

	secReq := &pb.ImageSecReq{
		ImageSecReqType: imageSecReqType,
		ImageSecDstType: pb.ImageSecDstType_SubScanner,
		ImageSecDstPath: node.ClusterKey,
		ClusterKey:      node.ClusterKey,
		RequestID:       time.Now().String(),
		Payload:         fileContent,
	}
	resp, err := s.RpcClient.ScannerPushImageSecMsg(ctx, secReq)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("clusterKey", node.ClusterKey).Msg("ScannerPushImageSecMsg")
		return err
	}
	if resp.Status > 0 {
		logging.Get().Info().Str("module", "imagescan").Str("clusterKey", node.ClusterKey).Int32("status", resp.Status).
			Msg("ScannerPushImageSecMsg")
		return fmt.Errorf("status:%d msg:%s", resp.Status, resp.StatusMessage)
	}
	return nil
}

func (s *DispatchDBSrv) sendToNodeHelper(ctx context.Context, dbPath imagesecModel.DBPathInfo, node *imagesecModel.NodeInfo,
	imageSecReqType pb.ImageSecReqType) error {
	// 重新加载之后要删除
	fileContent, err := os.ReadFile(dbPath.UpdateZipFilename)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("filename", dbPath.UpdateZipFilename).Msg("ReadFile")
		return err
	}

	secReq := &pb.ImageSecReq{
		ImageSecReqType: imageSecReqType,
		NodeName:        []string{node.Hostname},
		ClusterKey:      node.ClusterKey,
		RequestID:       uuid.New().String(),
		Payload:         fileContent,
	}
	resp, err := s.RpcClient.ScannerPushImageSecMsg(ctx, secReq)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("clusterKey", node.ClusterKey).Msg("sendToNodeHelper")
		return err
	}
	if resp.Status > 0 {
		logging.Get().Info().Str("module", "imagescan").Str("clusterKey", node.ClusterKey).Int32("status", resp.Status).
			Msg("ScannerPushImageSecMsg")
		return fmt.Errorf("status:%d msg:%s", resp.Status, resp.StatusMessage)
	}
	logging.Get().Info().Str("module", "imagescan").Int("imageSecReqType", int(imageSecReqType)).Interface("dbPath", dbPath).
		Interface("node", node).Msg("send to node ok")
	return nil
}
