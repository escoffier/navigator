package imagesec

import (
	"context"

	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type NodeReportService interface {
	SearchNode(ctx context.Context, param imagesecModel.SearchNodeInfoParam) ([]*imagesecModel.NodeInfo, int64, error)
}

type NodeReportSrv struct {
	nodeInfoDal imagesecStore.NodeInfoDal
	Log         *scannerUtils.LogEvent
}

func NewNodeReportSrv(nodeInfoDal imagesecStore.NodeInfoDal) *NodeReportSrv {
	return &NodeReportSrv{
		nodeInfoDal: nodeInfoDal,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("NodeReportSrv"),
			scannerUtils.WithModule(consts.ModuleImagesecSrv))}
}

func (s *NodeReportSrv) SearchNode(ctx context.Context, param imagesecModel.SearchNodeInfoParam) (
	[]*imagesecModel.NodeInfo, int64, error) {
	nods, cnt, err := s.nodeInfoDal.SearchNodeInfo(ctx, param)
	if err != nil {
		s.Log.Err(err).Interface("param", param).Msg("SearchNode")
		return nil, 0, scani18.SearchNode(err)
	}

	return nods, cnt, nil
}
