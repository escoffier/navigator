package imagesec

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type NodeReportService interface {
	SearchNode(ctx context.Context, param imagesecModel.SearchNodeInfoParam) ([]*imagesecModel.NodeInfo, int64, error)
}

type NodeReportSrv struct {
	nodeInfoDal imagesecStore.NodeInfoDal
}

func NewNodeReportSrv(nodeInfoDal imagesecStore.NodeInfoDal) *NodeReportSrv {
	return &NodeReportSrv{nodeInfoDal: nodeInfoDal}
}

func (s *NodeReportSrv) SearchNode(ctx context.Context, param imagesecModel.SearchNodeInfoParam) (
	[]*imagesecModel.NodeInfo, int64, error) {
	nods, cnt, err := s.nodeInfoDal.SearchNodeInfo(ctx, param)
	if err != nil {
		logging.Get().Err(err).Interface("param", param).Msg("SearchNode")
		return nil, 0, err
	}

	return nods, cnt, nil
}
