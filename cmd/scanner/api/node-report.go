package api

import (
	"github.com/gin-gonic/gin"

	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type NodeReportAPISrv struct {
	nodeSrv imagesecSrv.NodeReportService
}

func NewNodeReportAPISrv(nodeSrv imagesecSrv.NodeReportService) *NodeReportAPISrv {
	return &NodeReportAPISrv{nodeSrv: nodeSrv}
}

func (s *NodeReportAPISrv) SearchNode(ctx *gin.Context) {
	param := imagesecModel.SearchNodeInfoParam{
		Keyword: util.GetKeywordFromQuery(ctx, "keyword"),
		Filter:  model.GetFilter(ctx).SetDefault().SetMaxLimit(consts.DefaultLimit),
	}

	node, cnt, err := s.nodeSrv.SearchNode(ctx, param)
	if err != nil {
		response.JSONError(ctx, response.SearchErr(err))
		return
	}
	response.JSONOK(ctx, response.WithItems(node),
		response.WithTotalItems(int64(cnt)),
		response.WithItemsPerPage(param.Filter.Limit),
		response.WithStartIndex(param.Filter.Offset))
}
