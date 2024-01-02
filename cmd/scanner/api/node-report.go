package api

import (
	"github.com/gin-gonic/gin"

	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
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
		Filter:  imagesecModel.GetFilter(ctx).SetDefault().SetMaxLimit(consts.DefaultMaxLimit),
	}

	node, cnt, err := s.nodeSrv.SearchNode(ctx, param)
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}
	response.JSONOK(ctx, response.WithItems(node),
		response.WithTotalItems(int64(cnt)),
		response.WithItemsPerPage(param.Filter.Limit),
		response.WithStartIndex(param.Filter.Offset))
}
