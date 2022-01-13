package openapi

import (
	"errors"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/api/model/vuln"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/openapi"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type VulnServer struct {
	service *openapi.VulnService
}

func NewVulnServer(psql *rdbtools.GormWrapper) *VulnServer {
	return &VulnServer{
		service: openapi.NewVulnService(psql),
	}
}

func (v *VulnServer) List(ctx *gin.Context) {
	var req vuln.ListReq
	if err := ctx.BindQuery(&req); err != nil {
		response.JSONError(ctx, errors.New("parse request params error"))
		return
	}

	// default value: 10
	if req.Limit == 0 {
		req.Limit = 10
	}

	if req.Limit > 100 {
		response.JSONError(ctx, errors.New("param limit exceeds 100"))
		return
	}

	data, count, err := v.service.List(ctx, &req)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	vulns := vuln.ListResp{}
	vulns.Build(data)

	response.JSONOK(ctx, response.WithItems(vulns),
		response.WithTotalItems(count),
		response.WithItemsPerPage(int64(req.Limit)),
		response.WithStartIndex(int64(req.Offset)))
}

func (v *VulnServer) Detail(ctx *gin.Context) {
	var req vuln.DetailReq
	if err := ctx.BindUri(&req); err != nil {
		response.JSONError(ctx, errors.New("parse request params error"))
		return
	}

	if req.Name == "" {
		response.JSONError(ctx, errors.New("the vuln name is empty"))
		return
	}

	data, err := v.service.Detail(ctx, &req)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	detail := vuln.DetailResp{}
	detail.Build(data)

	response.JSONOK(ctx, response.WithItem(detail))
}

func (v *VulnServer) Statistic(ctx *gin.Context) {
	countBySeverity, err := v.service.CountBySeverity(ctx)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	if countBySeverity == nil {
		response.JSONError(ctx, errors.New("vulns' statistic is empty"))
		return
	}

	top5, err := v.service.CountTopN(ctx, 5)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	var res vuln.StatisticResp
	res.BuildCountBySeverity(countBySeverity).BuildCountByTops(top5)

	response.JSONOK(ctx, response.WithItem(res))
}
