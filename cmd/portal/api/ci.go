package api

import (
	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/ci"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type CiApiSrv struct {
	Component ci.CiComponent
}

func NewCiSrv(c ci.CiComponent) *CiApiSrv {
	return &CiApiSrv{Component: c}
}

func (c *CiApiSrv) GetImageTop5(ctx *gin.Context) {
	res, err := c.Component.IM.GetImageTop5(ctx)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res))
}

func (c *CiApiSrv) GetImageOverView(ctx *gin.Context) {
	interval := util.GetInt64FromQuery(ctx, "interval")
	res, err := c.Component.IM.GetImageOverView(ctx, int(interval))
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res))
}
