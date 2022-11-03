package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export/html"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ExportHtmlApiSrv struct {
	ExportHtmlInterface html.ExportHtmlInterface
}

func (s *ExportHtmlApiSrv) GetImageIdNames(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	res, err := s.ExportHtmlInterface.GetImageIdNames(ctx, taskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res))
}

func (s ExportHtmlApiSrv) GetRiskOverView(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	res, err := s.ExportHtmlInterface.GetRiskOverView(ctx, taskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res))
}

func (s ExportHtmlApiSrv) GetImages(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	startID := util.GetInt64FromQuery(ctx, "startID")
	res, err := s.ExportHtmlInterface.GetImages(ctx, taskID, startID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res))
}

func (s ExportHtmlApiSrv) GetImageVulns(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	startID := util.GetInt64FromQuery(ctx, "startID")
	imageID := util.GetInt64FromQuery(ctx, "imageID")

	severity := model.GetSeverityInt(ctx.Query("severity"))
	if severity <= model.SeverityNegligibleInt || severity > model.SeverityCriticalInt {
		response.JSONError(ctx, fmt.Errorf("no severity"))
		return
	}

	res, err := s.ExportHtmlInterface.GetImageVulns(ctx, taskID, imageID, severity, startID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res))
}

func (s ExportHtmlApiSrv) GetExportVulns(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	startID := util.GetInt64FromQuery(ctx, "startID")
	limit := util.GetInt64FromQuery(ctx, "limit")

	severity := model.GetSeverityInt(ctx.Query("severity"))
	if severity <= model.SeverityNegligibleInt || severity > model.SeverityCriticalInt {
		response.JSONError(ctx, fmt.Errorf("no severity"))
		return
	}

	canFixed := ctx.Query("canFixed")

	if canFixed != consts.TrueString && canFixed != consts.FalseString {
		response.JSONError(ctx, fmt.Errorf("no fixed"))
		return
	}

	res, err := s.ExportHtmlInterface.GetExportVulns(ctx, taskID, severity, canFixed, startID, limit)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res))
}

func (s ExportHtmlApiSrv) GetVirus(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	virus, err := s.ExportHtmlInterface.GetVirus(ctx, taskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(virus))
}

func (s ExportHtmlApiSrv) GetImageRisk(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	imageID := util.GetInt64FromQuery(ctx, "imageID")
	imageRisk, err := s.ExportHtmlInterface.GetImageRisk(ctx, taskID, imageID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(imageRisk))
}

func NewExportHtmlApiSrv(ExportHtmlInterface html.ExportHtmlInterface) *ExportHtmlApiSrv {
	return &ExportHtmlApiSrv{ExportHtmlInterface: ExportHtmlInterface}
}
