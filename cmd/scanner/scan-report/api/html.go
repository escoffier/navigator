package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ExportHtmlApiSrv struct {
	ExportHtmlDriver map[string]types.ExportHtmlInterface
	ExportSrv        service.ExportTaskInterface
}

func (s *ExportHtmlApiSrv) GetImageIdNames(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	driver, err := s.GetExportHtmlDriver(ctx, taskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res, err := driver.GetImageIdNames(ctx, taskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res))
}

func (s *ExportHtmlApiSrv) GetRiskOverView(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	driver, err := s.GetExportHtmlDriver(ctx, taskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res, err := driver.GetRiskOverView(ctx, taskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res))
}

func (s *ExportHtmlApiSrv) GetImages(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	startID := util.GetInt64FromQuery(ctx, "startID")
	driver, err := s.GetExportHtmlDriver(ctx, taskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res, err := driver.GetImages(ctx, taskID, startID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res))
}

func (s *ExportHtmlApiSrv) GetImageVulns(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	startID := util.GetInt64FromQuery(ctx, "startID")
	imageID := util.GetInt64FromQuery(ctx, "imageID")

	severity := imagesec.GetSeverityInt(ctx.Query("severity"))
	if severity <= model.SeverityNegligibleInt || severity > model.SeverityCriticalInt {
		response.JSONError(ctx, fmt.Errorf("no severity"))
		return
	}
	driver, err := s.GetExportHtmlDriver(ctx, taskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res, err := driver.GetImageVuln(ctx, types.GetExportVulnParam{
		TaskID:   taskID,
		ImageID:  imageID,
		Severity: severity,
		StartID:  startID,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res))
}

func (s *ExportHtmlApiSrv) GetExportVulns(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	startID := util.GetInt64FromQuery(ctx, "startID")
	limit := util.GetInt64FromQuery(ctx, "limit")

	severity := imagesec.GetSeverityInt(ctx.Query("severity"))
	if severity <= 0 || severity > imagesec.SeverityCriticalInt {
		response.JSONError(ctx, fmt.Errorf("no severity"))
		return
	}

	canFixed := ctx.Query("canFixed")

	if canFixed != consts.TrueString && canFixed != consts.FalseString {
		response.JSONError(ctx, fmt.Errorf("no fixed"))
		return
	}

	driver, err := s.GetExportHtmlDriver(ctx, taskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res, err := driver.GetExportVuln(ctx, types.GetExportVulnParam{
		TaskID:   taskID,
		Severity: severity,
		CanFixed: canFixed,
		StartID:  startID,
		Limit:    limit,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res))
}

func (s *ExportHtmlApiSrv) GetVirus(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	driver, err := s.GetExportHtmlDriver(ctx, taskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	virus, err := driver.GetVirus(ctx, taskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(virus))
}

func (s *ExportHtmlApiSrv) GetImageRisk(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "taskID")
	imageID := util.GetInt64FromQuery(ctx, "imageID")
	driver, err := s.GetExportHtmlDriver(ctx, taskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	imageRisk, err := driver.GetImageRisk(ctx, taskID, imageID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(imageRisk))
}

func (s *ExportHtmlApiSrv) GetExportHtmlDriver(ctx *gin.Context, taskID int64) (types.ExportHtmlInterface, error) {
	task, err := s.ExportSrv.GetExportTask(ctx, types.GetExportTaskParam{ID: taskID})
	if err != nil {
		return nil, err
	}
	if task.TaskType != imagesec.ExportHtml {
		return nil, fmt.Errorf("not html export")
	}
	dir, ok := s.ExportHtmlDriver[task.ExecuteType]
	if !ok || dir == nil {
		return nil, fmt.Errorf("not find the driver:%s", task.ExecuteType)
	}
	return dir, nil
}

func NewExportHtmlApiSrv(exportHtmlDriver map[string]types.ExportHtmlInterface,
	exportSrv service.ExportTaskInterface) *ExportHtmlApiSrv {
	return &ExportHtmlApiSrv{ExportHtmlDriver: exportHtmlDriver, ExportSrv: exportSrv}
}
