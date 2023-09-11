package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	rkentry "github.com/rookie-ninja/rk-entry/entry"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
)

func SetupGinRouter(exportSrv service.ExportTaskInterface, exportHtmlDriver map[string]types.ExportHtmlInterface) *gin.Engine {

	router := gin.Default()
	router.MaxMultipartMemory = 2 << 20

	router.Use(gin.Logger(), gin.Recovery(), LangMiddleware)

	exportApiSrv := NewExportApiSrv(exportSrv)

	exportHtmlApiSrv := NewExportHtmlApiSrv(exportHtmlDriver, exportSrv)

	v1 := router.Group("/api/v1/export/task")
	{
		v1.POST("/image", exportApiSrv.CreateImageExportTask)
		v1.POST("/scanTask", exportApiSrv.CreateScanResultExportTask)
		v1.POST("/vuln", exportApiSrv.CreateVulnExportTask)
		v1.POST("/imageSearch", exportApiSrv.CreateImageSearchExportTask)
		v1.POST("/naviAudit", exportApiSrv.CreateAuditExportTask)
		v1.POST("/yaml", exportApiSrv.CreateYamlExportTask)
		v1.POST("/dockerfile", exportApiSrv.CreateDockerfileExportTask)
		v1.GET("/checkScanTask", exportApiSrv.CheckScanTask)
		v1.GET("/detail", exportApiSrv.GetExportTaskDetail)
		v1.GET("/list", exportApiSrv.GetReportTaskList)
		v1.GET("/download", exportApiSrv.DownLoad)
	}

	v2 := router.Group("/api/v1/export/html")
	{
		v2.GET("/images", exportHtmlApiSrv.GetImages)
		v2.GET("/imageIdNames", exportHtmlApiSrv.GetImageIdNames)
		v2.GET("/riskOverView", exportHtmlApiSrv.GetRiskOverView)
		v2.GET("/imageRisk", exportHtmlApiSrv.GetImageRisk)
		v2.GET("/exportVulns", exportHtmlApiSrv.GetExportVulns)
		v2.GET("/imageVulns", exportHtmlApiSrv.GetImageVulns)
		v2.GET("/imageVirus", exportHtmlApiSrv.GetVirus)
	}

	return router
}

func LangMiddleware(ctx *gin.Context) {
	lang := strings.ToLower(ctx.GetHeader("Accept-Language"))
	if lang == "" {
		lang = strings.ToLower(ctx.GetHeader("accept-language"))
	}
	if lang != consts.LangEN {
		lang = consts.LangCH
	}
	ctx.Set(consts.LangKey, strings.ToLower(lang))
	ctx.Next()
}

func GenStaticFileHandlerEntry(fileDir string) *rkentry.StaticFileHandlerEntry {
	return rkentry.RegisterStaticFileHandlerEntry(
		rkentry.WithFileSystemStatic(http.Dir(fileDir)),
		rkentry.WithPathStatic("/api/v1/export/file"))
}
