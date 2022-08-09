package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	rkentry "github.com/rookie-ninja/rk-entry/entry"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/service"
)

func SetupGinRouter(exportSrv service.ExportInterface) *gin.Engine {

	router := gin.Default()
	router.MaxMultipartMemory = 2 << 20

	router.Use(gin.Logger(), gin.Recovery())

	exportApiSrv := NewExportApiSrv(exportSrv)

	v1 := router.Group("/api/v1/export/task")
	{
		v1.POST("/image", exportApiSrv.CreateImageExportTask)
		v1.POST("/scanTask", exportApiSrv.CreateScanResultExportTask)
		v1.POST("/naviAudit", exportApiSrv.CreateAuditExportTask)
		v1.POST("/vuln", exportApiSrv.CreateVulnExportTask)
		v1.GET("/checkScanTask", exportApiSrv.CheckScanTask)
		v1.GET("/detail", exportApiSrv.GetExportTaskDetail)
		v1.GET("/list", exportApiSrv.GetReportTaskList)
		v1.GET("/download", exportApiSrv.DownLoad)
	}

	return router
}

func GenStaticFileHandlerEntry(fileDir string) *rkentry.StaticFileHandlerEntry {
	return rkentry.RegisterStaticFileHandlerEntry(
		rkentry.WithFileSystemStatic(http.Dir(fileDir)),
		rkentry.WithPathStatic("/api/v1/export/file"))
}
