package api

// import (
// 	"github.com/gin-gonic/gin"
//
// 	openapi "gitlab.com/piccolo_su/vegeta/cmd/scanner/api/open-api"
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/ci"
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/service"
// 	scanReportService "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/service"
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
// )
//
// func OpenAPI(
// 	router *gin.Engine,
// 	scannerSvc component.ScannerSrv,
// 	rejectSvc component.ImageRejectSrv,
// 	registrySrv service.RegistryService,
// 	scanConfigSrv component.ScanConfigSrvInterface,
// 	vulnSrv component.VulnServiceInterface,
// 	ciDalSrv ci.CiComponent,
// 	imageSrv imagemeta.ImageService,
// 	exportSrv scanReportService.ExportTaskInterface,
// ) *gin.Engine {
//
// 	apiScannerSrv := openapi.NewScannerOpenAPISrv(scannerSvc, registrySrv, scanConfigSrv, imageSrv)
// 	apiRejectSrv := NewRejectAPISrv(rejectSvc)
// 	scanConfigAPISrv := openapi.NewScanConfigOpenAPISrv(scanConfigSrv)
// 	apiVulnSrc := openapi.NewVulnServer(vulnSrv, scannerSvc)
//
// 	openAPIRouter := router.Group("/openapi")
// 	// openApiRouter.Use(RateLimitMiddleware(redisClient, 20))
// 	// apiSyncImageSrv := NewSyncImageAPISrv(registrySrv)
// 	v1 := openAPIRouter.Group("/v1")
// 	{
// 		image := v1.Group("/images")
// 		{
// 			image.GET("/list", apiScannerSrv.ListImages) // Deprecated:
// 			image.POST("/list", apiScannerSrv.SearchImages)
// 			image.GET("/registryProject", apiScannerSrv.GetRegistryProject)
// 			image.POST("/scan/scantask/v2", apiScannerSrv.CreateScanTask) // Deprecated:
// 			image.POST("/scan/scantask", apiScannerSrv.CreateScanImageTask)
// 			image.GET("/detail", apiScannerSrv.GetImageDetails)
// 			image.GET("/layers", apiScannerSrv.ListImgLayersByImageName)
// 		}
//
// 		statistic := v1.Group("/statistic")
// 		{
// 			statistic.GET("/images", apiScannerSrv.ImageStatistic)
// 			statistic.GET("/vulns", apiVulnSrc.Statistic)
// 		}
//
// 		scanConfig := v1.Group("/scanConfig")
// 		{
// 			strategies := scanConfig.Group("/strategies")
// 			{
// 				strategies.POST("", scanConfigAPISrv.CreateStrategy2)
// 				strategies.GET("", scanConfigAPISrv.ListStrategy2)
// 				strategies.PUT("/:strategyName", scanConfigAPISrv.UpdateStrategyByName)
// 				strategies.DELETE("/:strategyName", scanConfigAPISrv.DeleteStrategyByName)
// 				strategies.GET("/:strategyName", scanConfigAPISrv.GetStrategyByName)
// 			}
// 		}
//
// 		vuln := v1.Group("/vulns")
// 		{
// 			vuln.GET("/list", apiVulnSrc.List)
// 			vuln.GET("/detail", apiVulnSrc.Detail)
// 			vuln.GET("/topNImage", apiVulnSrc.GetVulnTopNImage)
// 		}
//
// 		// ci
// 		ciSrv := NewCiSrv(ciDalSrv, exportSrv)
// 		cig := v1.Group("/ci")
// 		{
// 			cig.GET("/policies", ciSrv.GetCiPolicies)
// 			cig.GET("/policy/:name", ciSrv.GetCiPolicy)
// 			cig.GET("/tidb/version", ciSrv.TiDbVersion)
// 			cig.Static("/tidb/assets", global.ScannerOpts.PvcPath)
// 			cig.POST("/result", ciSrv.SaveResult)
// 			cig.POST("/sign", apiRejectSrv.SignImageTrusted)
// 		}
// 		// 和仓库相关
// 		register := v1.Group("/register")
// 		{
// 			register.GET("/registries", apiScannerSrv.SearchRegistry)
// 			register.PUT("/registry", apiScannerSrv.UpdateRegistry)
// 			register.DELETE("/registry", apiScannerSrv.DeleteRegistry)
// 			register.POST("/registry", apiScannerSrv.CreateRegistry)
// 		}
//
// 		// 和同步镜像相关
// 		// v12 := v1.Group("/syncImage")
// 		// {
// 		// v12.POST("/startSync", apiSyncImageSrv.StartSyncByRegName)
// 		// }
// 	}
//
// 	return router
// }
