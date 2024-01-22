package api

import (
	"os"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/ci"
	deploySrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/deployment"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	imagesecScanSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	regService "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scanReportService "gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/service"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func SetupGinRouter(
	imageSvc imagemeta.ImageService,
	rejectSvc imagesecSrv.TrustedImageService,
	registrySrv regService.RegistryService,
	scanResultSrv imagesecScanSrv.ScanResultService,
	ciDalSrv ci.CiComponent,
	scannerInfo imagesecSrv.ScanInstanceService,
	exportSrv scanReportService.ExportTaskInterface,
	policySrv detect.SecurityPolicyService,
	scanTaskSrv imagesecScanSrv.ScanTaskService,
	sensitiveRuleService imagesecSrv.SensitiveRuleService,
	scanImageConfigService imagesecSrv.ScanImageConfigService,
	nodeSrv imagesecSrv.NodeReportService,
	deployService deploySrv.DeployService,
	dBManager imagesecSrv.DBUpdateService,
) *gin.Engine {

	router := gin.New()
	gin.Default()
	gin.DisableConsoleColor() // 禁用请求日志控制台字体颜色
	router.MaxMultipartMemory = 2 << 20

	router.Use(gin.Recovery(), AddLanguage)

	ginMode := os.Getenv("LOGGING_LEVE")
	switch ginMode {
	case consts.LOGGINGDebug:
		router.Use(gin.Logger())
		gin.SetMode(gin.TestMode)
	default:
		gin.SetMode(gin.ReleaseMode)
	}

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "healthy",
		})
	})

	router = WebAPI(
		router,
		imageSvc,
		rejectSvc,
		registrySrv,
		scanResultSrv,
		ciDalSrv,
		scannerInfo,
		exportSrv,
		policySrv,
		scanTaskSrv,
		sensitiveRuleService,
		scanImageConfigService,
		nodeSrv,
		deployService,
		dBManager,
	)
	// 这一期先不管 openAPI
	router = OpenAPI(router, imageSvc, rejectSvc, ciDalSrv, exportSrv)
	// router = OpenAPI(router, scannerSvc, rejectSvc, registrySrv, scanConfigSrv,
	// 	scanResultSrv, ciDalSrv, imageSvc, syncImageSrv, exportSrv)

	return router
}

func WebAPI(router *gin.Engine,
	imageService imagemeta.ImageService,
	rejectSvc imagesecSrv.TrustedImageService,
	registrySrv regService.RegistryService,
	scanResultSrv imagesecScanSrv.ScanResultService,
	ciDalSrv ci.CiComponent,
	scannerInfo imagesecSrv.ScanInstanceService,
	exportSrv scanReportService.ExportTaskInterface,
	policySrv detect.SecurityPolicyService,
	scanTaskSrv imagesecScanSrv.ScanTaskService,
	sensitiveRuleService imagesecSrv.SensitiveRuleService,
	scanImageConfigService imagesecSrv.ScanImageConfigService,
	nodeSrv imagesecSrv.NodeReportService,
	deployService deploySrv.DeployService,
	dBManager imagesecSrv.DBUpdateService,
) *gin.Engine {
	apiRejectSrv := NewRejectAPISrv(rejectSvc)
	apiRegistrySrv := NewRegistrySrv(registrySrv, rejectSvc, scannerInfo)
	apiVulnSrv := NewVulnAPISrv(scanResultSrv)
	scanResultApi := NewScanResultAPI(imageService, scanResultSrv)

	imageBaseApi := NewImageInfoAPI(imageService)
	scanTaskAPI := NewScanTaskAPI(scanTaskSrv)
	nodeApiSrv := NewNodeReportAPISrv(nodeSrv)

	deployAPI := NewDeploySrv(deployService)

	configAPISrv := NewConfigAPISrv(sensitiveRuleService, scanImageConfigService, scanResultSrv, dBManager)
	v5 := router.Group("/api/v1/imagereject")
	{
		v5.POST("/online_moniter", deployAPI.CheckDeploy)

		trustedImageGroup := v5.Group("/trustedImages")
		{
			trustedImageGroup.GET("/rsa", apiRejectSrv.RSAList)
			trustedImageGroup.GET("/rsa/:id", apiRejectSrv.RSADetail)
			trustedImageGroup.POST("/rsa", apiRejectSrv.RSAGenerate)
			trustedImageGroup.PUT("/rsa/:id", apiRejectSrv.RSAUpdate)
			trustedImageGroup.DELETE("/rsa/:id", apiRejectSrv.RSADelete)
			trustedImageGroup.POST("/sign", apiRejectSrv.SignImageTrusted)
		}
	}

	// ci
	ciSrv := NewCiSrv(ciDalSrv, exportSrv)
	v14 := router.Group("/api/v1/ci")
	{
		v14.POST("/policy", ciSrv.CreateCiPolicy)
		v14.GET("/policy", ciSrv.CiPolicyDetail)
		v14.DELETE("/policy", ciSrv.DeleteCiPolicy)
		v14.GET("/policy/:name", ciSrv.GetCiPolicy)
		v14.PUT("/policy", ciSrv.UpdatePolicy)
		v14.GET("/policies", ciSrv.GetCiPolicyList)
		v14.POST("/whitelists", ciSrv.CreateWhitelist)
		v14.GET("/whitelist", ciSrv.GetWhitelist)
		v14.PUT("/whitelists", ciSrv.UpdateWhitelist)
		v14.GET("/image/whitelist", ciSrv.MatchWhitelist)
		v14.DELETE("/whitelist", ciSrv.DeleteWhitelist)
		v14.GET("/statistic/image", ciSrv.GetImageOverView)
		v14.GET("/statistic/top5", ciSrv.GetImageTop5)
		v14.GET("/images", ciSrv.GetImageList)
		v14.GET("/image", ciSrv.GetImageDetail)
		v14.POST("/vulnerability", ciSrv.MatchVulnerability)
		v14.POST("/result", ciSrv.SaveResult)
		v14.GET("/sensitives", ciSrv.GetSensitives)
		v14.GET("/vulns", ciSrv.GetRecordVulns)
		v14.GET("/vuln/detail", ciSrv.GetVulnDetail)
		v14.GET("/pkgs", ciSrv.GetRecordPkgs)
		v14.POST("/webhook", ciSrv.CreateWebhook)
		v14.PUT("/webhook", ciSrv.UpDateWebhook)
		v14.GET("/webhook", ciSrv.GetWebhook)
		v14.GET("/webhook/record", ciSrv.GetWebhookRecords)

		v14.GET("/tidb/version", ciSrv.TiDbVersion)
		v14.Static("/tidb/assets", global.ScannerOpts.PvcPath)
	}

	// 和同步镜像相关
	v12 := router.Group("/api/v1/syncImage")
	{
		v12.POST("/startSync", apiRegistrySrv.CreateSyncTask)
		v12.GET("/syncProgress", apiRegistrySrv.GetSyncProgress)
		v12.GET("/syncStatus", apiRegistrySrv.GetSyncStatus)

		v12.GET("/registries", apiRegistrySrv.SearchRegistry)
		v12.GET("/registry", apiRegistrySrv.GetRegistry)
		v12.PUT("/registry", apiRegistrySrv.UpdateRegistry)
		v12.POST("/registry", apiRegistrySrv.CreateRegistry)
		v12.DELETE("/registry", apiRegistrySrv.DeleteRegistry)
		v12.GET("/regType", apiRegistrySrv.GetRegistryType)
		v12.GET("/regions", apiRegistrySrv.GetRegions)
	}

	// 内部调用
	v13 := router.Group("/api/v1/internal")
	{
		v13.POST("/overview/image", imageBaseApi.RiskImageOverview)     // down
		v13.POST("/overview/registry", apiRegistrySrv.RegistryOverview) // down
	}

	scanInsSrv := NewScanInsAPISrv(scannerInfo)
	v15 := router.Group("/api/v1/scannerInfo")
	{
		v15.GET("/list", scanInsSrv.GetScanIns)
	}

	v2 := router.Group("/api/v1/images")
	{
		v2.GET("/sampleList", imageBaseApi.SearchImages)
		v2.GET("/verifyExistence", imageBaseApi.VerifyExistence)
		v2.GET("/existenceCount", imageBaseApi.ExistenceCount)
		v2.POST("/list", imageBaseApi.SearchImageWithScan)
		v2.POST("/assets/image", imageBaseApi.SearchAssetsImage)
		v2.GET("/overview", imageBaseApi.ImageOverview)
		v2.GET("/resource", imageBaseApi.SearchResources)         // 镜像详情中关联容器
		v2.GET("/related/image", imageBaseApi.SearchRelatedImage) // 关联镜像
		v2.POST("/baseImage", imageBaseApi.CreateBaseImage)
		v2.DELETE("/baseImage", imageBaseApi.DeleteBaseImage)
		v2.GET("/registryProject", imageBaseApi.GetRegistryProject)
		v2.GET("/detail/base", scanResultApi.ImageBaseDetail)
		v2.GET("/detail/issueStatistic", scanResultApi.ImageIssueStatistic)
		v2.GET("/detail/issueOverview", scanResultApi.SecurityIssueOverview)
		v2.GET("/detail/env", scanResultApi.SearchEnv)
		v2.GET("/detail/virus", scanResultApi.SearchVirus)
		v2.GET("/detail/sensitiveFile", scanResultApi.SearchSensitive)
		v2.GET("/detail/software", scanResultApi.SearchSoftware)
		v2.GET("/detail/vulns/vuln", scanResultApi.GetImageVulns)
		v2.GET("/detail/vulns/pkg", scanResultApi.GetImageVulnPkg)
		v2.GET("/detail/vulns/language", scanResultApi.GetImageVulnLanguage)
		v2.GET("/detail/vulns/gobinary", scanResultApi.GetImageVulnGoBinary)
		v2.GET("/detail/vulns/frame", scanResultApi.GetImageVulnFrame)
		v2.GET("/detail/webshell", scanResultApi.GetImageWebshell)
		v2.GET("/detail/baseImage", imageBaseApi.GetBaseImages)
		v2.GET("/detail/appImage", imageBaseApi.GetAppImages)
		v2.GET("/detail/license", imageBaseApi.GetLicense)
		v2.POST("/detail/riskInfo", scanResultApi.GetImageRiskInfo)
		v2.GET("/detail/layers", scanResultApi.GetImageLayer)
		v2.GET("/vulns/vuln/detail", scanResultApi.GetVulnDetail)
		v2.GET("/webshell/detail", scanResultApi.GetWebshellDetail)
		v2.GET("/webshell/content", scanResultApi.GetWebshellContent)
		v2.GET("/sensitive/detail", scanResultApi.GetSensitiveDetail)
		v2.GET("/malware/detail", scanResultApi.GetMalwareDetail)
		v2.GET("/webshell/file", scanResultApi.GetWebshellFile)
		v2.GET("/sensitive/file", scanResultApi.GetSensitiveFile)
		v2.GET("/malware/file", scanResultApi.GetMalwareFile)
		v2.GET("/license/file", scanResultApi.GetLicenseFile)
	}

	v4 := router.Group("/api/v1/vulns")
	{
		v4.GET("/list", apiVulnSrv.SearchVuln)                   //  漏洞发现列表：在线
		v4.GET("/statistic", apiVulnSrv.Statistic)               // down
		v4.GET("/topNImage", imageBaseApi.TopRiskImage)          // down
		v4.GET("/software", scanResultApi.SearchRelatedSoftware) // 和镜像详情中返回的数据不一样
		v4.GET("/query", imageBaseApi.GetImageByVuln)            // down
	}

	// 安全策略及镜像检测
	detectApi := NewDetectAPI(policySrv)
	v17 := router.Group("/api/v1/security")
	{
		v17.POST("/detect/policy", detectApi.CreatePolicy)
		v17.PUT("/detect/policy", detectApi.UpdatePolicy)
		v17.DELETE("/detect/policy", detectApi.DeletePolicy)
		v17.GET("/detect/policy/list", detectApi.SearchPolicy)
		v17.GET("/detect/policy/detail", detectApi.GetPolicyDetail)
		v17.GET("/detect/policy/snapshot", detectApi.GetPolicySnapshot)
	}

	// 扫描
	v18 := router.Group("/api/v1/scanTask")
	{
		v18.PUT("/image/scan/task/status", scanTaskAPI.UpdateScanTaskStatus)
		v18.PUT("/image/scan/subtask/reschedule", scanTaskAPI.RescheduleScanSubtask)
		v18.POST("/image/scan/task", scanTaskAPI.CreateImageScanTask)
		v18.GET("/image/scan/subtask/list", scanTaskAPI.SearchScanSubtask)
		v18.GET("/image/scan/task/list", scanTaskAPI.SearchScanTask)
	}

	v11 := router.Group("/api/v1/managementCenter")
	{
		v11.GET("/docs", configAPISrv.GetOpenapiDoc)
	}
	// 扫描配置
	v19 := router.Group("/api/v1/config")
	{
		v19.POST("/scan/sensitive/rule", configAPISrv.CreateSensitiveRule)
		v19.PUT("/scan/sensitive/rule", configAPISrv.UpdateSensitiveRule)
		v19.GET("/scan/sensitive/rule/list", configAPISrv.SearchSensitiveRule)
		v19.DELETE("/scan/sensitive/rule", configAPISrv.DeleteSensitiveRule)
		v19.GET("/scan/license/list", configAPISrv.SearchLicense)
		v19.GET("/scan/license/detail", configAPISrv.GetLicense)
		v19.GET("/view/const", configAPISrv.GetConstView)
		v19.GET("/scan/image", configAPISrv.GetScanImageConfig)
		v19.PUT("/scan/image", configAPISrv.UpdateScanImageConfig)
		v19.POST("/manage/db/vuln", configAPISrv.UpdateVulnDB)
		v19.POST("/manage/db/avira", configAPISrv.UpdateAviraDB)
		v19.GET("/manage/db/list", configAPISrv.SearchDB)
	}

	// 下期和前端一起废弃
	v20 := router.Group("/api/v1/db")
	{
		v20.PUT("/update", configAPISrv.UpdateVulnDB)
		v20.PUT("/update/malicious", configAPISrv.UpdateAviraDB)
		v20.GET("/version", configAPISrv.LatestVersion)
		v20.GET("/history", configAPISrv.SearchDB)
	}

	v21 := router.Group("/api/v1/node")
	{
		v21.GET("/nodeInfo/list", nodeApiSrv.SearchNode)
	}

	// 阻断
	v22 := router.Group("/api/v1/deploy")
	{
		v22.GET("/whiteImage", deployAPI.SearchDeployWhiteImage)
		v22.POST("/whiteImage", deployAPI.CreateDeployWhiteImage)
		v22.PUT("/whiteImage", deployAPI.UpdateDeployWhiteImage)
		v22.DELETE("/whiteImage", deployAPI.DeleteDeployWhiteImage)

		v22.POST("/record", deployAPI.SearchDeployRecord)
		v22.GET("/overview", deployAPI.DeployOverview)
		v22.GET("/blockTrend", deployAPI.DeployOverviewBlockTrend)
		v22.GET("/reasonTop5", deployAPI.DeployReasonTop5)
	}

	return router
}

func OpenAPI(router *gin.Engine,
	imageService imagemeta.ImageService,
	rejectSvc imagesecSrv.TrustedImageService,
	ciDalSrv ci.CiComponent,
	exportSrv scanReportService.ExportTaskInterface,
) *gin.Engine {
	apiRejectSrv := NewRejectAPISrv(rejectSvc)
	ciSrv := NewCiSrv(ciDalSrv, exportSrv)
	cig := router.Group("/openapi/v1/ci")
	{
		cig.GET("/policies", ciSrv.GetCiPolicies)
		cig.GET("/policy/:name", ciSrv.GetCiPolicy)
		cig.GET("/tidb/version", ciSrv.TiDbVersion)
		cig.Static("/tidb/assets", global.ScannerOpts.PvcPath)
		cig.POST("/result", ciSrv.SaveResult)
		cig.POST("/sign", apiRejectSrv.SignImageTrusted)
	}
	imageBaseApi := NewImageInfoAPI(imageService)
	image := router.Group("/openapi/v1/images")
	{
		image.GET("/image/image", ciSrv.GetCiPolicies)
		image.GET("/assets/image", imageBaseApi.SearchResources2)
		image.POST("/list", imageBaseApi.SearchImageWithScan)
	}

	return router
}

func AddLanguage(ctx *gin.Context) {
	ctx.Set(imagesecModel.AcceptLanguage, util.GetLanguage(ctx))
}
