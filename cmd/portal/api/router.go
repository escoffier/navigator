package api

import (
	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/config"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/service"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/store"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/ci"
)

func NewAPi(
	userService service.UserService,
	ud store.UserDal,
	pr service.ProjectService,
	cis ci.CiComponent,
	vulnService service.VulnService,
	exportSrv service.ExportTaskInterface,
) *gin.Engine {

	gin.Default()
	gin.DisableConsoleColor() // 禁用请求日志控制台字体颜色
	engin := gin.New()

	engin.MaxMultipartMemory = 2 << 20

	engin.Use(gin.Recovery(), AddLanguage)

	engin.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "healthy",
		})
	})

	// 初始化 API
	userAPI := NewUserAPI(userService)

	// 注册用户相关路由
	r1 := engin.Group("/api/v1/user", GenTokenAuthMiddleware(ud))
	{
		r1.PUT("/update", userAPI.UpdateUser)
		r1.GET("/detail", userAPI.GetUser)
		r1.GET("/list", userAPI.SearchUser)
		r1.GET("/token", userAPI.GetUserAuthCode)
		r1.DELETE("/delete", userAPI.DeleteUser)
		r1.PUT("/changePwd", userAPI.ChangePasswd)
		r1.PUT("/resetPwd", userAPI.ResetPasswd)
		r1.POST("/checkPasswd", userAPI.CheckPasswd)
		r1.POST("/register", userAPI.CreateUser)
	}
	// 注册用户相关路由
	r2 := engin.Group("/api/v1/user")
	{
		r2.POST("/login", userAPI.LoginUser)
		r2.GET("/authCode", userAPI.GetUser)
	}
	prAPi := NewProjectHandler(pr)
	r3 := engin.Group("/api/v1/projects", GenTokenAuthMiddleware(ud))
	{
		r3.GET("/list", prAPi.SearchProjects)
		r3.GET("/detail", prAPi.GetProjects)
		r3.POST("/create", prAPi.CreateProject)
		r3.PUT("/update", prAPi.UpdateProject)
		r3.DELETE("/delete", prAPi.DeleteProject)
	}

	ciSrv := NewCiSrv(cis)
	v4 := engin.Group("/api/v1/ci", GenTokenAuthMiddleware(ud))
	{
		v4.GET("/statistic/image", ciSrv.GetImageOverView)
		v4.GET("/statistic/top5", ciSrv.GetImageTop5)
	}

	home := NewHomePageHandler(config.GetConfig().SourceCheck.Addr, config.GetConfig().CodeSec.Addr)
	v5 := engin.Group("/api/v1/home", GenTokenAuthMiddleware(ud))
	{
		v5.GET("/statistic/riskComponent", home.GetHighRiskComponents)
		v5.GET("/statistic/license", home.GetLicenseStatistics)
		v5.GET("/statistic/usedComponent", home.GetMostUsedComponents)
		v5.GET("/statistic/vulStatistic", home.CountVulStatistics)
		v5.GET("/statistic/languageTop5", home.LanguageTop5Statistics)
		v5.GET("/statistic/vulTop5", home.VulTypeTop5Statistics)
	}
	global := NewGlobalHandler()
	v6 := engin.Group("/api/v1/global")
	{
		v6.GET("/consts/list", global.GetConst)
	}

	// 扫描结果相关
	vulnAPI := NewVulnAPI(vulnService, pr, cis)
	v7 := engin.Group("/api/v1/scan", GenTokenAuthMiddleware(ud))
	{
		v7.GET("/vuln/list/codesec", vulnAPI.SearchCodesecVuln)
		v7.GET("/summary/codesec", vulnAPI.CodesecSummary)
		v7.GET("/summary/sourceCheck", vulnAPI.SourceCheckSummary)
		v7.GET("/vuln/list/sourceCheck", vulnAPI.SearchSourceCheckVuln)
		v7.GET("/license/list/sourceCheck", vulnAPI.SearchSourceCheckLicense)
		v7.GET("/component/list/sourceCheck", vulnAPI.SearchSourceCheckComponent)
		v7.GET("/vuln/list/ci", vulnAPI.SearchCIVuln)
		v7.GET("/image/list/ci", vulnAPI.SearchCIImage)
		v7.POST("/startScan", vulnAPI.ScanProject)
	}

	// 导出任务
	exportHandler := NewExportHandler(exportSrv)
	v8 := engin.Group("/api/v1/export/task", GenTokenAuthMiddleware(ud))
	{
		v8.GET("/list", exportHandler.SearchExportTask)
		// v8.GET("/download", exportHandler.DownLoadFile)
		v8.GET("/download", exportHandler.DownLoad)
		v8.POST("/createTask", exportHandler.CreateExportProject)
	}
	return engin
}
