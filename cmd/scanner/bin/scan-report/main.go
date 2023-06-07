package main

import (
	"context"
	"flag"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	rkentry "github.com/rookie-ninja/rk-entry/entry"
	rkgin "github.com/rookie-ninja/rk-gin/boot"
	"github.com/rs/zerolog"
	"gitlab.com/security-rd/go-pkg/cache"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
	_ "go.uber.org/automaxprocs"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan"
	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/api"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export/html"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/starter"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
)

var (
	internal   time.Duration
	logLevel   string
	batchSize  int
	maxVulnCol int64

	parallelTaskNum         int
	emailHost               string
	emailPort               int64
	emailUser               string
	emailPasswd             string
	fileDir                 string
	HTTPListenAddr          string
	expiration              int64
	maxImageByOneExportTask int64
)

var (
	DefaultEmailUser = "console-robot@tensorsecurity.cn"
)

func init() {
	flag.DurationVar(&internal, "interval", 1*time.Minute, "job interval")
	flag.StringVar(&logLevel, "log-level", "info", "log level model")
	flag.IntVar(&batchSize, "batch-size", 50, "the batch size of data")
	flag.Int64Var(&maxVulnCol, "max-col", 4000, "max column in one excel file")
	flag.IntVar(&parallelTaskNum, "parallel-task-num", 1, "the batch size of data")
	flag.Int64Var(&expiration, "expiration", 7, "file expiration day") // 默认七天
	flag.Int64Var(&maxImageByOneExportTask, "export-max-image", 100000, "The maximum number of images exported by one export task")
	flag.StringVar(&fileDir, "file-dir", "/tmp", "export file storage directory")
	flag.StringVar(&HTTPListenAddr, "http-listen-addr", ":8080", "api addr")
}

func main() {
	flag.Parse()

	var err error

	emailHost = os.Getenv("EMAIL_HOST")

	if port, ok := os.LookupEnv("EMAIL_PORT"); ok {
		emailPort, err = strconv.ParseInt(port, 10, 64)
		if err != nil {
			logging.Get().
				Fatal().
				Msgf("`EMAIL_PORT` environment variable is <%s>,  and is invalid, can't be parse to integer", port)
		}
	} else {
		logging.Get().Warn().Msgf("can't find `EMAIL_PORT` environment variable, use default 465")
		emailPort = 465
	}

	emailUser = os.Getenv("EMAIL_USERNAME")
	if emailUser == "" {
		emailUser = DefaultEmailUser
	}

	if emailPasswd = os.Getenv("EMAIL_PASSWORD"); emailPasswd == "" {
		logging.Get().Warn().Msgf("unset `EMAIL_PASSWORD` environment variable, use empty string")
	}

	rdb, err := databases.NewRDBWithMySQLByEnv(context.Background())

	if err != nil {
		logging.Get().Fatal().Msgf("init db error, err :%v", err)
		os.Exit(1)
	}

	// share data use db 0
	rc0, err := cache.NewRedis(cache.SetDB(0))
	if err != nil {
		logging.Get().Fatal().Msgf("init redis error, err :%v", err)
		os.Exit(1)
	}

	// 建议改为loggingOptions用法
	// 目前由于log-level参数名称冲突
	if logLevel == "debug" {
		logging.Get().Logger = logging.Get().Logger.Level(zerolog.DebugLevel)
		rdb.SetDebugMode()
		logging.Get().Warn().Msg("debug model!!! please close debug model when release.")
	}

	es := elastic.NewESClientWithEnv(context.Background())

	// 导出的漏洞类型，中移环境默认导出应用漏洞和config文件引入的漏洞
	vct := make([]string, 0)
	vulnClassType := strings.TrimSpace(os.Getenv("EXPORT_VULN_CLASS"))
	if vulnClassType == "" {
		vct = []string{report.ClassOSPkg, report.ClassConfig}
	} else {
		vct = strings.Split(vulnClassType, ",")
	}

	config := starter.Config{
		MaxVulnCol:              maxVulnCol,
		Internal:                internal,
		BatchSize:               batchSize,
		EmailHost:               emailHost,
		EmailPort:               emailPort,
		EmailUser:               emailUser,
		EmailPasswd:             emailPasswd,
		FileDir:                 fileDir,
		ParallelTaskNum:         parallelTaskNum,
		Expiration:              expiration,
		Rdb:                     rdb,
		Es:                      es,
		MaxImageByOneExportTask: maxImageByOneExportTask,
		RedisCli:                rc0,
		IncludeCNNVDVuln:        false,
		IncludeRHSAVuln:         false,
		VulnClassType:           vct,
	}

	logging.Get().Info().Int64("MaxVulnCol", config.MaxVulnCol).Int64("MaxImageByOneExportTask",
		config.MaxImageByOneExportTask).Msg("config")
	// 起后台协程服务
	backgroundSrv := starter.NewBackgroundTasks(context.Background(), config)
	backgroundSrv.Start(context.Background())

	registryDal := store.NewRegistryDao(config.Rdb)
	vulnDal := store.NewVulnDao(config.Rdb)
	webshellDal := store.NewWebsehllDao(config.Rdb)
	resourceDal := store.NewResourceDao(config.Rdb)
	trustedImageDal := store.NewScannerOrm(config.Rdb)
	exportTaskDal := store.NewExportTaskDao(config.Rdb)
	scanTaskDal := store.NewScannerOrm(config.Rdb)
	imageDal := store.NewScannerOrm(config.Rdb)
	scanResultDal := store.NewImageScanResultDao(config.Rdb)
	scannerInstanceInfoDal := store.NewScannerInstanceDao(config.Rdb)

	updateTaskDal := common.NewUpdateTaskSrv(exportTaskDal, rc0)

	if err := updateTaskDal.DeleteIdempotent(context.Background()); err != nil {
		os.Exit(1)
	}

	nodeScanResultDal := imagesecStore.NewScanResultDao(config.Rdb)
	nodeImageDal := imagesecStore.NewImageMetaDao(config.Rdb, nil)

	policyDal := imagesecStore.NewDetectPolicyDao(config.Rdb)
	detectResultDal := imagesecStore.NewImageDetectResultDao(config.Rdb)
	nodeReportDal := imagesecStore.NewNodeReportDao(config.Rdb)
	scannerConfigDal := imagesecStore.NewScannerConfigDao(config.Rdb)
	nodeTaskDal := imagesecStore.NewScanTaskDao(config.Rdb)
	nodeScanTaskDal := imagesecStore.NewScanTaskDao(config.Rdb)

	nodeImageSrv := imagemeta.NewNodeImageSrv(nodeImageDal, registryDal, nodeScanResultDal,
		resourceDal, nodeReportDal, policyDal, detectResultDal, trustedImageDal, scannerConfigDal, nodeTaskDal)

	libImageSrv := component.NewLibImageSrv(imageDal, registryDal, scanTaskDal, vulnDal,
		scanResultDal, webshellDal, trustedImageDal, resourceDal, scannerInstanceInfoDal)
	nodeVulnSrv := imagesecSrv.NewVulnSrv(nodeScanResultDal)

	nodeScanTaskSrv := imagescan.NewScanTaskSrv(nodeScanTaskDal, nodeImageSrv, scannerConfigDal)

	exportTask := service.NewExportTaskSrv(
		store.NewExportTaskDao(rdb),
		maxImageByOneExportTask,
		store.NewScannerOrm(rdb),
		libImageSrv,
		nodeImageSrv,
		nodeScanTaskSrv,
		rc0,
		vulnDal,
	)

	libImageHtml := html.NewExportLibImageHtmlSrv(libImageSrv, vulnDal, exportTaskDal, updateTaskDal, fileDir, vct)
	nodeImageHtml := html.NewExportNodeImageHtmlSrv(nodeImageSrv, exportTaskDal, updateTaskDal, nodeVulnSrv, fileDir, vct)

	cicdImageHtml := html.NewExportCiImageHtmlSrv(libImageSrv, vulnDal, exportTaskDal, updateTaskDal, fileDir)

	exportHtmlDriver := make(map[string]types.ExportHtmlInterface)

	exportHtmlDriver[consts.ExportCIReport] = cicdImageHtml
	exportHtmlDriver[consts.ExportLibTask] = libImageHtml
	exportHtmlDriver[consts.ExportSingleImage] = libImageHtml
	exportHtmlDriver[consts.ExportLibImageSearch] = libImageHtml
	exportHtmlDriver[consts.ExportNodeImageSearch] = nodeImageHtml

	router := api.SetupGinRouter(exportTask, exportHtmlDriver)

	staticEntry := api.GenStaticFileHandlerEntry(fileDir)

	ginEntry := rkgin.RegisterGinEntry(
		rkgin.WithPort(GetPort(HTTPListenAddr)),
		WithRouter(router),
		rkgin.WithStaticFileHandlerEntry(staticEntry))

	// Bootstrap gin entry
	ginEntry.Bootstrap(context.Background())

	// Wait for shutdown signal
	rkentry.GlobalAppCtx.WaitForShutdownSig()

	// Interrupt gin entry
	ginEntry.Interrupt(context.Background())
}

func WithRouter(router *gin.Engine) rkgin.GinEntryOption {
	return func(entry *rkgin.GinEntry) {
		if router != nil {
			entry.Router = router
		}
	}
}

func GetPort(addr string) uint64 {
	split := strings.Split(addr, ":")
	if len(split) < 2 {
		return 8080
	}
	port, err := strconv.ParseUint(split[1], 10, 64)
	if err != nil {
		logging.Get().Err(err).Str("addr", addr).Msg("GetPort")
		return 8080
	}
	return port
}
