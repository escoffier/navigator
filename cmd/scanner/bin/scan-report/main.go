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
	"gitlab.com/security-rd/go-pkg/leaderelection"
	"gitlab.com/security-rd/go-pkg/logging"
	_ "go.uber.org/automaxprocs"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	imagescanService "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/api"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/export/common"
	html2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/export/html"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/starter"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	flag2 "gitlab.com/piccolo_su/vegeta/pkg/flag"
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
	electionOpts            *leaderelection.ElectionOpts
)

var (
	DefaultEmailUser = "console-robot@tensorsecurity.cn"
)

func init() {
	electionOpts = flag2.NewDefaultElectionOpts()
	flag.DurationVar(&internal, "interval", 1*time.Minute, "job interval")
	flag.StringVar(&logLevel, "log-level", "info", "log level model")
	flag.IntVar(&batchSize, "batch-size", 50, "the batch size of data")
	flag.Int64Var(&maxVulnCol, "max-col", 4000, "max column in one excel file")
	flag.IntVar(&parallelTaskNum, "parallel-task-num", 1, "the batch size of data")
	flag.Int64Var(&expiration, "expiration", 7, "file expiration day") // 默认七天
	flag.Int64Var(&maxImageByOneExportTask, "export-max-image", 100000, "The maximum number of images exported by one export task")
	flag.StringVar(&fileDir, "file-dir", "/tmp", "export file storage directory")
	flag.StringVar(&HTTPListenAddr, "http-listen-addr", ":8080", "api addr")
	flag.DurationVar(&electionOpts.LeaseDuration, "leader-elect-lease-duration", 15*time.Second, "lease duration")
	flag.DurationVar(&electionOpts.RenewDeadline, "leader-elect-renew-deadline", 12*time.Second, "renew deadline")
	flag.DurationVar(&electionOpts.RetryPeriod, "leader-elect-retry-period", 2*time.Second, "retry period")
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

	var enableLeaderElection bool
	elect := os.Getenv("ENABLE_LEADER_ELECTION")
	if elect == consts.TrueString {
		enableLeaderElection = true
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if enableLeaderElection {
		elector, err := leaderelection.New(func(ctx context.Context) {
			start(config)
			logging.Get().Info().Msg("start scan report service")
		}, cancel, electionOpts)
		if err != nil {
			logging.Get().Err(err).Msg("error occurred when server running")
			return
		}
		elector.Run(ctx)
		logging.Get().Info().Msg("lost lease")
		return
	}

	start(config)
}

func start(config starter.Config) {
	logging.Get().Info().Int64("MaxVulnCol", config.MaxVulnCol).Int64("MaxImageByOneExportTask",
		config.MaxImageByOneExportTask).Msg("config")
	// 起后台协程服务
	backgroundSrv := starter.NewBackgroundTasks(context.Background(), config)
	backgroundSrv.Start(context.Background())

	registryDal := imagesecStore.NewRegistryDao(config.Rdb)
	vulnDal := adaptStore.NewVulnDao(config.Rdb)
	resourceDal := imagesecStore.NewResourceDao(config.Rdb)
	trustedImageDal := adaptStore.NewTrustedImageDao(config.Rdb)
	exportTaskDal := imagesecStore.NewExportTaskDao(config.Rdb)
	scannerInstanceInfoDal := imagesecStore.NewScannerInstanceDao(config.Rdb)

	updateTaskDal := common.NewUpdateTaskSrv(exportTaskDal, config.RedisCli)

	scanResultDal := imagesecStore.NewScanResultDao(config.Rdb)
	imageDal := imagesecStore.NewImageMetaDao(config.Rdb)
	userDal := imagesecStore.NewUserDao(config.Rdb)

	policyDal := imagesecStore.NewDetectPolicyDao(config.Rdb)
	detectResultDal := imagesecStore.NewImageDetectResultDao(config.Rdb)
	detectTaskDal := imagesecStore.NewDetectTaskDao(config.Rdb)
	nodeDal := imagesecStore.NewNodeReportDao(config.Rdb)
	scannerConfigDal := imagesecStore.NewScanImageConfigDao(config.Rdb)
	nodeTaskDal := imagesecStore.NewScanTaskDao(config.Rdb)
	scanTaskDal := imagesecStore.NewScanTaskDao(config.Rdb)
	deployDal := imagesecStore.NewDeployDao(config.Rdb)
	preScanTaskDal := imagesecStore.NewScanTaskPreDao(config.Rdb)
	cacheDal := imagesecStore.NewImageCacheDao(config.Rdb)

	imageSrv := imagemeta.NewImageMetaSrv(
		imageDal,
		registryDal,
		scanResultDal,
		resourceDal,
		nodeDal,
		policyDal,
		detectResultDal,
		trustedImageDal,
		scannerConfigDal,
		nodeTaskDal,
		scannerInstanceInfoDal,
		deployDal,
		cacheDal,
	)

	vulnSrv := imagescanService.NewScanResultSrv(scanResultDal, cacheDal)

	scanTaskSrv := imagescanService.NewScanTaskSrv(
		scanTaskDal,
		preScanTaskDal,
		detectTaskDal,
		imageSrv,
		imageDal,
		scannerConfigDal,
		imageDal,
		userDal,
		nodeDal,
	)

	exportTask := service.NewExportTaskSrv(

		imagesecStore.NewExportTaskDao(config.Rdb),
		imageSrv,
		scanTaskSrv,
		config.RedisCli,
		vulnDal,
	)

	imageHtmlExport := html2.NewExportImageHtmlSrv(imageSrv, exportTaskDal, updateTaskDal, vulnSrv, fileDir, config.VulnClassType)

	cicdImageHtml := html2.NewExportCiImageHtmlSrv(exportTaskDal, updateTaskDal, fileDir)

	exportHtmlDriver := make(map[string]types.ExportHtmlInterface)

	exportHtmlDriver[consts.ExportCIReport] = cicdImageHtml
	exportHtmlDriver[consts.ExportScanTask] = imageHtmlExport
	exportHtmlDriver[consts.ExportImageSearch] = imageHtmlExport

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
