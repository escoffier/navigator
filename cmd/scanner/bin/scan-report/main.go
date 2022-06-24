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
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/api"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/starter"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
	_ "go.uber.org/automaxprocs"
)

var (
	internal   time.Duration
	logLevel   string
	batchSize  int
	batchImage int64

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
	flag.StringVar(&logLevel, "log-level", "info", "debug model")
	flag.IntVar(&batchSize, "batch-size", 50, "the batch size of data")
	flag.Int64Var(&batchImage, "batch-image", 300, "number of image in one excel file")
	flag.IntVar(&parallelTaskNum, "parallel-task-num", 1, "the batch size of data")
	flag.Int64Var(&expiration, "expiration", 7, "file expiration day") // 默认七天
	flag.Int64Var(&maxImageByOneExportTask, "export-max-image", 800, "The maximum number of images exported by one export task")
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

	// 建议改为loggingOptions用法
	// 目前由于log-level参数名称冲突
	if logLevel == "debug" {
		logging.Get().Logger = logging.Get().Logger.Level(zerolog.DebugLevel)
		rdb.SetDebugMode()
		logging.Get().Warn().Msg("debug model!!! please close debug model when release.")
	}

	es := elastic.NewESClientWithEnv(context.Background())

	// 起后台协程服务
	backgroundSrv := starter.NewBackgroundTasks(context.Background(), starter.Config{
		Internal:                internal,
		BatchSize:               batchSize,
		EmailHost:               emailHost,
		EmailPort:               emailPort,
		EmailUser:               emailUser,
		EmailPasswd:             emailPasswd,
		FileDir:                 fileDir,
		Rdb:                     rdb,
		BatchImage:              batchImage,
		ParallelTaskNum:         parallelTaskNum,
		Expiration:              expiration,
		Es:                      es,
		MaxImageByOneExportTask: maxImageByOneExportTask,
	})
	backgroundSrv.Start(context.Background())

	router := api.SetupGinRouter(service.NewExportSrv(store.NewExportTaskDao(rdb), maxImageByOneExportTask, store.NewScannerOrm(rdb)))

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
