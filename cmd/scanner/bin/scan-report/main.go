package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"strconv"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/api"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/starter"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	internal   time.Duration
	logLevel   string
	batchSize  int
	batchImage int64

	parallelTaskNum int
	emailHost       string
	emailPort       int64
	emailUser       string
	emailPasswd     string
	fileDir         string
	HTTPListenAddr  string
	expiration      int64
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
			logging.GetLogger().
				Fatal().
				Msgf("`EMAIL_PORT` environment variable is <%s>,  and is invalid, can't be parse to integer", port)
		}
	} else {
		logging.GetLogger().Warn().Msgf("can't find `EMAIL_PORT` environment variable, use default 465")
		emailPort = 465
	}

	emailUser = os.Getenv("EMAIL_USERNAME")
	if emailUser == "" {
		emailUser = DefaultEmailUser
	}

	if emailPasswd = os.Getenv("EMAIL_PASSWORD"); emailPasswd == "" {
		logging.GetLogger().Warn().Msgf("unset `EMAIL_PASSWORD` environment variable, use empty string")
	}

	rdb, err := databases.NewRDBWithMySQLByEnv(context.Background())

	if err != nil {
		logging.GetLogger().Fatal().Msgf("init db error, err :%v", err)
		os.Exit(1)
	}
	if logLevel == "debug" {
		rdb.SetDebugMode()
		logging.SetVerbose()
		logging.GetLogger().Warn().Msg("debug model!!! please close debug model when release.")
	}

	// 起后台协程服务
	backgroundSrv := starter.NewBackgroundTasks(context.Background(), starter.Config{
		Internal:        internal,
		BatchSize:       batchSize,
		EmailHost:       emailHost,
		EmailPort:       emailPort,
		EmailUser:       emailUser,
		EmailPasswd:     emailPasswd,
		FileDir:         fileDir,
		Rdb:             rdb,
		BatchImage:      batchImage,
		ParallelTaskNum: parallelTaskNum,
		Expiration:      expiration,
	})
	backgroundSrv.Start(context.Background())

	// 起api服务
	ginServer := &http.Server{
		Addr:    HTTPListenAddr,
		Handler: api.SetupGinRouter(service.NewExportSrv(store.NewExportTaskDao(rdb)))}
	if err := ginServer.ListenAndServe(); err != nil {
		logging.GetLogger().Err(err).Msg("ginServer.ListenAndServe")
		os.Exit(1)
	}
}
