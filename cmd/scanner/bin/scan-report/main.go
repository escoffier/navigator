package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strconv"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	scanreport "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	internal  time.Duration
	debug     bool
	batchSize int

	emailHost   string
	emailPort   int64
	emailUser   string
	emailPasswd string
)

var (
	DefaultEmailUser = "console-robot@tensorsecurity.cn"
)

func init() {
	flag.DurationVar(&internal, "interval", 5*time.Minute, "job interval")
	flag.BoolVar(&debug, "debug", false, "debug model")
	flag.IntVar(&batchSize, "batch-size", 50, "the batch size of data")
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

	if debug {
		logging.SetVerbose()
		logging.GetLogger().Warn().Msg("debug model!!! please close debug model when release.")
	}

	rdb, err := databases.NewRDBWithMySQLByEnv(context.Background())

	if err != nil {
		log.Fatalf("init db error, err :%v", err)
	}
	if debug {
		rdb.SetDebugMode()
	}

	server := scanreport.NewScanReportSrv(
		scanreport.WithDB(store.NewScannerOrm(rdb)),
		scanreport.WithVulnDal(store.NewVulnDao()),
		scanreport.WithInternal(internal),
		scanreport.WithBatchSize(batchSize),
		scanreport.WithEmailDialer(emailHost, int(emailPort), emailUser, emailPasswd),
	)
	if err := server.Run(); err != nil {
		log.Fatalf("run server failed, err: %v", err)
	}
}
