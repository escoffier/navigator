package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strconv"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	scanreport "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
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

	emailPort, err = strconv.ParseInt(os.Getenv("EMAIL_PORT"), 10, 64)
	if err != nil {
		log.Fatal("`EMAIL_PORT` environment variable invalid, can't be parse to integer")
	}

	emailUser = os.Getenv("EMAIL_USERNAME")
	if emailUser == "" {
		emailUser = DefaultEmailUser
	}

	if emailPasswd = os.Getenv("EMAIL_PASSWORD"); emailPasswd == "" {
		log.Fatal("unset `EMAIL_PASSWORD` environment variable")
	}

	if debug {
		logging.SetVerbose()
		logging.GetLogger().Warn().Msg("debug model!!! please close debug model when release.")
	}

	scannerGormWrapDb, err := rdbtools.GormWrapperOpen(1*time.Minute, func() (*gorm.DB, error) {
		db, err := databases.GetMysqlWithEnv(context.Background())
		if err != nil {
			return nil, err
		}
		if debug {
			db = db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Info)})
		}

		return db, nil
	})

	if err != nil {
		log.Fatalf("init db error, err :%v", err)
	}

	server := scanreport.NewScanReportSrv(
		scanreport.WithDB(store.NewScannerOrm(scannerGormWrapDb)),
		scanreport.WithInternal(internal),
		scanreport.WithBatchSize(batchSize),
		scanreport.WithEmailDialer(emailHost, int(emailPort), emailUser, emailPasswd),
	)
	if err := server.Run(); err != nil {
		log.Fatalf("run server failed, err: %v", err)
	}
}
