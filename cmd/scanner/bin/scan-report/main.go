package main

import (
	"flag"
	"log"
	"time"

	"github.com/pkg/errors"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	scanreport "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

var (
	internal  time.Duration
	dbStr     string
	debug     bool
	batchSize int

	emailHost   string
	emailPort   int
	emailUser   string
	emailPasswd string
)

var (
	DefaultEmailPassword = "r8UJgg7ejpSoDOAF"
	DefaultEmailUser     = "console-robot@tensorsecurity.cn"
)

func init() {
	flag.DurationVar(&internal, "interval", 5*time.Minute, "job interval")
	flag.StringVar(&dbStr, "db-connect-str", "", "db address")
	flag.BoolVar(&debug, "debug", false, "debug model")
	flag.IntVar(&batchSize, "batch-size", 50, "the batch size of data")

	flag.StringVar(&scanreport.Host, "host", scanreport.Host, "console host")

	flag.StringVar(&emailHost, "email-host", "smtp.feishu.cn", "email host")
	flag.IntVar(&emailPort, "email-port", 465, "email port")
	flag.StringVar(&emailUser, "email-user", "", "email user")
	flag.StringVar(&emailPasswd, "email-passwd", "", "email password")
}

func main() {
	flag.Parse()
	if dbStr == "" {
		log.Fatal("db-connect-str can't be empty")
	}

	if emailPasswd == "" {
		emailPasswd = DefaultEmailPassword
	}

	if emailUser == "" {
		emailUser = DefaultEmailUser
	}

	if debug {
		logging.SetVerbose()
		logging.GetLogger().Warn().Msg("debug model!!! please close debug model when release.")
	}

	scannerGormWrapDb, err := rdbtools.GormWrapperOpen(1*time.Minute, func() (*gorm.DB, error) {

		db, err := gorm.Open(postgres.Open(dbStr), &gorm.Config{Logger: logger.Discard.LogMode(logger.Silent)})
		if err != nil {
			return nil, err
		}
		sqlDB, err := db.DB()
		if err != nil {
			return nil, errors.Wrap(err, "set connection params error")
		}
		sqlDB.SetMaxOpenConns(30)
		sqlDB.SetMaxIdleConns(5)
		sqlDB.SetConnMaxLifetime(time.Hour)

		if debug {
			db = db.Debug()
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
		scanreport.WithEmailDialer(emailHost, emailPort, emailUser, emailPasswd),
	)
	if err := server.Run(); err != nil {
		log.Fatalf("run server failed, err: %v", err)
	}
}
