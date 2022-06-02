package starter

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export"
	scanreport "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/scan-report"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type BackgroundTasks struct {
	ScanReport     *scanreport.ScanReportSrv
	ImageExport    *export.ImageExport
	ScanTaskExport *export.ScanTaskExport
	ClearFile      *export.ClearFile
}

type Config struct {
	BatchImage      int64
	Internal        time.Duration
	BatchSize       int
	EmailHost       string
	EmailPort       int64
	EmailUser       string
	EmailPasswd     string
	FileDir         string
	ParallelTaskNum int
	Expiration      int64
	Rdb             *databases.RDBInstance
}

func NewDefaultConfig() *Config {
	return &Config{
		Internal:    time.Minute,
		BatchSize:   1,
		EmailHost:   "",
		EmailPort:   0,
		EmailUser:   "",
		EmailPasswd: "",
		FileDir:     "",
		Rdb:         nil,
	}
}

func NewBackgroundTasks(ctx context.Context, config Config) *BackgroundTasks {
	scanReportServer := scanreport.NewScanReportSrv(
		scanreport.WithDB(store.NewScannerOrm(config.Rdb)),
		scanreport.WithVulnDal(store.NewVulnDao(config.Rdb)),
		scanreport.WithInternal(config.Internal),
		scanreport.WithBatchSize(config.BatchSize),
		scanreport.WithEmailDialer(config.EmailHost, int(config.EmailPort), config.EmailUser, config.EmailPasswd),
	)

	exportTaskDal := store.NewExportTaskDao(config.Rdb)
	dal := store.NewScannerOrm(config.Rdb)
	resourceDal := store.NewResourceDao(config.Rdb)

	registryDal := store.NewRegistryDao(config.Rdb)
	scanConfigDal := store.NewScanConfigDao(config.Rdb)
	vulnDal := store.NewVulnDao(config.Rdb)
	imageSrv := component.NewConScannerSrv(dal, registryDal, dal, scanConfigDal, vulnDal)

	imageExportSrv := export.NewImageExport(resourceDal, exportTaskDal, imageSrv, config.FileDir, config.Internal)
	scanTaskExportSrv := export.NewScanTaskExport(imageExportSrv, exportTaskDal, dal, config.FileDir, config.Internal, imageExportSrv, config.BatchImage)
	clearFile := export.NewClearFile(config.FileDir, config.Expiration, exportTaskDal)
	srv := &BackgroundTasks{
		ScanReport:     scanReportServer,
		ImageExport:    imageExportSrv,
		ScanTaskExport: scanTaskExportSrv,
		ClearFile:      clearFile,
	}
	return srv
}

func (s *BackgroundTasks) Start(ctx context.Context) {
	// 导出镜像报告
	go func() {
		tick := time.NewTicker(s.ScanReport.Interval)
		defer tick.Stop()
		for {
			s.ScanReport.Run(ctx)
			logging.GetLogger().Info().Msg("start ScanReport job")
			<-tick.C
		}
	}()

	// 镜像扫描数据导出excel
	go func() {
		tick := time.NewTicker(s.ImageExport.Interval)
		defer tick.Stop()
		for {
			s.ImageExport.Run(ctx)
			logging.GetLogger().Info().Msg("start ImageExport job")
			<-tick.C
		}
	}()
	// 扫描任务中镜像扫描数据导出excel
	go func() {
		tick := time.NewTicker(s.ScanTaskExport.Interval)
		defer tick.Stop()
		for {
			s.ScanTaskExport.Run(ctx)
			logging.GetLogger().Info().Msg("start ScanTaskExport job")
			<-tick.C
		}
	}()

	// 删除过期文件
	go func() {
		tick := time.NewTicker(s.ScanTaskExport.Interval)
		defer tick.Stop()
		for {
			s.ClearFile.Run(ctx)
			logging.GetLogger().Info().Msg("start ClearFile job")
			<-tick.C
		}
	}()
}
