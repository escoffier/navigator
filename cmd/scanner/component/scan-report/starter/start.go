package starter

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/elastic"

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
	AuditExport    *export.AuditExport
	ClearFile      *export.ClearFile
}

type Config struct {
	MaxVulnCol              int64
	Internal                time.Duration
	BatchSize               int
	EmailHost               string
	EmailPort               int64
	EmailUser               string
	EmailPasswd             string
	FileDir                 string
	ParallelTaskNum         int
	Expiration              int64
	Rdb                     *databases.RDBInstance
	Es                      *elastic.ESClient
	MaxImageByOneExportTask int64
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
	imageSrv := component.NewConScannerSrv(dal, registryDal, dal, scanConfigDal, vulnDal, nil) // scan-report 无需上报事件中心，此处传空

	imageExportSrv := export.NewImageExport(resourceDal, exportTaskDal, imageSrv, config.FileDir, config.Internal)
	scanTaskExportSrv := export.NewScanTaskExport(imageExportSrv, exportTaskDal, dal, config.FileDir, config.Internal, imageExportSrv, config.MaxVulnCol, config.MaxImageByOneExportTask)
	clearFile := export.NewClearFile(config.FileDir, config.Expiration, exportTaskDal)
	naviAuditReport := export.NewAuditExport(exportTaskDal, config.Internal, config.FileDir, config.Es, "navi-audit-")
	srv := &BackgroundTasks{
		ScanReport:     scanReportServer,
		ImageExport:    imageExportSrv,
		ScanTaskExport: scanTaskExportSrv,
		AuditExport:    naviAuditReport,
		ClearFile:      clearFile,
	}
	return srv
}

func (s *BackgroundTasks) Start(ctx context.Context) {
	// 导出镜像报告
	go func() {
		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.ScanReport.Run(ctx)
			logging.GetLogger().Debug().Msg("finish ScanReport job")
			<-tick.C
		}
	}()

	// 镜像扫描数据导出excel
	go func() {
		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.ImageExport.Run(ctx)
			logging.GetLogger().Debug().Msg("finish ImageExport job")
			<-tick.C
		}
	}()
	// 扫描任务中镜像扫描数据导出excel
	go func() {
		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.ScanTaskExport.Run(ctx)
			logging.GetLogger().Debug().Msg("finish ScanTaskExport job")
			<-tick.C
		}
	}()
	// 审计日志数据导出excel
	go func() {
		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.AuditExport.Run(ctx)
			logging.GetLogger().Debug().Msg("finish AuditExport job")
			<-tick.C
		}
	}()

	// 删除过期文件
	go func() {
		tick := time.NewTicker(time.Minute * 30)
		defer tick.Stop()
		for {
			s.ClearFile.Run(ctx)
			logging.GetLogger().Debug().Msg("finish ClearFile job")
			<-tick.C
		}
	}()
}
