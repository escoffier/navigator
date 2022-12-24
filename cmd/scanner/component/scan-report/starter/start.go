package starter

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/security-rd/go-pkg/elastic"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export/excel"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export/html"
	scanreport "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/scan-report"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type BackgroundTasks struct {
	ScanReport         *scanreport.ScanReportSrv
	ImageExport        *excel.ImageExport
	ScanTaskExport     *excel.ScanTaskExport
	AuditExport        *excel.AuditExport
	ClearFileAndRecord *excel.ClearFileAndRecord
	VulnExport         *excel.VulnExport
	ImageSearchSrv     *excel.ImageSearchSrv
	ImageExportHtml    *html.ExportImageHtmlSrv
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
	RedisCli                *redis.Client
	IncludeCNNVDVuln        bool
	IncludeRHSAVuln         bool
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
	scanResultDal := store.NewImageScanResultDao(config.Rdb)
	idempotentDal := store.NewIdempotentDao(config.Rdb)
	imageSrv := component.NewConScannerSrv(dal, registryDal, dal, scanConfigDal, vulnDal, nil) // scan-report 无需上报事件中心，此处传空
	updateTask := export.NewUpdateTaskSrv(store.NewExportTaskDao(config.Rdb), config.RedisCli)
	webshellDal := store.NewWebsehllDao(config.Rdb)
	// 镜像导出excel
	imageExportSrv := excel.NewImageExport(resourceDal, exportTaskDal, imageSrv,
		config.FileDir, config.Internal, updateTask, config.IncludeCNNVDVuln, config.IncludeRHSAVuln)

	// 扫描任务导出excel
	scanTaskExportSrv := excel.NewScanTaskExport(imageExportSrv, exportTaskDal, dal, config.FileDir,
		updateTask, config.MaxVulnCol, config.MaxImageByOneExportTask, config.IncludeCNNVDVuln, config.IncludeRHSAVuln)
	// 导出漏洞
	vulnExportSrv := excel.NewVulnExport(exportTaskDal, config.FileDir, vulnDal, dal, resourceDal, updateTask)
	// 清理文件
	clearFile := excel.NewClearFile(config.FileDir, config.Expiration, exportTaskDal, idempotentDal)

	naviAuditReport := excel.NewAuditExport(exportTaskDal, config.Internal, config.FileDir, config.Es, "navi-audit-")

	// 镜像搜索列表导出excel
	imageSearchSrv := excel.NewImageSearchSrv(scanTaskExportSrv, exportTaskDal, config.FileDir, updateTask,
		component.NewImageService(dal, registryDal, dal, vulnDal, scanResultDal, webshellDal), config.IncludeCNNVDVuln, config.IncludeRHSAVuln)
	// 镜像扫描报告导出到html
	imageHtmlSrv := html.NewExportImageHtmlSrv(component.NewImageService(dal, registryDal, dal, vulnDal, scanResultDal, webshellDal),
		vulnDal, dal, exportTaskDal, updateTask, config.FileDir)

	srv := &BackgroundTasks{
		ScanReport:         scanReportServer,
		ImageExport:        imageExportSrv,
		ScanTaskExport:     scanTaskExportSrv,
		AuditExport:        naviAuditReport,
		ClearFileAndRecord: clearFile,
		VulnExport:         vulnExportSrv,
		ImageSearchSrv:     imageSearchSrv,
		ImageExportHtml:    imageHtmlSrv,
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
			logging.GetLogger().Info().Msg("finish ScanReport job")
			<-tick.C
		}
	}()

	// 镜像扫描数据导出excel
	go func() {
		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.ImageExport.Run(ctx)
			logging.GetLogger().Info().Msg("finish ImageExport job")
			<-tick.C
		}
	}()

	// 扫描任务中镜像扫描数据导出excel
	go func() {
		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.ScanTaskExport.Run(ctx)
			logging.GetLogger().Info().Msg("finish ScanTaskExport job")
			<-tick.C
		}
	}()

	// 导出漏洞数据
	go func() {
		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.VulnExport.Run(ctx)
			logging.GetLogger().Debug().Msg("finish VulnExport job")
			<-tick.C
		}
	}()

	// 对搜索结果导出excel
	go func() {
		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.ImageSearchSrv.Run(ctx)
			logging.GetLogger().Debug().Msg("finish ImageSearchSrv job")
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

	// 删除过期文件及记录
	go func() {
		tick := time.NewTicker(time.Minute * 30)
		defer tick.Stop()
		for {
			s.ClearFileAndRecord.Run(ctx)
			logging.GetLogger().Debug().Msg("finish ClearFileAndRecord job")
			<-tick.C
		}
	}()

	// 镜像扫描报告导出html
	go func() {
		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.ImageExportHtml.Run(ctx)
			logging.GetLogger().Debug().Msg("finish ImageExportHtml job")
			<-tick.C
		}
	}()
}
