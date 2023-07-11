package starter

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export/excel"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export/html"
	scanreport "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/scan-report"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
)

type BackgroundTasks struct {
	ScanReport                 *scanreport.ScanReportSrv
	LibScanTaskExportExcel     *excel.LibImageScanTaskExport
	NodeScanTaskExportExcel    *excel.NodeImageScanTaskExport
	AuditExport                *excel.AuditExport
	ClearFileAndRecord         *common.ClearFileAndRecord
	VulnExportExcel            *excel.VulnExport
	LibImageSearchExportExcel  *excel.LibImageSearchExportExcel
	NodeImageSearchExportExcel *excel.NodeImageSearchExportExcel
	SingeImageExportExcel      *excel.SingeImageExportExcel
	LibImageExportHtml         *html.ExportLibImageHtmlSrv
	NodeImageExportHtml        *html.ExportNodeImageHtmlSrv
	CICDImageExportHtml        *html.ExportCiImageHtmlSrv
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
	VulnClassType           []string
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
	scanTaskDal := store.NewScannerOrm(config.Rdb)
	resourceDal := store.NewResourceDao(config.Rdb)
	trustedImageDal := store.NewScannerOrm(config.Rdb)
	registryDal := store.NewRegistryDao(config.Rdb)
	vulnDal := store.NewVulnDao(config.Rdb)
	scanResultDal := store.NewImageScanResultDao(config.Rdb)
	idempotentDal := store.NewIdempotentDao(config.Rdb)
	webshellDal := store.NewWebsehllDao(config.Rdb)
	scannerInstanceDal := store.NewScannerInstanceDao(config.Rdb)
	libImageDal := store.NewScannerOrm(config.Rdb)
	nodeImageDal := imagesecStore.NewImageMetaDao(config.Rdb, nil)
	nodeReportDal := imagesecStore.NewNodeReportDao(config.Rdb)
	policyDal := imagesecStore.NewDetectPolicyDao(config.Rdb)
	detectResultDal := imagesecStore.NewImageDetectResultDao(config.Rdb)
	nodeScanTaskDal := imagesecStore.NewScanTaskDao(config.Rdb)
	nodeScanResultDal := imagesecStore.NewScanResultDao(config.Rdb)
	scannerConfigDal := imagesecStore.NewScannerConfigDao(config.Rdb)

	updateTask := common.NewUpdateTaskSrv(store.NewExportTaskDao(config.Rdb), config.RedisCli)

	libImageSvc := component.NewLibImageSrv(libImageDal, registryDal, scanTaskDal, vulnDal, scanResultDal,
		webshellDal, trustedImageDal, resourceDal, scannerInstanceDal)

	nodeImageSvc := imagemeta.NewNodeImageSrv(nodeImageDal, registryDal, nodeScanResultDal,
		resourceDal, nodeReportDal, policyDal, detectResultDal, trustedImageDal,
		scannerConfigDal, nodeScanTaskDal)

	imageExportSrv := common.NewExcelExportSrv(exportTaskDal, libImageSvc, nodeImageSvc, config.FileDir,
		updateTask, config.MaxVulnCol)

	// 镜像导出excel

	// 扫描任务导出excel
	libScanTaskExportSrv := excel.NewLibScanTaskExport(imageExportSrv, scanTaskDal, updateTask)
	nodeScanTaskExportSrv := excel.NewNodeImageScanTaskExport(imageExportSrv, nodeScanTaskDal, updateTask)
	// 导出漏洞
	vulnExportSrv := excel.NewVulnExport(exportTaskDal, config.FileDir, vulnDal, libImageSvc, updateTask)
	// 清理文件
	clearFile := common.NewClearFile(config.FileDir, config.Expiration, exportTaskDal, idempotentDal)
	nodeImageScanResultDal := imagesecStore.NewScanResultDao(config.Rdb)

	naviAuditReport := excel.NewAuditExport(exportTaskDal, config.Internal, config.FileDir, config.Es, "navi-audit-")
	vulnSrv := imagesecSrv.NewVulnSrv(nodeImageScanResultDal)

	// 镜像搜索列表导出excel
	libImageSearchExportExcel := excel.NewLibImageSearchExportExcel(imageExportSrv, updateTask, libImageSvc)
	nodeimageSearchExportExcel := excel.NewNodeImageSearchExportExcel(imageExportSrv, updateTask, nodeImageSvc)
	singeImageExport := excel.NewSingeImageExport(imageExportSrv)
	// 镜像扫描报告导出到html
	libImageHtmlSrv := html.NewExportLibImageHtmlSrv(libImageSvc, vulnDal, exportTaskDal, updateTask, config.FileDir, config.VulnClassType)
	nodeImageHtmlSrv := html.NewExportNodeImageHtmlSrv(nodeImageSvc, exportTaskDal, updateTask, vulnSrv, config.FileDir, config.VulnClassType)
	cicdImageHtmlSrv := html.NewExportCiImageHtmlSrv(libImageSvc, vulnDal, exportTaskDal, updateTask, config.FileDir)

	srv := &BackgroundTasks{
		ScanReport:                 scanReportServer,
		LibScanTaskExportExcel:     libScanTaskExportSrv,
		NodeScanTaskExportExcel:    nodeScanTaskExportSrv,
		AuditExport:                naviAuditReport,
		ClearFileAndRecord:         clearFile,
		VulnExportExcel:            vulnExportSrv,
		LibImageSearchExportExcel:  libImageSearchExportExcel,
		NodeImageSearchExportExcel: nodeimageSearchExportExcel,
		SingeImageExportExcel:      singeImageExport,
		LibImageExportHtml:         libImageHtmlSrv,
		NodeImageExportHtml:        nodeImageHtmlSrv,
		CICDImageExportHtml:        cicdImageHtmlSrv,
	}
	return srv
}

func (s *BackgroundTasks) Start(ctx context.Context) {
	// 导出风险探索中的镜像报告
	go func() {

		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ScanReport")
			}
		}()

		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.ScanReport.Run(ctx)
			logging.Get().Debug().Msg("finish ScanReport job")
			<-tick.C
		}
	}()

	s.LibScanTaskExportExcel.Run(ctx)
	s.NodeScanTaskExportExcel.Run(ctx)
	s.LibImageSearchExportExcel.Run(ctx)
	s.NodeImageSearchExportExcel.Run(ctx)
	s.SingeImageExportExcel.Run(ctx)
	s.ClearFileAndRecord.Run(ctx)

	// 导出漏洞数据
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ScanReport")
			}
		}()

		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.VulnExportExcel.Run(ctx)
			logging.Get().Debug().Msg("finish VulnExportExcel job")
			<-tick.C
		}
	}()

	// 审计日志数据导出excel
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ScanReport")
			}
		}()

		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.AuditExport.Run(ctx)
			logging.Get().Debug().Msg("finish AuditExport job")
			<-tick.C
		}
	}()

	// 镜像扫描报告导出html
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ScanReport")
			}
		}()

		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.LibImageExportHtml.Run(ctx)
			logging.Get().Debug().Msg("finish LibImageExportHtml job")
			<-tick.C
		}
	}()

	// cicd导出html
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ScanReport")
			}
		}()

		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.CICDImageExportHtml.Run(ctx)
			logging.Get().Debug().Msg("finish CICDImageExportHtml job")
			<-tick.C
		}
	}()

	// 镜像扫描报告导出html
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ScanReport")
			}
		}()

		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()
		for {
			s.NodeImageExportHtml.Run(ctx)
			logging.Get().Debug().Msg("finish NodeImageExportHtml job")
			<-tick.C
		}
	}()
}
