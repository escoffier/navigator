package starter

import (
	"context"
	"os"
	"runtime/debug"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/translate"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	imagescanSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	common2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/export/common"
	excel2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/export/excel"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/export/html"
	scanreport2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/scan-report"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
)

type BackgroundTasks struct {
	ScanReport                *scanreport2.ScanReportSrv
	ScanTaskExportExcel       *excel2.ImageScanTaskExport
	AuditExport               *excel2.AuditExport
	ClearFileAndRecord        *common2.ClearFileAndRecord
	VulnExportExcel           *excel2.VulnExport
	ImageSearchExportExcel    *excel2.ImageSearchExportExcel
	CICDImageExportHtml       *html.ExportCiImageHtmlSrv
	ExportImageHtmlSrv        *html.ExportImageHtmlSrv
	YamlScanExportExcel       *excel2.YamlScanExportExcel
	DockerfileScanExportExcel *excel2.DockerfileScanExportExcel
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
	// 周期报告的逻辑，不敢动
	scanReportServer := scanreport2.NewScanReportSrv(
		scanreport2.WithDB(adaptStore.NewScannerOrm(config.Rdb)),
		scanreport2.WithVulnDal(adaptStore.NewVulnDao(config.Rdb)),
		scanreport2.WithInternal(config.Internal),
		scanreport2.WithBatchSize(config.BatchSize),
		scanreport2.WithEmailDialer(config.EmailHost, int(config.EmailPort), config.EmailUser, config.EmailPasswd),
	)

	exportTaskDal := imagesecStore.NewExportTaskDao(config.Rdb)
	resourceDal := imagesecStore.NewResourceDao(config.Rdb)
	trustedImageDal := adaptStore.NewTrustedImageDao(config.Rdb)
	registryDal := imagesecStore.NewRegistryDao(config.Rdb)
	scanResultDal := imagesecStore.NewScanResultDao(config.Rdb)
	idempotentDal := imagesecStore.NewIdempotentDao(config.Rdb)
	imageDal := imagesecStore.NewImageMetaDao(config.Rdb)
	nodeReportDal := imagesecStore.NewNodeReportDao(config.Rdb)
	scanInstanceDal := imagesecStore.NewScannerInstanceDao(config.Rdb)
	policyDal := imagesecStore.NewDetectPolicyDao(config.Rdb)
	detectResultDal := imagesecStore.NewImageDetectResultDao(config.Rdb)
	scanTaskDal := imagesecStore.NewScanTaskDao(config.Rdb)
	scanConfigDal := imagesecStore.NewScanImageConfigDao(config.Rdb)
	deployDal := imagesecStore.NewDeployDao(config.Rdb)

	updateTask := common2.NewUpdateTaskSrv(imagesecStore.NewExportTaskDao(config.Rdb), config.RedisCli)
	cacheDal := imagesecStore.NewImageCacheDao(config.Rdb)
	imageSvc := imagemeta.NewImageMetaSrv(
		imageDal, registryDal, scanResultDal,
		resourceDal, nodeReportDal, policyDal, detectResultDal, trustedImageDal,
		scanConfigDal, scanTaskDal, scanInstanceDal, deployDal, cacheDal,
	)

	scanResSrv := imagescanSrv.NewScanResultSrv(scanResultDal, cacheDal)

	imageExportSrv := common2.NewExcelExportSrv(exportTaskDal, imageSvc, config.FileDir,
		updateTask, config.MaxVulnCol)

	// 镜像导出excel

	// 扫描任务导出excel
	// libScanTaskExportSrv := excel.NewLibScanTaskExport(imageExportSrv, scanResultDal, updateTask)
	scanTaskExportSrv := excel2.NewImageScanTaskExport(imageExportSrv, scanTaskDal, updateTask)
	// 导出漏洞
	vulnExportSrv := excel2.NewVulnExport(exportTaskDal, config.FileDir, scanResultDal, imageSvc, updateTask)
	// 清理文件
	clearFile := common2.NewClearFile(config.FileDir, config.Expiration, exportTaskDal, idempotentDal)

	naviAuditReport := excel2.NewAuditExport(exportTaskDal, config.Internal, config.FileDir, config.Es, "navi-audit-")

	imageSearchExportExcel := excel2.NewImageSearchExportExcel(imageExportSrv, updateTask, imageSvc)
	cicdImageHtmlSrv := html.NewExportCiImageHtmlSrv(exportTaskDal, updateTask, config.FileDir)

	translation, err := translate.NewTranslation(ctx, config.Rdb)
	if err != nil {
		logging.Get().Error().Err(err).Msg("translation init fails")
		os.Exit(2)
	}
	yamlScanExportExcel := excel2.NewYamlScanExportExcel(exportTaskDal, updateTask, config.Rdb, config.FileDir, translation)
	dockerfileScanExportExcel := excel2.NewDockerfileScanExportExcel(exportTaskDal, updateTask, config.Rdb, config.FileDir, translation)

	imageHtmlSrv := html.NewExportImageHtmlSrv(
		imageSvc,
		exportTaskDal,
		updateTask,
		scanResSrv,
		config.FileDir,
		config.VulnClassType,
	)

	srv := &BackgroundTasks{
		ScanReport:                scanReportServer,
		ScanTaskExportExcel:       scanTaskExportSrv,
		AuditExport:               naviAuditReport,
		ClearFileAndRecord:        clearFile,
		VulnExportExcel:           vulnExportSrv,
		ImageSearchExportExcel:    imageSearchExportExcel,
		CICDImageExportHtml:       cicdImageHtmlSrv,
		ExportImageHtmlSrv:        imageHtmlSrv,
		YamlScanExportExcel:       yamlScanExportExcel,
		DockerfileScanExportExcel: dockerfileScanExportExcel,
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

	s.ScanTaskExportExcel.Run(ctx)
	s.ImageSearchExportExcel.Run(ctx)
	s.ClearFileAndRecord.Run(ctx)
	s.YamlScanExportExcel.Run(ctx)
	s.DockerfileScanExportExcel.Run(ctx)

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
			s.ExportImageHtmlSrv.Run(ctx)
			logging.Get().Debug().Msg("finish ExportImageHtmlSrv job")
			<-tick.C
		}
	}()
}
