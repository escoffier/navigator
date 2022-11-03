package consts

const (
	ExportScanResult  string = "ExportScanTask"
	ExportVuln        string = "ExportVuln"
	AuditExeType      string = "ExportNaviAudit"
	ExportSingleImage string = "ExportImage"
	ExportImageSearch string = "ExportImageSearch"

	ExportImageView  string = "镜像报告"
	AuditExeTypeView string = "审计日志"
	ExportVulnView   string = "漏洞报告"
)

const (
	ExportStatusEmpty = iota
	ExportStatusPending
	ExportStatusRunning
	ExportStatusFinish
	ExportStatusError
)

const (
	ExportVulnDupUseTypeForGRiskOverView = 1
	ExportVulnDupUseTypeForExportVuln    = 2
)

const (
	TaskExporting               = true
	DefaultExportBathSize       = 1000
	ExportTimeFormatForFilename = "2006-01-02T15:04:05"
	ExportTimeFormat            = "2006-01-02 15:04:05"

	KoaCodeSuccess      = 200 // html生成服务调用成功的状态码
	KoaStatusSuccess    = "success"
	KoaStatusInprogress = "inprogress"
	KoaStatusFailed     = "failed"
	KoaAddr             = "http://localhost:8090"
	ExportHtmlReady     = 1
)
