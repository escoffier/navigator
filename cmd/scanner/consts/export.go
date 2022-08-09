package consts

const (
	ExportImage      string = "ExportImage"
	ExportScanResult string = "ExportScanTask"
	ExportVuln       string = "ExportVuln"
	AuditExeType     string = "ExportNaviAudit"

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
	TaskExporting         = true
	TaskNotExporting      = false
	DefaultExportBathSize = 1000

	DefaultExportMaxCol = 20000 // 检测漏洞表数据，如果超过该值，就重新生成新的excel文件
	MaxColNumber        = 50000 // 循环检测可写入位置时，检测最大的col,防止死循环

	ExportTimeFormatForFilename = "2006-01-02T15:04:05"
	ExportTimeFormat            = "2006-01-02 15:04:05"
)
