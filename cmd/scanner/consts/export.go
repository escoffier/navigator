package consts

import (
	"strings"
)

const (
	ExportVuln              string = "ExportVuln"
	AuditExeType            string = "ExportNaviAudit"
	IACYamlExportType       string = "ExportIACYamls"
	IACDockerfileExportType string = "ExportIACDockerfiles"

	ExportImageSearch string = "ExportImageSearch"

	ExportCIReport string = "ExportCIReport"
	ExportScanTask string = "ExportScanTask"

	ExportImageViewCH         string = "镜像报告"
	AuditExeTypeViewCH        string = "审计日志"
	ExportVulnViewCH          string = "漏洞报告"
	ExportIACYamlViewCH       string = "yaml扫描"
	ExportIACDockerfileViewCH string = "dockerfile扫描"

	ExportImageViewEN         string = "Image Report"
	AuditExeTypeViewEN        string = "Audit Log"
	ExportVulnViewEN          string = "Vulnerability Report"
	ExportIACYamlViewEN       string = "Yaml Scan"
	ExportIACDockerfileViewEN string = "Dockerfile Scan"

	ExportCIType = "ci"
)

const (
	LangEN  = "en"
	LangCH  = "zh"
	LangKey = "lang"
)

func GetExportTypeView(exportType string, lang string) string {
	if strings.ToLower(lang) == LangCH {
		switch exportType {
		case ExportCIReport, ExportScanTask, ExportImageSearch:
			return ExportImageViewCH
		case ExportVuln:
			return ExportVulnViewCH
		case AuditExeType:
			return AuditExeTypeViewCH
		case IACYamlExportType:
			return ExportIACYamlViewCH
		case IACDockerfileExportType:
			return ExportIACDockerfileViewCH
		}
	}

	if strings.ToLower(lang) == LangEN {
		switch exportType {
		case ExportCIReport, ExportScanTask, ExportImageSearch:
			return ExportImageViewEN
		case ExportVuln:
			return ExportVulnViewEN
		case AuditExeType:
			return AuditExeTypeViewEN
		case IACYamlExportType:
			return ExportIACYamlViewEN
		case IACDockerfileExportType:
			return ExportIACDockerfileViewEN
		}
	}
	return ""
}

const (
	ExportStatusEmpty   = ""
	ExportStatusPending = "pending"
	ExportStatusRunning = "running"
	ExportStatusFinish  = "finished"
	ExportStatusError   = "error"
)

const (
	TaskExporting         = true
	DefaultExportBathSize = 1000
	ExportTimeFormat      = "2006-01-02 15:04:05"

	KoaCodeSuccess   = 200 // html生成服务调用成功的状态码
	KoaStatusSuccess = "success"
	KoaStatusFailed  = "failed"
	KoaAddr          = "http://localhost:8090"
	ExportHtmlReady  = 1
)
