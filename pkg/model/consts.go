package model

const (
	RejectPolicyIgnore = "ignore" // 忽略
	RejectPolicyAlarm  = "alarm"  // 报警
	RejectPolicyReject = "reject" // 阻断

	RejectPolicyBaseModel = "base" // 基本模式
	RejectPolicySafeModel = "safe" // 安全模式

	// 漏洞级别
	VulnLevelNegligible = "Negligible" // 可忽略
	VulnLevelUnknown    = "Unknown"    // 未知
	VulnLevelLow        = "Low"        // 低
	VulnLevelMedium     = "Medium"     // 中
	VulnLevelHigh       = "High"       // 危
	VulnLevelCritical   = "Critical"   // 高危

	// TOP5 统计类别
	RejectReasonScore            = 1 // 漏洞评分低于设置值
	RejectReasonHasSensitiveFile = 2 // 存在敏感文件
	RejectReasonHasMalicious     = 3 // 存在恶意文件
	RejectReasonHasCustomizeVuln = 4 // 存在自定义漏洞

	RejectReasonHasNegligibleVuln = 5  // 存在可忽略漏洞
	RejectReasonHasUnknownVuln    = 6  // 存在末知漏洞
	RejectReasonHasLowVuln        = 7  // 存在低危漏洞
	RejectReasonHasMediumVuln     = 8  // 存在中危漏洞
	RejectReasonHasHighVuln       = 9  // 存在危险漏洞
	RejectReasonHasCriticalVuln   = 10 // 存在高危漏洞
	RejectNoLibrary               = 11 // 来源镜像不在本地仓库（安全模式）
	RejectScanFailure             = 12 // 镜像扫描失败
	RejectScanNotScanned          = 13 // 镜像未扫描
)

const (
	LangEn = "en"
	LangCh = "ch"
)

const (
	RejectReasonScoreEN             = "Vulnerability score lower than set value"
	RejectReasonHasSensitiveFileEN  = "Exist sensitive file"
	RejectReasonHasMaliciousEN      = "Exist malicious file"
	RejectReasonHasCustomizeVulnEN  = "Exist custom vulnerability file"
	RejectReasonHasNegligibleVulnEN = "Exist Negligible vulnerability file"
	RejectReasonHasUnknownVulnEN    = "Exist Unknown vulnerability file"
	RejectReasonHasLowVulnEN        = "Exist Low vulnerability file"
	RejectReasonHasMediumVulnEN     = "Exist Medium vulnerability file"
	RejectReasonHasHighVulnEN       = "Exist High vulnerability file"
	RejectReasonHasCriticalVulnEN   = "Exist Critical vulnerability file"
	RejectNoLibraryEN               = "image not in config registry"
	RejectScanFailureEN             = "image scan failure"
	RejectScanScanNotScannedEN      = "image not scanned"

	RejectReasonScoreZH             = "漏洞评分低于设置值"
	RejectReasonHasSensitiveFileZH  = "存在敏感文件"
	RejectReasonHasMaliciousZH      = "存在恶意文件"
	RejectReasonHasCustomizeVulnZH  = "存在自定义漏洞"
	RejectReasonHasNegligibleVulnZH = "存在可忽略漏洞"
	RejectReasonHasUnknownVulnZH    = "存在末知漏洞"
	RejectReasonHasLowVulnZH        = "存在低危漏洞"
	RejectReasonHasMediumVulnZH     = "存在中危漏洞"
	RejectReasonHasHighVulnZH       = "存在危险漏洞"
	RejectReasonHasCriticalVulnZH   = "存在高危漏洞"
	RejectNoLibraryZH               = "来源镜像不在本地仓库"
	RejectScanFailureZH             = "镜像扫描失败" //
	RejectScanScanNotScannedZH      = "镜像未扫描"  //
)

const (
	UsePatternForCICD   = "for_cicd"
	UsePatternForK8s    = "for_k8s"
	UsePatternForOnline = "for_online"
)
const RegistryUseTypeBuff = 2 // 表示CICD的中转仓库

const (
	ImageFromTypeCICD   = 2
	ImageFromTypeNormal = 1
)
