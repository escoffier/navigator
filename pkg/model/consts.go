package model

const (
	ModuleContainerSecurity   = "ContainerSecurity"
	ModuleZHContainerSecurity = "容器安全"

	RuleCategoryATTCK  = "ATT&CK"
	RuleCategoryWatson = "Watson"

	RuleCategoryZHATTCK  = "ATT&CK"
	RuleCategoryZHWatson = "主动防御"

	LicenseTypePOC        = "POC"
	LicenseTypeZHPOC      = "POC"
	LicenseTypeDelivery   = "Delivery"
	LicenseTypeZHDelivery = "交付"
)

const (
	RejectPolicyIgnore = "ignore" // 忽略
	RejectPolicyAlarm  = "alarm"  // 报警
	RejectPolicyReject = "reject" // 阻断

	RejectPolicyBaseModel = "base" // 基本模式
	RejectPolicySafeModel = "safe" // 安全模式
)

const (
	RejectReasonVulnScore            = 1  // 漏洞评分低于设置值
	RejectReasonHasSensitiveFile     = 2  // 存在敏感文件
	RejectReasonHasMalicious         = 3  // 存在恶意文件
	RejectReasonHasCustomizeVuln     = 4  // 存在自定义漏洞
	RejectReasonHasNegligible        = 5  // 存在可忽略漏洞
	RejectReasonHasUnknown           = 6  // 存在未知漏洞
	RejectReasonHasLow               = 7  // 存在低危漏洞
	RejectReasonHasMedium            = 8  // 存在中危漏洞
	RejectReasonHasHigh              = 9  // 存在危险漏洞
	RejectReasonHasCritical          = 10 // 存在高危漏洞
	RejectNoLibrary                  = 11 // 来源镜像不在本地仓库（安全模式）
	RejectScanFailure                = 12 // 镜像扫描失败
	RejectScanNotScanned             = 13 // 镜像未扫描
	RejectReasonDifferentImageDigest = 14 // 在线镜像digest和仓库digest不一致
	RejectReasonUntrustedBaseImage   = 15 // 基础镜像不可信
	RejectReasonWebshellScore        = 16 // webshell 评分低于设置值
	RejectReasonUntrustedImage       = 17 // 不信任的镜像
	RejectReasonPrivilegedBoot       = 18 // 特权账户启动的镜像
	RejectReasonHasUntrustedEnv      = 19 // 不信任的环境变量
)

const (
	SeverityCRITICALString = "CRITICAL"
	SeverityHIGHString     = "HIGH"
	SeverityMEDIUMString   = "MEDIUM"
	SeverityLOWString      = "LOW"
	SeverityUNKNOWNString  = "UNKNOWN"
)

const (
	MaxVulnScore             = 50
	MaxWebshellScore         = 40
	MaxVirusScore            = 40
	MaxSensitiveScore        = 10
	SingleSensitiveScore     = 5
	MaxWebshellAndVirusScore = 40 // 评分细则规定webshell和病毒都算恶意文件加起来满分40
)

const (
	UsePatternForCICD   = "for_cicd"
	UsePatternForK8s    = "for_k8s"
	UsePatternForOnline = "for_online"
)
const (
	CICDImageRegistry   = 2 // 表示CICD的中转仓库
	NodeBuffRegistry    = 3 // 表示节点镜像所使用的仓库
	UserRegistry        = 1 // 表示同步仓库
	NodeImageSplitCount = 6
	IsAbnormalEnv       = 1

	CICDImageRegistryString = "cicd"     // 表示CICD的中转仓库
	NodeBuffRegistryString  = "node"     // 表示节点镜像所使用的仓库
	UserRegistryString      = "registry" // 表示同步仓库

)
