package model

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
	MaxWebshellScore         = 30
	MaxVirusScore            = 40
	MaxSensitiveScore        = 10
	SingleSensitiveScore     = 5
	MaxWebshellAndVirusScore = 40 // 评分细则规定webshell和病毒都算恶意文件加起来满分40
)

const (
	LangEn = "en"
	LangZh = "zh"
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

var reasonZHMap = map[int64]string{
	RejectReasonVulnScore:            "漏洞评分低于设置值",
	RejectReasonHasSensitiveFile:     "存在敏感文件",
	RejectReasonHasMalicious:         "存在恶意文件",
	RejectReasonHasCustomizeVuln:     "存在自定义漏洞",
	RejectReasonHasNegligible:        "存在可忽略漏洞",
	RejectReasonHasUnknown:           "存在末知漏洞",
	RejectReasonHasLow:               "存在低危漏洞",
	RejectReasonHasMedium:            "存在中危漏洞",
	RejectReasonHasHigh:              "存在危险漏洞",
	RejectReasonHasCritical:          "存在高危漏洞",
	RejectNoLibrary:                  "来源镜像不在本地仓库",
	RejectScanFailure:                "镜像扫描失败",
	RejectScanNotScanned:             "镜像未扫描",
	RejectReasonDifferentImageDigest: "在线镜像digest和仓库digest不一致",
	RejectReasonUntrustedBaseImage:   "非基础镜像构建的应用镜像",
	RejectReasonWebshellScore:        "webshell评分高于设置值",
	RejectReasonUntrustedImage:       "非可信镜像",
	RejectReasonPrivilegedBoot:       "root用户启动镜像",
	RejectReasonHasUntrustedEnv:      "包含不信任环境变量",
}
var reasonENMap = map[int64]string{
	RejectReasonVulnScore:            "Vulnerability score lower than set value",
	RejectReasonHasSensitiveFile:     "Exist sensitive file",
	RejectReasonHasMalicious:         "Exist malicious file",
	RejectReasonHasCustomizeVuln:     "Exist custom vulnerability file",
	RejectReasonHasNegligible:        "Exist Negligible vulnerability file",
	RejectReasonHasUnknown:           "Exist Unknown vulnerability file",
	RejectReasonHasLow:               "Exist Low vulnerability file",
	RejectReasonHasMedium:            "Exist Medium vulnerability file",
	RejectReasonHasHigh:              "Exist High vulnerability file",
	RejectReasonHasCritical:          "Exist Critical vulnerability file",
	RejectNoLibrary:                  "Image not in config registry",
	RejectScanFailure:                "Image scan failure",
	RejectScanNotScanned:             "Image not scanned",
	RejectReasonDifferentImageDigest: "The online mirror's digest is different from the registry mirror's",
	RejectReasonUntrustedBaseImage:   "The application image is not built with a verified base image",
	RejectReasonWebshellScore:        "Webshell score more than set value",
	RejectReasonUntrustedImage:       "Untrusted image",
	RejectReasonPrivilegedBoot:       "root user boot image",
	RejectReasonHasUntrustedEnv:      "Untrusted envs",
}

var reasonChMap = map[string]string{
	SeverityNegligible: GetRejectReason(LangZh)[RejectReasonHasNegligible],
	SeverityUnknown:    GetRejectReason(LangZh)[RejectReasonHasUnknown],
	SeverityLow:        GetRejectReason(LangZh)[RejectReasonHasLow],
	SeverityMedium:     GetRejectReason(LangZh)[RejectReasonHasMedium],
	SeverityHigh:       GetRejectReason(LangZh)[RejectReasonHasHigh],
	SeverityCritical:   GetRejectReason(LangZh)[RejectReasonHasCritical],
}
var reasonEnMap = map[string]string{
	SeverityNegligible: GetRejectReason(LangEn)[RejectReasonHasNegligible],
	SeverityUnknown:    GetRejectReason(LangEn)[RejectReasonHasUnknown],
	SeverityLow:        GetRejectReason(LangEn)[RejectReasonHasLow],
	SeverityMedium:     GetRejectReason(LangEn)[RejectReasonHasMedium],
	SeverityHigh:       GetRejectReason(LangEn)[RejectReasonHasHigh],
	SeverityCritical:   GetRejectReason(LangEn)[RejectReasonHasCritical],
}

func GetRejectReason(lag string) map[int64]string {
	if lag == LangZh {
		return reasonZHMap
	} else if lag == LangEn {
		return reasonENMap
	}
	return make(map[int64]string)
}

func GetSeverityRejectReason(severity string) int64 {
	subScore := map[string]int64{
		SeverityCritical:   RejectReasonHasCritical,
		SeverityHigh:       RejectReasonHasHigh,
		SeverityMedium:     RejectReasonHasMedium,
		SeverityLow:        RejectReasonHasLow,
		SeverityNegligible: RejectReasonHasNegligible,
		SeverityUnknown:    RejectReasonHasUnknown,
	}
	return subScore[severity]
}

func GetVulnRuleKey(vulnLevel string, lag string) string {
	switch lag {
	case LangEn:
		return reasonEnMap[vulnLevel]
	case LangZh:
		return reasonChMap[vulnLevel]
	}
	return ""
}

var OpenLicense = []string{"GPL", "MIT", "Apache License", "BSD", "MPL"}

const (
	ExportExcel = "excel"
	ExportHtml  = "html"
)
