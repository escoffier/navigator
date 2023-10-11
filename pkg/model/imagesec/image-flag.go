package imagesec

// 镜像表中Flag
const (
	FlagHasExceptionVuln       = 0
	FlagHasExceptionMalware    = 1
	FlagHasExceptionSensitive  = 2
	FlagHasExceptionWebshell   = 3
	FlagHasExceptionPKG        = 4
	FlagHasExceptionEnv        = 5
	FlagDetectExceptionBoot    = 6 // root启动(检测问题)
	FlagHasExceptionPkgLicense = 7
	FlagHasFixedVuln           = 8
	FlagAppImage               = 9  // 应用镜像(本身属性)
	FlagBaseImage              = 10 // 基础镜像(本身属性)
	FlagHasExceptionLicense    = 11 // 含有不合规的 license 文件

	FlagImageDetectNotExitINReg = 12 // 镜像不在仓库内(问题)
	// 部署上线特有
	FlagImageNotScanned      = 13
	FlagImageDetectUnTrusted = 14 // 镜像不可信 (问题)
	FlagNotExitBaseImage     = 15 // (问题)
	FlagImageDeployWhite     = 16

	FlagImageNotMaintained = 17 // os不再维护
	FlagImageTrusted       = 18 // 可信息镜像(本身属性)
	FlagImageUnTrusted     = 19 // 不可信息镜像(本身属性)

	FlagImageExceptionBoot = 20 // root启动(本身属性)

	FlagImageOnline        = 23 // 镜像在线
	FlagImageNotOnline     = 24 // 镜像离线
	FlagImageHasFixSuggest = 25 // 镜像有可修复建议
	FlagImageNotInRegistry = 26 // 镜像不在仓库内(本身的属性)
	FlagImageInRegistry    = 27 // 镜像在仓库内(本身的属性)

	FlagImageHasUnknownVun   = 28
	FlagImageHasLowVuln      = 29
	FlagImageHasMediumVuln   = 30
	FlagImageHasHighVuln     = 31
	FlagImageHasCriticalVuln = 32 // 镜像存在高危漏洞

	FlagImageDeployBlock  = 33 // 部署上线状态
	FlagImageDeployAlarm  = 34
	FlagImageDeployPassed = 35

	// 2.19的需求，需要对镜像安全状态排序
	FlagImageSafeUnknown = 61 // 镜像的安全状态:未知（默认状态）
	FlagImageSafe        = 62 // 镜像的安全状态：安全
	FlagImageUnsafe      = 63 // 镜像的安全状态:风险
)

func GetSecurityIssueLabelZH(flag int64) string {
	switch flag {
	case FlagHasExceptionVuln:
		return "漏洞"
	case FlagHasExceptionSensitive:
		return "敏感文件"
	case FlagHasExceptionWebshell:
		return "WebShell"
	case FlagHasExceptionPKG:
		return "不合规软件"
	case FlagHasExceptionEnv:
		return "异常环境变量"
	case FlagDetectExceptionBoot:
		return "root用户启动"
	case FlagHasExceptionPkgLicense:
		return "不允许的开源许可"
	case FlagHasExceptionMalware:
		return "恶意文件"
	case FlagHasExceptionLicense:
		return "风险文件引用"
	case FlagImageDetectUnTrusted:
		return "非可信镜像"
	case FlagHasFixedVuln:
		return "包含可修复漏洞"
	case FlagImageHasFixSuggest:
		return "存在修复建议"
	case FlagImageDetectNotExitINReg:
		return "非仓库镜像"
	case FlagImageNotScanned:
		return "镜像未扫描"
	case FlagNotExitBaseImage:
		return "非基础镜像构建"

	default:
		return ""
	}
}

func GetSecurityIssueLabelEN(flag int64) string {
	switch flag {
	case FlagHasExceptionVuln:
		return "Vulnerability"
	case FlagHasExceptionSensitive:
		return "Sensitive files"
	case FlagHasExceptionWebshell:
		return "WebShell"
	case FlagHasExceptionPKG:
		return "Non-compliant software"
	case FlagHasExceptionEnv:
		return "Abnormal environment variables"
	case FlagDetectExceptionBoot:
		return "Start by non-root user"
	case FlagHasExceptionPkgLicense:
		return "Prohibited open source license"
	case FlagHasExceptionMalware:
		return "Trojan Virus"
	case FlagHasExceptionLicense:
		return "Non-compliant License"
	case FlagImageDetectUnTrusted:
		return "Un-trusted"
	case FlagHasFixedVuln:
		return "Has fixed Vulnerability"
	case FlagImageHasFixSuggest:
		return "Has fixed suggest"
	case FlagImageDetectNotExitINReg:
		return "image not in registry"
	case FlagImageNotScanned:
		return "image not scanned"
	case FlagNotExitBaseImage:
		return "not exit base image"
	default:
		return ""
	}
}

func GetSecurityIssueLabelKey() map[uint64]string {
	ans := map[uint64]string{
		FlagHasExceptionVuln:        ExceptionVuln,
		FlagHasExceptionSensitive:   ExceptionSensitive,
		FlagHasExceptionWebshell:    ExceptionWebshell,
		FlagHasExceptionPKG:         ExceptionPKG,
		FlagHasExceptionEnv:         ExceptionEnv,
		FlagDetectExceptionBoot:     ExceptionBoot,
		FlagHasExceptionPkgLicense:  ExceptionPkgLicense,
		FlagHasExceptionMalware:     ExceptionMalware,
		FlagHasExceptionLicense:     ExceptionLicense,
		FlagImageDetectUnTrusted:    UnTrustedString,
		FlagHasFixedVuln:            HasFixedVulnString,
		FlagImageHasFixSuggest:      ImageHasSuggestionString,
		FlagImageDetectNotExitINReg: ImageNotInReg,
		FlagImageNotScanned:         ImageNotScanned,
		FlagNotExitBaseImage:        ImageNotExitBaseImage,
	}

	return ans
}

const (
	BaseImageTypeString = "base"
	AppImageTypeString  = "app"
	AndString           = "and"
	OrString            = "or"
	TrueString          = "true"
	FalseString         = "false"

	ImageSafeString   = "safe"    // 镜像的安全状态：安全
	ImageUnsafeString = "unsafe"  // 镜像的安全状态:风险
	ImageSafeUnknown  = "unknown" // 镜像的安全状态:未知

	ExceptionVuln            = "exceptionVuln"
	ExceptionMalware         = "exceptionMalware"
	ExceptionSensitive       = "exceptionSensitive"
	ExceptionWebshell        = "exceptionWebshell"
	ExceptionPKG             = "exceptionPKG"
	ExceptionEnv             = "exceptionEnv"
	ExceptionBoot            = "exceptionBoot"
	ExceptionPkgLicense      = "exceptionPkgLicense"
	ExceptionLicense         = "exceptionLicense" // 含有不合规的 license 文件
	UnTrustedString          = "untrusted"
	TrustedString            = "trusted"
	HasFixedVulnString       = "hasFixedVuln"
	ImageHasSuggestionString = "hasSuggestion"
	ImageNotInReg            = "notInRegistry"
	ImageNotScanned          = "imageNotScanned"
	ImageNotExitBaseImage    = "notExitBaseImage"

	DeployActionBlock = "block"
	DeployActionAlarm = "alarm"
	DeployActionPass  = "pass"
	DeployModSafe     = "safe"
	DeployModBase     = "base"
)
