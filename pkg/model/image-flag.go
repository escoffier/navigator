package model

// 镜像表中Flag
const (
	FlagHasVuln          = 0
	FlagHasMalicious     = 1
	FlagHasSensitive     = 2
	FlagHasWebshell      = 3
	FlagHasExceptPKG     = 4
	FlagHasExceptEnv     = 5
	FlagPrivilegedBoot   = 6
	FlagHasExceptLicense = 7
	FlagHasFixedVuln     = 8
	FlagAppImage         = 9  // 应用镜像
	FlagBaseImage        = 10 // 基础镜像

	// 扫描状态的flag 节点镜像已废弃
	FlagImageScanUnknown    = 11
	FlagImageScanPending    = 12
	FlagImageScanInProgress = 13
	FlagImageScanSuccess    = 14
	FlagImageScanFailed     = 15
	FlagImageNotScan        = 16

	FlagImageNotMaintained = 17 // os不再维护
	FlagImageTrusted       = 18 // 可信息镜像
	FlagImageUnTrusted     = 19 // 不可信息镜像

	FlagImageSafe        = 20 // 镜像的安全状态：安全
	FlagImageUnsafe      = 21 // 镜像的安全状态:风险
	FlagImageSafeUnknown = 22 // 镜像的安全状态:未知（默认状态）

	FlagImageOnline        = 23 // 镜像在线
	FlagImageNotOnline     = 24 // 镜像离线
	FlagImageHasFixSuggest = 25 // 镜像有可修复建议
	FlagNodeImageNotInLib  = 26 // 节点镜像不在仓库内
	FlagNodeImageInLib     = 27 // 节点镜像在仓库内

	FlagImageHasUnknownVun          = 28
	FlagImageHasLowVuln             = 29
	FlagImageHasMediumVuln          = 30
	FlagImageHasHighVuln            = 31
	FlagImageHasCriticalVuln        = 32 // 镜像存在高危漏洞
	FlagHasPasswdEnv                = 33
	JobNotScan               string = "not_scan"
)

func GetAllFlag() []uint64 {
	flags := []uint64{FlagHasVuln, FlagHasMalicious, FlagHasSensitive,
		FlagHasWebshell, FlagHasExceptPKG, FlagHasExceptEnv,
		FlagPrivilegedBoot, FlagHasExceptLicense, FlagHasFixedVuln, FlagAppImage, FlagBaseImage}
	return flags
}
func GetSecurityIssueLabel(flag int64) string {
	switch flag {
	case FlagHasVuln:
		return "漏洞"
	case FlagHasSensitive:
		return "敏感文件"
	case FlagHasWebshell:
		return "WebShell"
	case FlagHasExceptPKG:
		return "不合规软件"
	case FlagHasExceptEnv:
		return "异常环境变量"
	case FlagPrivilegedBoot:
		return "root用户启动"
	case FlagHasExceptLicense:
		return "不允许的开源许可"
	case FlagHasMalicious:
		return "恶意文件"
	default:
		return ""
	}
}

func GetImageFlag() []int64 {
	flags := []int64{FlagBaseImage, FlagAppImage, FlagPrivilegedBoot}
	return flags
}

func GetScanFlag() []uint64 {
	flgs := []uint64{FlagHasVuln, FlagHasMalicious, FlagHasSensitive,
		FlagHasWebshell, FlagHasExceptPKG, FlagHasExceptEnv, FlagHasExceptLicense, FlagHasFixedVuln,
	}
	return flgs
}

func GetScanStatusFlag() []uint64 {
	flags := []uint64{
		FlagImageScanUnknown,
		FlagImageScanPending,
		FlagImageScanInProgress,
		FlagImageScanSuccess,
		FlagImageScanFailed,
		FlagImageNotScan,
	}
	return flags
}
