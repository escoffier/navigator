package model

import "strings"

const (
	UserNormal       = "normal"
	UserDeleted      = "deleted"
	UserRoleAdmin    = "admin"
	UserAdminName    = "admin"
	AdminEmail       = "admin@admin.com"
	AdminPassword    = "admin@123"
	UserRoleOperator = "operator"
)

// 用户状态常量
const (
	UserStatusActive   = "active"   // 启用
	UserStatusInactive = "inactive" // 停用
	UserStatusLocked   = "locked"   // 锁定
)

const (
	EncryptPasswordKey = "talkerss"
	GitTypeGitlabV3    = "gitlab-v3"
	GitTypeGitlabV4    = "gitlab-v4"
	GitTypeGitlab      = "gitlab"
	GitTypeGitHub      = "github"
	GitTypeGitee       = "gitee"
)

// sourceCheck 超危，高危，中危, 低危，其他，无风险
// codesec 超危，高危，中危，低危，其他，无风险
const (
	SeverityCriticalInt   = 10
	SeverityHighInt       = 9
	SeverityMediumInt     = 8
	SeverityLowInt        = 7
	SeverityUnknownInt    = 6
	SeverityUnRiskInt     = 5
	SeverityRecommendInt  = 4
	SeverityCritical      = "CRITICAL"
	SeverityHigh          = "HIGH"
	SeverityMedium        = "MEDIUM"
	SeverityLow           = "LOW"
	SeverityOther         = "OTHER"
	SeverityUnRisk        = "UNRISK"
	SeverityUnknown       = "UNKNOWN"
	SeverityNONE          = "NONE"
	SeverityRecommend     = "RECOMMEND"
	SeverityCriticalView  = "超危"
	SeverityUnknownView   = "未知"
	SeverityHighView      = "高危"
	SeverityMediumView    = "中危"
	SeverityLowView       = "低危"
	SeverityOtherView     = "其他"
	SeverityUnRiskView    = "无风险"
	SeverityRecommendView = "建议" // codesec
)

// SetSeverityFromGrade 根据风险等级名称设置 Severity 和 SeverityInt
// 支持中文和英文的风险等级名称
func SetSeverityFromGrade(grade string) (severity string, severityInt int64) {
	switch grade {
	case SeverityCriticalView, SeverityCritical:
		return SeverityCritical, SeverityCriticalInt
	case SeverityHighView, SeverityHigh:
		return SeverityHigh, SeverityHighInt
	case SeverityMediumView, SeverityMedium:
		return SeverityMedium, SeverityMediumInt
	case SeverityLowView, SeverityLow:
		return SeverityLow, SeverityLowInt
	case SeverityOtherView, SeverityOther:
		return SeverityOther, SeverityUnknownInt
	case SeverityUnRiskView, SeverityUnRisk, SeverityNONE:
		return SeverityUnRisk, SeverityUnRiskInt
	case SeverityRecommendView, SeverityRecommend:
		return SeverityRecommend, SeverityRecommendInt
	default:
		return SeverityUnknown, SeverityUnknownInt
	}
}

func GetSeverityInt(level string) int64 {
	switch strings.ToUpper(level) {
	case SeverityCritical:
		return SeverityCriticalInt
	case SeverityHigh:
		return SeverityHighInt
	case SeverityMedium:
		return SeverityMediumInt
	case SeverityLow:
		return SeverityLowInt
	case SeverityUnknown:
		return SeverityUnknownInt
	case SeverityUnRisk:
		return SeverityUnRiskInt
	case SeverityRecommend:
		return SeverityRecommendInt
	}
	return 0
}

func GetSeverityEN(level int64) string {
	switch level {
	case SeverityCriticalInt:
		return SeverityCritical
	case SeverityHighInt:
		return SeverityHigh
	case SeverityMediumInt:
		return SeverityMedium
	case SeverityLowInt:
		return SeverityLow
	case SeverityUnknownInt:
		return SeverityUnknown
	case SeverityUnRiskInt:
		return SeverityUnRisk
	case SeverityRecommendInt:
		return SeverityRecommend
	default:
		return ""
	}
}

func GetSeverityZH(level int64) string {
	switch level {
	case SeverityCriticalInt:
		return SeverityCriticalView
	case SeverityHighInt:
		return SeverityHighView
	case SeverityMediumInt:
		return SeverityMediumView
	case SeverityLowInt:
		return SeverityLowView
	case SeverityUnRiskInt:
		return SeverityUnRiskView
	case SeverityRecommendInt:
		return SeverityRecommendView
	default:
		return SeverityUnknownView
	}
}

const (
	BranchMaster = "master"
)
