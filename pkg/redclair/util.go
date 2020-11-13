package redclair

import (
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	SeverityUnknownEn    = "Unknown"
	SeverityUnknownZh    = "未知"
	SeverityNoneEn       = "None"
	SeverityNoneZh       = "沒有"
	SeverityNegligibleEn = "Negligible"
	SeverityNegligibleZh = "微不足道"
	SeverityLowEn        = "Low"
	SeverityLowZh        = "低"
	SeverityMediumEn     = "Medium"
	SeverityMediumZh     = "中"
	SeverityHighEn       = "High"
	SeverityHighZh       = "高"
	SeverityCriticalEn   = "Critical"
	SeverityCriticalZh   = "危急"
)

func ToChineseSeverity(severityEn string) string {
	if severityEn == SeverityUnknownEn {
		return SeverityUnknownZh
	}
	if severityEn == SeverityNoneEn {
		return SeverityNoneZh
	}
	if severityEn == SeverityNegligibleEn {
		return SeverityNegligibleZh
	}
	if severityEn == SeverityLowEn {
		return SeverityLowZh
	}
	if severityEn == SeverityMediumEn {
		return SeverityMediumZh
	}
	if severityEn == SeverityHighEn {
		return SeverityHighZh
	}
	if severityEn == SeverityCriticalEn {
		return SeverityCriticalZh
	}
	logging.GetLogger().Warn().Str("severity", severityEn).Msg("Failed to obtain chinese severity")
	return SeverityUnknownZh
}

// Based on ranges defined for CVSS v3.0, because they're more fine-grained.
// https://nvd.nist.gov/vuln-metrics/cvss
func GetSeverityFromScore(score int64) string {
	if score == 0 {
		return SeverityNoneEn
	} else if score >= 1 && score <= 9 {
		return SeverityNegligibleEn
	} else if score >= 10 && score <= 39 {
		return SeverityLowEn
	} else if score >= 40 && score <= 69 {
		return SeverityMediumEn
	} else if score >= 70 && score <= 89 {
		return SeverityHighEn
	} else if score >= 90 {
		return SeverityCriticalEn
	} else {
		return SeverityUnknownEn
	}
}

func SeverityGreaterThan(this, other string) bool {
	return severityToInt(this) > severityToInt(other)
}

func severityToInt(sev string) int {
	switch strings.ToLower(sev) {
	case strings.ToLower(SeverityUnknownEn):
		return 0
	case strings.ToLower(SeverityNoneEn):
		return 1
	case strings.ToLower(SeverityNegligibleEn):
		return 2
	case strings.ToLower(SeverityLowEn):
		return 3
	case strings.ToLower(SeverityMediumEn):
		return 4
	case strings.ToLower(SeverityHighEn):
		return 5
	case strings.ToLower(SeverityCriticalEn):
		return 6
	default:
		logging.GetLogger().Warn().Str("severity", sev).Msg("Unexpected severity level")
		return -1
	}
}

func CompareVulnerabilities(left VulnerabilityInfo, right VulnerabilityInfo) bool {

	if left.CVSSv2Score < right.CVSSv2Score {
		return true
	} else if left.CVSSv2Score > right.CVSSv2Score {
		return false
	}
	// else CVSSv2 was equal (usually the case when its empty string "" on both sides)

	if SeverityGreaterThan(left.Severity, right.Severity) {
		return false
	} else if SeverityGreaterThan(right.Severity, left.Severity) {
		return true
	}
	// else Severity equal

	if left.CVE < right.CVE {
		return true
	} else if left.CVE > right.CVE {
		return false
	}
	// else Same CVE

	// Sometimes we hack SensitiveFilenames into VulnerabilitInfo, in that case FeatureName
	// is file path. Use it to sort.
	if left.FeatureName < right.FeatureName {
		return true
	} else if left.FeatureName > right.FeatureName {
		return false
	}

	// this must be some duplicate...
	logging.GetLogger().Warn().
		Str("left", fmt.Sprintf("%+v", left)).
		Str("right", fmt.Sprintf("%+v", right)).
		Msg("Encountered potential duplicate during vulnerability comparison")

	return false
}
