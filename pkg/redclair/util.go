package redclair

import (
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	SeverityUnknown    = "Unknown"
	SeverityNone       = "None"
	SeverityNegligible = "Negligible"
	SeverityLow        = "Low"
	SeverityMedium     = "Medium"
	SeverityHigh       = "High"
	SeverityCritical   = "Critical"
)

// Based on ranges defined for CVSS v3.0, because they're more fine-grained.
// https://nvd.nist.gov/vuln-metrics/cvss
func GetSeverityFromScore(score int64) string {
	if score == 0 {
		return SeverityNone
	} else if score >= 1 && score <= 9 {
		return SeverityNegligible
	} else if score >= 10 && score <= 39 {
		return SeverityLow
	} else if score >= 40 && score <= 69 {
		return SeverityMedium
	} else if score >= 70 && score <= 89 {
		return SeverityHigh
	} else if score >= 90 {
		return SeverityCritical
	} else {
		return SeverityUnknown
	}
}

func SeverityGreaterThan(this, other string) bool {
	return SeverityToInt(this) > SeverityToInt(other)
}

func SeverityToInt(sev string) int {
	switch strings.ToLower(sev) {
	case strings.ToLower(SeverityUnknown):
		return 0
	case strings.ToLower(SeverityNone):
		return 1
	case strings.ToLower(SeverityNegligible):
		return 2
	case strings.ToLower(SeverityLow):
		return 3
	case strings.ToLower(SeverityMedium):
		return 4
	case strings.ToLower(SeverityHigh):
		return 5
	case strings.ToLower(SeverityCritical):
		return 6
	default:
		logging.GetLogger().Warn().Str("severity", sev).Msg("Unexpected severity level")
		return -1
	}
}

func CompareVulnerabilities(left model.VulnerabilityInfo, right model.VulnerabilityInfo) bool {

	if left.CVSS.CVSSv2Score != "" && right.CVSS.CVSSv2Score != "" {
		if left.CVSS.CVSSv2Score < right.CVSS.CVSSv2Score {
			return true
		} else if left.CVSS.CVSSv2Score > right.CVSS.CVSSv2Score {
			return false
		}
	}
	// else CVSSv2 was equal (usually the case when its empty string "" on both sides)

	if SeverityGreaterThan(left.Severity, right.Severity) {
		return false
	} else if SeverityGreaterThan(right.Severity, left.Severity) {
		return true
	}
	// else Severity equal

	if left.ID < right.ID {
		return true
	} else if left.ID > right.ID {
		return false
	}
	// else Same ID (e.g. CVE)

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
