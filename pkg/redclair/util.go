package redclair

import (
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
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

func SeverityGreaterThan(this, other string) bool {
	return severityToInt(this) > severityToInt(other)
}

func severityToInt(sev string) int {
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
