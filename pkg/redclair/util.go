package redclair

import (
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func CompareVulnerabilities(left VulnerabilityInfo, right VulnerabilityInfo) bool {

	if left.CVSSv2Score < right.CVSSv2Score {
		return true
	} else if left.CVSSv2Score > right.CVSSv2Score {
		return false
	}
	// else CVSSv2 was equal (usually the case when its empty string "" on both sides)

	if SeverityMap[left.Severity] < SeverityMap[right.Severity] {
		return true
	} else if SeverityMap[left.Severity] > SeverityMap[right.Severity] {
		return false
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
