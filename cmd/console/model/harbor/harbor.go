package harbor

import (
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
)

// Based on OpenAPI definition
// https://github.com/goharbor/pluggable-scanner-spec

type harborErrorInner struct {
	Message string `json:"message"`
}
type harborError struct {
	Inner harborErrorInner `json:"error"`
}

// helper func
func NewHarborErrorAndLog(err error, msg string) harborError {
	logging.GetLogger().Warn().Err(err).Msg(msg)
	return harborError{harborErrorInner{msg}}
}

type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}
type Capability struct {
	ConsumesMIMETypes []string `json:"consumes_mime_types"`
	ProducesMIMETypes []string `json:"produces_mime_types"`
}
type Manifest struct {
	Scanner      Scanner           `json:"scanner"`
	Capabilities []Capability      `json:"capabilities"`
	Properties   map[string]string `json:"properties"`
}

type Registry struct {
	URL           string `json:"url"`           // harbor-harbor-registry:5000
	Authorization string `json:"authorization"` // Bearer: JWTTOKENGOESHERE
}
type Artifact struct {
	Repository string `json:"repository"` // library/mongo
	Digest     string `json:"digest"`     // sha256:fc66cdef5ca33809823182c9c5d72ea86fd2cef7713cf3363e1a0b12a5d77500
	Tag        string `json:"tag"`        // 3.14-xenial
	MimeType   string `json:"mime_type"`  // application/vnd.docker.distribution.manifest.v2+json
}
type ScanRequest struct {
	Registry Registry `json:"registry"`
	Artifact Artifact `json:"artifact"`
}

type ScanResponse struct {
	ID string `json:"id"`
}

type VulnerabilityItem struct {
	ID          string   `json:"id"`          // CVE-2017-8283
	Package     string   `json:"package"`     // dpkg
	Version     string   `json:"version"`     // 1.17.27
	FixVersion  string   `json:"fix_version"` // 1.18.0
	Severity    string   `json:"severity"`    // enum in: Unknown,Negligible,Low,Medium,High,Critical
	Description string   `json:"description"` // ...
	Links       []string `json:"links"`       // - https://security-tracker.debian.org/tracker/CVE-2017-8283
}
type HarborVulnerabilityReport struct {
	Registry        Registry            `json:"registry"`
	Artifact        Artifact            `json:"artifact"`
	Severity        string              `json:"severity"` // enum in: Unknown,Negligible,Low,Medium,High,Critical
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

func severityGreaterThan(this, other string) bool {
	return severityToInt(this) > severityToInt(other)
}

func severityToInt(sev string) int {
	switch strings.ToLower(sev) {
	case "unknown":
		return 0
	case "negligible":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	default:
		logging.GetLogger().Warn().Str("severity", sev).Msg("Unexpected severity level")
		return -1
	}
}

func RedclairReportToHarborReport(redclairReport redclair.VulnerabilityReport) HarborVulnerabilityReport {
	harborVulns := []VulnerabilityItem{}
	highestSeveritySoFar := "Unknown"

	for _, redVuln := range redclairReport.Vulnerabilities {

		id := redVuln.CVE
		if redVuln.CNNVD != "" {
			id = fmt.Sprintf("%s (%s)", id, redVuln.CNNVD)
		}

		harborVuln := VulnerabilityItem{
			ID:          id,
			Package:     redVuln.FeatureName,
			Version:     redVuln.FeatureVersion,
			FixVersion:  redVuln.FixedBy, // Not sure about this field
			Severity:    redVuln.Severity,
			Description: redVuln.Description,
			Links:       redVuln.Links,
		}

		harborVulns = append(harborVulns, harborVuln)

		if severityGreaterThan(highestSeveritySoFar, redVuln.Severity) {
			highestSeveritySoFar = redVuln.Severity
		}
	}

	for _, sensitiveFile := range redclairReport.Sensitives {
		harborVuln := VulnerabilityItem{
			ID:          fmt.Sprintf("Potential leak of sensitive file: %s", sensitiveFile.Name),
			Package:     "-",
			Version:     "-",
			FixVersion:  "-",
			Severity:    "Medium",
			Description: sensitiveFile.Description,
			Links:       []string{},
		}

		harborVulns = append(harborVulns, harborVuln)
	}

	harborReport := HarborVulnerabilityReport{
		Registry: Registry{
			// Not sure why this is in the API definition in the first place but oh well...
			Authorization: "<not needed>",
			URL:           "<not needed>",
		},
		Artifact: Artifact{
			Repository: redclairReport.Repository,
			Digest:     redclairReport.Digest,
			Tag:        redclairReport.Tag,
			// Potentially modify here when we support more MIME types
			MimeType: "application/vnd.docker.distribution.manifest.v2+json",
		},
		Severity:        highestSeveritySoFar,
		Vulnerabilities: harborVulns,
	}

	return harborReport
}
