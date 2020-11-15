package harbor

import (
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
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
	Description string   `json:"description"`
	Links       []string `json:"links"` // - https://security-tracker.debian.org/tracker/CVE-2017-8283
}

type HarborVulnerabilityReport struct {
	Registry        Registry            `json:"registry"`
	Artifact        Artifact            `json:"artifact"`
	Severity        string              `json:"severity"` // enum in: Unknown,Negligible,Low,Medium,High,Critical
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

func RedclairReportToHarborReport(redclairReport redclair.VulnerabilityReport) HarborVulnerabilityReport {
	harborVulns := []VulnerabilityItem{}
	highestSeveritySoFar := redclair.SeverityUnknown

	for _, redVuln := range redclairReport.Vulnerabilities {

		id := redVuln.ID
		links := redVuln.Links

		description := fmt.Sprintf("[%s] %s", redVuln.ID, redVuln.Description)
		if redVuln.CVSS.CVSSv2Score != "" {
			// keeping English version for posterity
			// description = fmt.Sprintf("[CVSSv2] Score: %s (Base: %s) | %s", redVuln.CVSSv2Score, redVuln.CVSSv2Vector, description)
			description = fmt.Sprintf("[CVSSv2] 得分了: %s (基礎: %s) | %s", redVuln.CVSS.CVSSv2Score, redVuln.CVSS.CVSSv2Vector, description)
		}
		if redVuln.CVSS.CVSSv3Score != "" {
			// keeping English version for posterity
			// description = fmt.Sprintf("[CVSSv3] Score: %s, Exploitability Score: %s, Impact Score: %s (Base: %s) | %s",
			// 	redVuln.CVSSv3Score, redVuln.CVSSv3ExploitabilityScore, redVuln.CVSSv3ImpactScore, redVuln.CVSSv3Vector, description)
			description = fmt.Sprintf("[CVSSv3] 得分了: %s, 可利用性得分: %s, 影響得分: %s (基礎: %s) | %s",
				redVuln.CVSS.CVSSv3Score, redVuln.CVSS.CVSSv3ExploitabilityScore, redVuln.CVSS.CVSSv3ImpactScore, redVuln.CVSS.CVSSv3Vector, description)
		}

		akas := []string{}

		for _, cnnvd := range redVuln.CNNVDs {
			akas = append(akas, cnnvd.Number)
			links = util.AppendIfMissing(links, cnnvd.RefLink)
		}

		for _, cnvd := range redVuln.CNVDs {
			akas = append(akas, cnvd.Number)
			description = fmt.Sprintf("%s | [%s] %s: %s ", description, cnvd.Number, cnvd.Title, cnvd.Description)
			links = util.AppendIfMissing(links, cnvd.RefLink)
		}

		if len(akas) > 0 {
			// keeping English version for posterity
			// id = fmt.Sprintf("%s (aka %s)", id, strings.Join(akas, ", "))
			id = fmt.Sprintf("%s (也称为 %s)", id, strings.Join(akas, ", "))
		}

		harborVuln := VulnerabilityItem{
			ID:          id,
			Package:     redVuln.FeatureName,
			Version:     redVuln.FeatureVersion,
			FixVersion:  redVuln.FixedBy, // Not sure about this field
			Severity:    redVuln.Severity,
			Description: description,
			Links:       links,
		}

		harborVulns = append(harborVulns, harborVuln)

		if redclair.SeverityGreaterThan(highestSeveritySoFar, redVuln.Severity) {
			highestSeveritySoFar = redVuln.Severity
		}
	}

	for _, sensitiveFile := range redclairReport.Sensitives {
		harborVuln := VulnerabilityItem{
			ID:          fmt.Sprintf("敏感文件的潛在洩漏: %s", sensitiveFile.Name), // Assume ZH lang
			Package:     sensitiveFile.Name,
			Severity:    redclair.SeverityUnknown,
			Description: sensitiveFile.DescriptionZh, // Assume ZH lang
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
