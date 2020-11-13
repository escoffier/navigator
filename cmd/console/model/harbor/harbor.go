package harbor

import (
	"context"
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/lang"
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
	ID            string   `json:"id"` // CVE-2017-8283
	IDEn          string   `json:"-"`
	IDZh          string   `json:"-"`
	Package       string   `json:"package"`     // dpkg
	Version       string   `json:"version"`     // 1.17.27
	FixVersion    string   `json:"fix_version"` // 1.18.0
	Severity      string   `json:"severity"`    // enum in: Unknown,Negligible,Low,Medium,High,Critical
	Description   string   `json:"description"`
	DescriptionEn string   `json:"-"`
	DescriptionZh string   `json:"-"`
	Links         []string `json:"links"` // - https://security-tracker.debian.org/tracker/CVE-2017-8283
}

func (vi *VulnerabilityItem) ApplyTranslation(ctx context.Context) {
	if lang.Language(ctx) == lang.LanguageZH {
		vi.Description = vi.DescriptionZh
		vi.ID = vi.IDZh
		vi.Severity = redclair.ToChineseSeverity(vi.Severity)
	} else {
		vi.Description = vi.DescriptionEn
		vi.ID = vi.IDEn
	}
}

type HarborVulnerabilityReport struct {
	Registry        Registry            `json:"registry"`
	Artifact        Artifact            `json:"artifact"`
	Severity        string              `json:"severity"` // enum in: Unknown,Negligible,Low,Medium,High,Critical
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

func (hvr *HarborVulnerabilityReport) ApplyTranslation(ctx context.Context) {
	for i := range hvr.Vulnerabilities {
		hvr.Vulnerabilities[i].ApplyTranslation(ctx)
	}
	if lang.Language(ctx) == lang.LanguageZH {
		hvr.Severity = redclair.ToChineseSeverity(hvr.Severity)
	}
}

func RedclairReportToHarborReport(redclairReport redclair.VulnerabilityReport) HarborVulnerabilityReport {
	harborVulns := []VulnerabilityItem{}
	highestSeveritySoFar := redclair.SeverityUnknownEn

	for _, redVuln := range redclairReport.Vulnerabilities {

		id := redVuln.CVE
		if redVuln.CNNVD != "" {
			id = fmt.Sprintf("%s (%s)", id, redVuln.CNNVD)
		}

		descriptionEn := redVuln.DescriptionEn
		descriptionZh := redVuln.DescriptionZh
		if redVuln.CVSSv2Score != "" {
			descriptionEn = fmt.Sprintf("[CVSSv2] Score: %s (Base: %s) | %s", redVuln.CVSSv2Score, redVuln.CVSSv2Vector, descriptionEn)
			descriptionZh = fmt.Sprintf("[CVSSv2] 得分了: %s (基礎: %s) | %s", redVuln.CVSSv2Score, redVuln.CVSSv2Vector, descriptionZh)
		}
		if redVuln.CVSSv3Score != "" {
			descriptionEn = fmt.Sprintf("[CVSSv3] Score: %s, Exploitability Score: %s, Impact Score: %s (Base: %s) | %s",
				redVuln.CVSSv3Score, redVuln.CVSSv3ExploitabilityScore, redVuln.CVSSv3ImpactScore, redVuln.CVSSv3Vector, descriptionEn)
			descriptionZh = fmt.Sprintf("[CVSSv3] 得分了: %s, 可利用性得分: %s, 影響得分: %s (基礎: %s) | %s",
				redVuln.CVSSv3Score, redVuln.CVSSv3ExploitabilityScore, redVuln.CVSSv3ImpactScore, redVuln.CVSSv3Vector, descriptionZh)
		}

		harborVuln := VulnerabilityItem{
			IDEn:          id,
			IDZh:          id,
			Package:       redVuln.FeatureName,
			Version:       redVuln.FeatureVersion,
			FixVersion:    redVuln.FixedBy, // Not sure about this field
			Severity:      redVuln.Severity,
			DescriptionEn: descriptionEn,
			DescriptionZh: descriptionZh,
			Links:         redVuln.Links,
		}

		harborVulns = append(harborVulns, harborVuln)

		if redclair.SeverityGreaterThan(highestSeveritySoFar, redVuln.Severity) {
			highestSeveritySoFar = redVuln.Severity
		}
	}

	for _, sensitiveFile := range redclairReport.Sensitives {
		harborVuln := VulnerabilityItem{
			IDEn:          fmt.Sprintf("Potential leak of sensitive file: %s", sensitiveFile.Name),
			IDZh:          fmt.Sprintf("敏感文件的潛在洩漏: %s", sensitiveFile.Name),
			Package:       "-",
			Version:       "-",
			FixVersion:    "-",
			Severity:      redclair.SeverityMediumEn,
			DescriptionEn: sensitiveFile.DescriptionEn,
			DescriptionZh: sensitiveFile.DescriptionZh,
			Links:         []string{},
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
