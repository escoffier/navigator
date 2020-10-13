package redclair

import (
	"encoding/json"
	"sort"
)

// VulnerabilityReport ...
type VulnerabilityReport struct {
	Repository      string              `json:"repository"`
	Image           string              `json:"image"`
	Hash            string              `json:"hash"`
	Unapproved      []string            `json:"unapproved"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
}

// LayerCommand ...
type LayerCommand struct {
	Layer   string `json:"layer"`
	Command string `json:"command"`
}

// VulnerabilityLayerReport ...
type VulnerabilityLayerReport struct {
	Layer           string              `json:"layer"`
	Command         string              `json:"command"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
}

// VulnerabilityLayerGroupReport ...
type VulnerabilityLayerGroupReport []VulnerabilityLayerReport

// VulnerabilityReportOfSingleLayer ...
type VulnerabilityReportOfSingleLayer struct {
	Layer           string              `json:"layer"`
	Image           string              `json:"image"`
	Hash            string              `json:"hash"`
	Unapproved      []string            `json:"unapproved"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
}

// InSlice ...
func InSlice(val VulnerabilityInfo, slice []VulnerabilityInfo) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

// SliceSubtract ...
func SliceSubtract(slice1, slice2 []VulnerabilityInfo) (diffslice []VulnerabilityInfo) {
	if len(slice1) < len(slice2) {
		t := slice1
		slice1 = slice2
		slice2 = t
	}
	for _, v := range slice1 {
		if !InSlice(v, slice2) {
			diffslice = append(diffslice, v)
		}
	}
	return
}

// SortBySeverity ...
func SortBySeverity(vulnerabilities []VulnerabilityInfo) {
	sort.Slice(vulnerabilities, func(i, j int) bool {
		return SeverityMap[vulnerabilities[i].Severity] < SeverityMap[vulnerabilities[j].Severity]
	})
}

// FilterApproved ...
func FilterApproved(
	vulnerabilities []VulnerabilityInfo,
	unapproved []string,
	reportAll bool,
) []VulnerabilityInfo {
	if reportAll {
		return vulnerabilities
	}

	vulns := make([]VulnerabilityInfo, 0)
	for _, vuln := range vulnerabilities {
		for _, u := range unapproved {
			if vuln.Vulnerability == u {
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns
}

// reportJSON ...
func reportJSON(
	imageName string,
	vulnerabilities []VulnerabilityInfo,
	unapproved []string,
	hash string,
) []byte {
	report := &VulnerabilityReport{
		Image:           imageName,
		Hash:            hash,
		Vulnerabilities: vulnerabilities,
		Unapproved:      unapproved,
	}
	j, err := json.MarshalIndent(report, "", "    ")
	if err != nil {
		log.Warn().Msgf("Could not create a report: report is not proper JSON %v", err)
		return nil
	}
	return j
}

// ReportJSONOfSingleLAyer ...
func ReportJSONOfSingleLAyer(
	layerID string,
	imageName string,
	vulnerabilities []VulnerabilityInfo,
	unapproved []string,
	hash string,
) []byte {
	report := &VulnerabilityReportOfSingleLayer{
		Layer:           layerID,
		Image:           imageName,
		Hash:            hash,
		Vulnerabilities: vulnerabilities,
		Unapproved:      unapproved,
	}
	reportJSON, err := json.MarshalIndent(report, "", "    ")
	if err != nil {
		log.Warn().Msgf("Could not create a report: report is not proper JSON %v", err)
		return nil
	}
	return reportJSON
}
