package redclair

import (
	"sort"
)

// VulnerabilityReport ...
type VulnerabilityReport struct {
	Repository      string                              `json:"repository"`
	Tag             string                              `json:"tag"`
	Digest          string                              `json:"digest"`
	Unapproved      []string                            `json:"unapproved"`
	Vulnerabilities []VulnerabilityInfo                 `json:"vulnerabilities"`
	Sensitives      []Sensitive                         `json:"sensitives"`
	PerLayerReport  map[string]VulnerabilityLayerReport `json:"perLayerReport"`
}

// VulnerabilityLayerReport ...
type VulnerabilityLayerReport struct {
	VulnerabilitiesAdded   []VulnerabilityInfo `json:"vulnerabilitiesAdded"`
	VulnerabilitiesRemoved []VulnerabilityInfo `json:"vulnerabilitiesRemoved"`
	Sensitives             []Sensitive         `json:"sensitives"`
}

// SortBySeverity ...
func SortBySeverity(vulnerabilities []VulnerabilityInfo) {
	sort.Slice(vulnerabilities, func(i, j int) bool {
		return SeverityMap[vulnerabilities[i].Severity] < SeverityMap[vulnerabilities[j].Severity]
	})
}
