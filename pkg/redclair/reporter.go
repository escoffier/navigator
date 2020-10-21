package redclair

import (
	"sort"
)

// VulnerabilityReport ...
type VulnerabilityReport struct {
	Repository      string              `json:"repository"`
	Tag             string              `json:"tag"`
	Digest          string              `json:"digest"`
	Unapproved      []string            `json:"unapproved"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
}

// SortBySeverity ...
func SortBySeverity(vulnerabilities []VulnerabilityInfo) {
	sort.Slice(vulnerabilities, func(i, j int) bool {
		return SeverityMap[vulnerabilities[i].Severity] < SeverityMap[vulnerabilities[j].Severity]
	})
}
