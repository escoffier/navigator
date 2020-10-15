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
