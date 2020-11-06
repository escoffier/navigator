package redclair

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
	LayerDigest            string              `json:"layerDigest"`
	VulnerabilitiesAdded   []VulnerabilityInfo `json:"vulnerabilitiesAdded"`
	VulnerabilitiesRemoved []VulnerabilityInfo `json:"vulnerabilitiesRemoved"`
	Sensitives             []Sensitive         `json:"sensitives"`
}
