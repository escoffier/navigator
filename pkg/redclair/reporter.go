package redclair

import "context"

// VulnerabilityReport ...
type VulnerabilityReport struct {
	Repository      string                     `json:"repository"`
	Tag             string                     `json:"tag"`
	Digest          string                     `json:"digest"`
	Unapproved      []string                   `json:"unapproved"`
	Vulnerabilities []VulnerabilityInfo        `json:"vulnerabilities"`
	Sensitives      []Sensitive                `json:"sensitives"`
	PerLayerReport  []VulnerabilityLayerReport `json:"perLayerReport"`
}

// VulnerabilityLayerReport ...
type VulnerabilityLayerReport struct {
	LayerNo                int                 `json:"layerNo"`
	LayerDigest            string              `json:"layerDigest"`
	VulnerabilitiesAdded   []VulnerabilityInfo `json:"vulnerabilitiesAdded"`
	VulnerabilitiesRemoved []VulnerabilityInfo `json:"vulnerabilitiesRemoved"`
	Sensitives             []Sensitive         `json:"sensitives"`
}

func (vlr *VulnerabilityLayerReport) ApplyTranslation(ctx context.Context) {
	for i := range vlr.VulnerabilitiesAdded {
		vlr.VulnerabilitiesAdded[i].ApplyTranslation(ctx)
	}
	for i := range vlr.VulnerabilitiesRemoved {
		vlr.VulnerabilitiesRemoved[i].ApplyTranslation(ctx)
	}
	for i := range vlr.Sensitives {
		vlr.Sensitives[i].ApplyTranslation(ctx)
	}
}
