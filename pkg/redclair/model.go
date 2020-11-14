package redclair

import "context"

type CNVDVulnerabilityInfo struct {
	Number      string `json:"number" bson:"number"`
	Title       string `json:"title" bson:"title"`
	Severity    string `json:"severity" bson:"severity"`
	RefLink     string `json:"referenceLink" bson:"referenceLink"`
	Description string `json:"description" bson:"description"`
}

type CNNVDVulnerabilityInfo struct {
	Number  string `json:"number" bson:"number"`
	RefLink string `json:"referenceLink" bson:"referenceLink"`
	// TODO other fields once we obtain the CNNVD database?
}

type CVSSVulnerabilityInfo struct {
	CVSSv2Score               string `json:"cvssv2score" bson:"cvssv2score"`
	CVSSv2Vector              string `json:"cvssv2vector" bson:"cvssv2vector"`
	CVSSv3Score               string `json:"cvssv3score" bson:"cvssv3score"`
	CVSSv3ExploitabilityScore string `json:"cvssv3exploitabilityScore" bson:"cvssv3exploitabilityScore"`
	CVSSv3ImpactScore         string `json:"cvssv3impactScore" bson:"cvssv3impactScore"`
	CVSSv3Vector              string `json:"cvssv3vector" bson:"cvssv3vector"`
}

type VulnerabilityInfo struct {
	ID          string `json:"id" bson:"id"` // this doesn't have to be CVE. This could be for example ELSA...
	Description string `json:"description" bson:"description"`

	FeatureName    string   `json:"featurename" bson:"featurename"`
	FeatureVersion string   `json:"featureversion" bson:"featureversion"`
	Namespace      string   `json:"namespace" bson:"namespace"`
	Links          []string `json:"links" bson:"links"`
	Severity       string   `json:"severity" bson:"severity"`
	FixedBy        string   `json:"fixedby" bson:"fixedby"`

	CVSS   CVSSVulnerabilityInfo    `json:"cvss,omitempty" bson:"cvss,omitempty"`
	CNNVDs []CNNVDVulnerabilityInfo `json:"cnnvds,omitempty" bson:"cnnvds,omitempty"`
	CNVDs  []CNVDVulnerabilityInfo  `json:"cnvds,omitempty" bson:"cnvds,omitempty"`
}

// VulnerabilityReport ...
type VulnerabilityReport struct {
	Repository      string                     `json:"repository"`
	Tag             string                     `json:"tag"`
	Digest          string                     `json:"digest"`
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
	for i := range vlr.Sensitives {
		vlr.Sensitives[i].ApplyTranslation(ctx)
	}
}
