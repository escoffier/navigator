package model

// CachedScanWorkerReport ...
type CachedScanWorkerReport struct {
	Vulns              []VulnerabilityInfo   `json:"vulnerability" bson:"vulnerability"`
	VulnsAdded         []VulnerabilityInfo   `json:"vulnerabilityAdded" bson:"vulnerabilityAdded"`
	VulnsRemoved       []VulnerabilityInfo   `json:"vulnerabilityRemoved" bson:"vulnerabilityRemoved"`
	Sensitive          []Sensitive           `json:"sensitive" bson:"sensitive"`
	OverallSeverity    string                `json:"overallSeverity" bson:"overallSeverity"`
	OverallSeverityInt int                   `json:"overallSeverityInt" bson:"overallSeverityInt"`
	SeverityHistogram  SeverityHistogramInfo `json:"severityHistogram" bson:"severityHistogram"`
}

type CachedLayer struct {
	Digest       string                  `json:"digest,omitempty"`
	Parent       string                  `json:"parent,omitempty"`
	Repositories []string                `json:"repositories,omitempty"`
	Tags         []string                `json:"tag,omitempty"`
	ImageDigests []string                `json:"image_digest,omitempty"`
	NameSpace    string                  `json:"namespace,omitempty"`
	ScanReport   *CachedScanWorkerReport `json:"scan_report,omitempty"`
}

type DBUpdateTime struct {
	Value int64 `json:"value"`
}

type DBVulnerabilityUpdateTime struct {
	MaxCreatedAt string `json:"maxcreatedat"`
}

type DBVulnerabilityEntry struct {
	Name      string `json:"name"`
	NameSpace string `json:"namespace"`
}
