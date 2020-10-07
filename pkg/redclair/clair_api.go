package redclair

// NewerLayerFeaturesVulnerability New layer feature
type NewerLayerFeaturesVulnerability struct {
	Name          string
	NamespaceName string
	Description   string
	Link          string
	Severity      string
	FixedBy       string
}

// NewerLayerFeature New Layer feature
type NewerLayerFeature struct {
	Name            string
	NamespaceName   string
	VersionFormat   string
	Version         string
	AddedBy         string
	Vulnerabilities []NewerLayerFeaturesVulnerability
}

// NewerLayer New Layer of image
type NewerLayer struct {
	Name       string
	Path       string
	ParentName string
	Format     string
	Features   []NewerLayerFeature
}

// NewerLayerEnvelopeError Envelop error
type NewerLayerEnvelopeError struct {
	Message string
}

// NewerLayerEnvelope Newer Layer Envelop
type NewerLayerEnvelope struct {
	Layer NewerLayer
	Error *NewerLayerEnvelopeError
}
