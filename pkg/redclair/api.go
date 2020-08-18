package redclair

import "github.com/williballenthin/govt"

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

// ClairVulnerabilityReport ...
type ClairVulnerabilityReport struct {
	ID              string              `json:"_id" bson:"_id"`
	Image           string              `json:"Image" bson:"Image"`
	Hash            string              `json:"hash" bson:"hash"`
	Unapproved      []string            `json:"unapproved" bson:"unapproved"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities" bson:"vulnerabilities"`
}

// ClairVulnerabilityFlattenedReport ...
type ClairVulnerabilityFlattenedReport struct {
	ImageDigest    string `json:"image_dist" bson:"image_digest"`
	Image          string `json:"image" bson:"image"`
	Hash           string `json:"hash" bson:"hash"`
	FeatureName    string `json:"featurename" bson:"featurename"`
	FeatureVersion string `json:"featureversion" bson:"featureversion"`
	Vulnerability  string `json:"vulnerability" bson:"vulnerability"`
	Namespace      string `json:"namespace" bson:"namespace"`
	Description    string `json:"description" bson:"description"`
	Link           string `json:"link" bson:"link"`
	Severity       string `json:"severity" bson:"severity"`
	Fixedby        string `json:"fixedby" bson:"fixedby"`
}

// TempFileSignature ...
type TempFileSignature struct {
	Filename    string
	Digest      string
	Size        int64
	HeadContent []byte
	Detected    int
	FileReport  *govt.FileReport
	Sensitive   []SecretPattern
	Dumped      bool
}

// AggregatedTempFileSignature ...
type AggregatedTempFileSignature struct {
	Filename  string
	Digest    string
	Size      int64
	Detected  int
	Sensitive []SecretPattern
}

// ClairImageFileSignature ...
type ClairImageFileSignature struct {
	ID        string                        `json:"_id" bson:"_id"`
	ImageName string                        `json:"image_name" bson:"image_name"`
	Files     []AggregatedTempFileSignature `json:"files" bson:"files"`
}

// ClairImageFileFlattenedSignature ...
type ClairImageFileFlattenedSignature struct {
	Image     string `json:"image" bson:"image"`
	Filename  string `json:"filename" bson:"filename"`
	Digest    string `json:"digest" bson:"digest"`
	Size      int64  `json:"size" bson:"size"`
	Detected  int    `json:"detected" bson:"detected"`
	Sensitive string `json:"sensitive" bson:"sensitive"`
}

// ClairImageSoftware ...
type ClairImageSoftware struct {
	ID        string     `json:"_id" bson:"_id"`
	ImageName string     `json:"image_name" bson:"image_name"`
	Software  []Software `json:"software" bson:"software"`
}

// ClairImageFlattenedSoftware ...
type ClairImageFlattenedSoftware struct {
	Image         string `json:"image" bson:"image"`
	Name          string `json:"name" bson:"name"`
	Version       string `json:"version" bson:"version"`
	VersionFormat string `json:"version_format" bson:"version_format"`
	Type          string `json:"type" bson:"type"`
}
