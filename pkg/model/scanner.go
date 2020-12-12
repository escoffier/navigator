package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var VulnerabilityInImagesRiskFilters = map[string]int{
	"default":      ScanTypeBySeverity,
	"medToCrit":    ScanTypeByMedToCritical,
	"networkBased": ScanTypeNetWorkBased,
}

func GetDefaultVulnerabilityInImagesRiskFilterName() string {
	return "default"
}

var ScannedImagesSortableFields = map[string]string{
	"finishedAt":      "finishedAt",
	"overallSeverity": "scan_report.overallSeverityInt",
	"repository":      "repository",
	"tag":             "tag",
	"imageDigest":     "digest",
}

func GetDefaultScannedImagesSortableName() string {
	return "finishedAt"
}

func GetScannedImagesSortableNames() []string {
	keys := make([]string, len(ScannedImagesSortableFields))

	i := 0
	for k := range ScannedImagesSortableFields {
		keys[i] = k
		i++
	}
	return keys
}

type ImageScanSummaryResult struct {
	TopVulns          []VulnerabilityInfo   `json:"topVulnerabilities"`
	OverallSeverity   string                `json:"overallSeverity"`
	Repository        string                `json:"repository"`
	HarborURL         string                `json:"harborURL"`
	Tag               string                `json:"tag"`
	Digest            string                `json:"digest"`
	TaskID            primitive.ObjectID    `json:"taskID"`
	SensitiveFiles    []Sensitive           `json:"sensitiveFiles"`
	StartedAt         int64                 `json:"startedAt"`
	FinishedAt        int64                 `json:"finishedAt"`
	SeverityHistogram SeverityHistogramInfo `json:"severityHistogram"`
}

type ImageScanDetailedResult struct {
	TopVulns          []VulnerabilityInfo        `json:"topVulnerabilities"`
	OverallSeverity   string                     `json:"overallSeverity"`
	Repository        string                     `json:"repository"`
	HarborURL         string                     `json:"harborURL"`
	Tag               string                     `json:"tag"`
	Digest            string                     `json:"digest"`
	PerLayerReport    []VulnerabilityLayerReport `json:"perLayerReport"`
	TaskID            primitive.ObjectID         `json:"taskID"`
	SeverityHistogram SeverityHistogramInfo      `json:"severityHistogram"`
}

type ScanReportAffectedImage struct {
	Repository string             `json:"repository"`
	Tag        string             `json:"tag"`
	Digest     string             `json:"digest"`
	HarborURL  string             `json:"harborURL"`
	FinishedAt int64              `json:"finishedAt"`
	TaskID     primitive.ObjectID `json:"taskID"`
}

type VulnerabilityInImages struct {
	MetadataEntry  `json:"-" bson:",inline"`
	ID             primitive.ObjectID         `json:"id,omitempty" bson:"_id,omitempty"`
	VulnInfo       VulnerabilityInfo          `json:"vulnInfo" bson:"vulnInfo"`
	AffectedImages *[]ScanReportAffectedImage `json:"affectedImages" bson:"affectedImages"`
	ScanType       int                        `json:"-" bson:"scanType"` //By Severity 1 Med to Critical 2 Network based 3
}

// Sensitive ...
type Sensitive struct {
	Name          string `json:"name" bson:"name"`
	Description   string `json:"description" bson:"description"`
	DescriptionEn string `json:"description_en" bson:"description_en"`
	DescriptionZh string `json:"description_zh" bson:"description_zh"`
}

const (
	ScanTypeBySeverity      = 1
	ScanTypeByMedToCritical = 2
	ScanTypeNetWorkBased    = 3
)

type VulnInfoEx struct {
	// Helper struct that creates one to one mapping between vulnerability and affected image.
	VulnerabilityInfo
	AffectedRepository string
	AffectedTag        string
	AffectedDigest     string
	AffectedHarborURL  string
	FinishedAt         int64
	TaskID             primitive.ObjectID
}
