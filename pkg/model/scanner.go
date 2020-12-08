package model

import "go.mongodb.org/mongo-driver/bson/primitive"

var scannedImagesSortableFields = func() map[string]string {
	return map[string]string{
		"finishedAt":      "finishedAt",
		"overallSeverity": "scan_report.overallSeverityInt",
		"repository":      "repository",
		"tag":             "tag",
		"imageDigest":     "digest",
	}
}

func GetDefaultScannedImagesSortableName() string {
	return "finishedAt"
}

func GetScannedImagesSortableField(key string) string {
	return scannedImagesSortableFields()[key]
}

func GetScannedImagesSortableNames() []string {
	keys := make([]string, len(scannedImagesSortableFields()))

	i := 0
	for k := range scannedImagesSortableFields() {
		keys[i] = k
		i++
	}
	return keys
}

type ImageScanSummaryResult struct {
	TopVulns          []VulnerabilityInfo   `json:"topVulnerabilities"`
	OverallSeverity   string                `json:"overallSeverity"`
	Repository        string                `json:"repository"`
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

type ScanReportListItem struct {
	VulnInfo       VulnerabilityInfo          `json:"vulnInfo"`
	AffectedImages *[]ScanReportAffectedImage `json:"affectedImages"`
}

// Sensitive ...
type Sensitive struct {
	Name          string `json:"name" bson:"name"`
	Description   string `json:"description" bson:"description"`
	DescriptionEn string `json:"description_en" bson:"description_en"`
	DescriptionZh string `json:"description_zh" bson:"description_zh"`
}
