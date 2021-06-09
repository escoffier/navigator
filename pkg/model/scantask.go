package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	ScanStatusInProgress          = "inprogress"
	ScanStatusSucceeded           = "succeeded"
	ScanStatusFailed              = "failed"
	ScanStatusPending             = "pending"
	ScanStatusUnprocessableEntity = "failedUnprocessable"
)

type ScannerReq struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization,omitempty"`
	Repository    string `json:"repository"`
	Digest        string `json:"digest,omitempty"`
	Tag           string `json:"tag,omitempty"`
	ResultsURL    string `json:"resultsUrl,omitempty"`
}

// ScanTask ...
type ScanTask struct {
	MetadataEntry     `json:"-" bson:",inline"`
	ID                primitive.ObjectID    `json:"dbId,omitempty" bson:"_id,omitempty"`
	URL               string                `json:"url" bson:"url"`
	Authorization     string                `json:"-" bson:"-"` // Do NOT persist or return authorization
	Status            string                `json:"status" bson:"status"`
	Message           string                `json:"message" bson:"message"`
	StartedAt         int64                 `json:"startedAt" bson:"startedAt"`
	FinishedAt        int64                 `json:"finishedAt" bson:"finishedAt"`
	Tag               string                `json:"tag" form:"tag" query:"tag"`
	Repository        string                `json:"repository" bson:"repository"`
	ImageDigest       string                `json:"digest,omitempty" bson:"digest,omitempty"` // sha256:2166fca0902583220885c81e7dd194e51c05c2b58029c00d33b3c25a1448f108
	ScanReport        ScanReport            `json:"scan_report,omitempty" bson:"scan_report,omitempty"`
	HarborURL         string                `json:"harborURL,omitempty" bson:"harborURL,omitempty"`
	FirstScanAt       int64                 `json:"firstScanAt" bson:"firstScanAt"` // tracks the first ever scan of this image (digest)
	Stale             bool                  `json:"stale" bson:"stale"`             // if true, there are newer scans of this image (digest)
	SeverityHistogram SeverityHistogramInfo `json:"severityHistogram" bson:"severityHistogram"`
	ImageID           int64                 `json:"-" bson:"-"`
	TableID           int64                 `json:"-" bson:"-"`
}

type ScanReport struct {
	Vulns              VulnerabilityReport   `json:"vulnerability" bson:"vulnerability"`
	OverallSeverity    string                `json:"overallSeverity" bson:"overallSeverity"`
	OverallSeverityInt int                   `json:"overallSeverityInt" bson:"overallSeverityInt"`
	SeverityHistogram  SeverityHistogramInfo `json:"severityHistogram" bson:"severityHistogram"`
}

type SeverityHistogramInfo struct {
	NumCritical   int64 `json:"numCritical"`
	NumHigh       int64 `json:"numHigh"`
	NumMedium     int64 `json:"numMedium"`
	NumLow        int64 `json:"numLow"`
	NumNegligible int64 `json:"numNegligible"`
	NumUnknown    int64 `json:"numUnknown"`
}

type VulnerabilityReport struct {
	Repository        string                     `json:"repository"`
	Tag               string                     `json:"tag"`
	Digest            string                     `json:"digest"`
	Vulnerabilities   []VulnerabilityInfo        `json:"vulnerabilities"`
	Sensitives        []Sensitive                `json:"sensitives"`
	PerLayerReport    []VulnerabilityLayerReport `json:"perLayerReport"`
	SeverityHistogram SeverityHistogramInfo      `json:"severityHistogram" bson:"severityHistogram"`
}

type VulnerabilityLayerReport struct {
	LayerNo                int                   `json:"layerNo"`
	LayerDigest            string                `json:"layerDigest"`
	VulnerabilitiesAdded   []VulnerabilityInfo   `json:"vulnerabilitiesAdded"`
	VulnerabilitiesRemoved []VulnerabilityInfo   `json:"vulnerabilitiesRemoved"`
	Sensitives             []Sensitive           `json:"sensitives"`
	OverallSeverity        string                `json:"overallSeverity"`
	OverallSeverityInt     int                   `json:"overallSeverityInt"`
	SeverityHistogram      SeverityHistogramInfo `json:"severityHistogram" bson:"severityHistogram"`
}

type ImageResponse struct {
	ID           int64          `json:"id"`
	Digest       string         `json:"digest"`
	Library      string         `json:"library"`
	ScanStatus   string         `json:"scan_status"`
	CompleteTime string         `json:"complete_time"`
	Questions    []QuestionInfo `json:"questions"`
	FullRepoName string         `json:"full_repo_name"`
	Tags         string         `json:"tags"`
}

type ScanOneStatusResponse struct {
	ScanStatus   string `json:"scan_status"`
	EndTime      string `json:"end_time"`
	HasVulu      bool   `json:"has_vulu"`      // 是否有漏洞
	HasMalicious bool   `json:"has_malicious"` // 是否有病毒
	HasSensitive bool   `json:"has_sensitive"` // 是否有敏感文件
}
