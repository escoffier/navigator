package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	VirusScanSuccess = "success"
	VirusScanFailed  = "failed"
	VirusScanDoing   = "doing"
	VirusScanWait    = "wait"
)

type VirusInfo struct {
	FileName  string `json:"filename" bson:"filename"`
	FilePath  string `json:"filepath" bson:"filepath"`
	VirusName string `json:"virusname" bson:"virusname"`
}

// WebShellInfo is the result of webshell detection
type WebShellInfo struct {
	FileName string `json:"filename" bson:"filename"`
	FilePath string `json:"filepath" bson:"filepath"`
	// the score of webshell detection
	Score int64 `json:"score" bson:"score"`
	// the code-segments which contain webshell
	Codes []string `json:"codes" bson:"codes"`
}

type VirusLayerReport struct {
	LayerNo      int            `json:"layerNo"`
	LayerDigest  string         `json:"layerDigest"`
	ViursInfo    []VirusInfo    `json:"virus_info"`
	WebShellInfo []WebShellInfo `json:"web_shell_info"`
}

type VirusReport struct {
	Repository     string             `json:"repository"`
	Tag            string             `json:"tag"`
	Digest         string             `json:"digest"`
	Virus          []VirusInfo        `json:"virus_info" bson:"virus_info"`
	WebShellInfo   []WebShellInfo     `json:"web_shell_info"`
	PerLayerReport []VirusLayerReport `json:"perLayerReport"`
}

type VirusScanReport struct {
	Virus VirusReport `json:"virus_report"`
}

type VirusScanTask struct {
	MetadataEntry `json:"-" bson:",inline"`
	ID            primitive.ObjectID `json:"dbId,omitempty" bson:"_id,omitempty"`
	URL           string             `json:"url" bson:"url"`
	Authorization string             `json:"-" bson:"-"` // Do NOT persist or return authorization
	Status        string             `json:"status" bson:"status"`
	Message       string             `json:"message" bson:"message"`
	StartedAt     int64              `json:"startedAt" bson:"startedAt"`
	FinishedAt    int64              `json:"finishedAt" bson:"finishedAt"`
	Tag           string             `json:"tag" form:"tag" query:"tag"`
	Repository    string             `json:"repository" bson:"repository"`
	ImageDigest   string             `json:"digest,omitempty" bson:"digest,omitempty"` // sha256:2166fca0902583220885c81e7dd194e51c05c2b58029c00d33b3c25a1448f108
	ScanReport    VirusScanReport    `json:"virus_scan_report,omitempty" bson:"virus_scan_report,omitempty"`
	HarborURL     string             `json:"harborURL,omitempty" bson:"harborURL,omitempty"`
	FirstScanAt   int64              `json:"firstScanAt" bson:"firstScanAt"` // tracks the first ever scan of this image (digest)
	Stale         bool               `json:"stale" bson:"stale"`             // if true, there are newer scans of this image (digest)
	ImageID       int64              `json:"-" bson:"-"`
	TableID       int64              `json:"-" bson:"-"`
	// SeverityHistogram SeverityHistogramInfo `json:"severityHistogram" bson:"severityHistogram"`
}

func (VirusScanTask) TableName() string {
	return "virusScanTasks"
}
