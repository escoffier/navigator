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
	FileName  string `json:"filename"`
	FilePath  string `json:"filepath"`
	VirusName string `json:"virusname"`
}

// WebShellInfo is the result of webshell detection
type WebShellInfo struct {
	FileName string `json:"filename"`
	FilePath string `json:"filepath"`
	// the score of webshell detection
	Score int64 `json:"score"`
	// the code-segments which contain webshell
	Codes []string `json:"codes"`
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
	Virus          []VirusInfo        `json:"virus_info"`
	WebShellInfo   []WebShellInfo     `json:"web_shell_info"`
	PerLayerReport []VirusLayerReport `json:"perLayerReport"`
}

type VirusScanReport struct {
	Virus VirusReport `json:"virus_report"`
}

type VirusScanTask struct {
	MetadataEntry `json:"-"`
	ID            primitive.ObjectID `json:"dbId,omitempty"`
	URL           string             `json:"url"`
	Authorization string             `json:"-"` // Do NOT persist or return authorization
	Status        string             `json:"status"`
	Message       string             `json:"message"`
	StartedAt     int64              `json:"startedAt"`
	FinishedAt    int64              `json:"finishedAt"`
	Tag           string             `json:"tag" form:"tag" query:"tag"`
	Repository    string             `json:"repository"`
	ImageDigest   string             `json:"digest,omitempty"` // sha256:2166fca0902583220885c81e7dd194e51c05c2b58029c00d33b3c25a1448f108
	ScanReport    VirusScanReport    `json:"virus_scan_report,omitempty"`
	HarborURL     string             `json:"harborURL,omitempty"`
	FirstScanAt   int64              `json:"firstScanAt"` // tracks the first ever scan of this image (digest)
	Stale         bool               `json:"stale"`       // if true, there are newer scans of this image (digest)
	ImageID       int64              `json:"-"`
	TableID       int64              `json:"-"`
}

func (VirusScanTask) TableName() string {
	return "virusScanTasks"
}
