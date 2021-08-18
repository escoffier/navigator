package model

import "time"

type VirusCachedScanWorkerReport struct {
	Virus     []VirusInfo    `json:"virus" bson:"virus"`
	Webshells []WebShellInfo `json:"webshells" bson:"webshells"`
}

type VirusCachedLayer struct {
	Digest       string   `json:"digest,omitempty"`
	Parent       string   `json:"parent,omitempty"`
	Repositories []string `json:"repositories,omitempty"`
	Tags         []string `json:"tag,omitempty"`
	ImageDigests []string `json:"image_digest,omitempty"`
	//NameSpace    string                       `json:"namespace,omitempty"`
	ScanReport *VirusCachedScanWorkerReport `json:"scan_report,omitempty"`
}

type VirusScanQueueInfo struct {
	Status  string
	StartAt time.Time
}

type VirusScanStatusInfo struct {
	Status string `json:"status,omitempty"`
	Digest string `json:"digest,omitempty"`
}
