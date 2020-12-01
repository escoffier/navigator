package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"

	"gitlab.com/piccolo_su/vegeta/pkg/metadata"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
)

const (
	// ScanTasksCollection is the collection name for the scan tasks
	ScanTasksCollection = "scantasks"

	ScanStatusInProgress          = "inprogress"
	ScanStatusSucceeded           = "succeeded"
	ScanStatusFailed              = "failed"
	ScanStatusUnprocessableEntity = "failedUnprocessable"
)

type ScannerReq struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization,omitempty"`
	Repository    string `json:"repository"`
	Digest        string `json:"digest,omitempty"`
	Tag           string `json:"tag,omitempty"`
}

// ScanTask ...
type ScanTask struct {
	metadata.MetadataEntry `json:"-" bson:",inline"`
	ID                     primitive.ObjectID `json:"dbId,omitempty" bson:"_id,omitempty"`
	URL                    string             `json:"url" bson:"url"`
	Authorization          string             `json:"-" bson:"-"` // Do NOT persist or return authorization
	Status                 string             `json:"status" bson:"status"`
	Message                string             `json:"message" bson:"message"`
	StartedAt              int64              `json:"startedAt" bson:"startedAt"`
	FinishedAt             int64              `json:"finishedAt" bson:"finishedAt"`
	Tag                    string             `json:"tag" form:"tag" query:"tag"`
	Repository             string             `json:"repository" bson:"repository"`
	ImageDigest            string             `json:"digest,omitempty" bson:"digest,omitempty"` // sha256:2166fca0902583220885c81e7dd194e51c05c2b58029c00d33b3c25a1448f108
	ScanReport             ScanReport         `json:"scan_report,omitempty" bson:"scan_report,omitempty"`
	HarborURL              string             `json:"harborURL,omitempty" bson:"harborURL,omitempty"`
	FirstScanAt            int64              `json:"firstScanAt" bson:"firstScanAt"` // tracks the first ever scan of this image (digest)
	Stale                  bool               `json:"stale" bson:"stale"`             // if true, there are newer scans of this image (digest)
}

// ScanWorkerReport ...
type ScanWorkerReport struct {
	Vulns              []redclair.VulnerabilityInfo `json:"vulnerability" bson:"vulnerability"`
	VulnsAdded         []redclair.VulnerabilityInfo `json:"vulnerabilityAdded" bson:"vulnerabilityAdded"`
	VulnsRemoved       []redclair.VulnerabilityInfo `json:"vulnerabilityRemoved" bson:"vulnerabilityRemoved"`
	Sensitive          []redclair.Sensitive         `json:"sensitive" bson:"sensitive"`
	OverallSeverity    string                       `json:"overallSeverity" bson:"overallSeverity"`
	OverallSeverityInt int                          `json:"overallSeverityInt" bson:"overallSeverityInt"`
}

// ScanReport ...
type ScanReport struct {
	Vulns              redclair.VulnerabilityReport `json:"vulnerability" bson:"vulnerability"`
	OverallSeverity    string                       `json:"overallSeverity" bson:"overallSeverity"`
	OverallSeverityInt int                          `json:"overallSeverityInt" bson:"overallSeverityInt"`
}

// CachedLayer ...
type CachedLayer struct {
	Digest       string            `json:"digest,omitempty"`
	Parent       string            `json:"parent,omitempty"`
	Repositories []string          `json:"repositories,omitempty"`
	Tags         []string          `json:"tag,omitempty"`
	ImageDigests []string          `json:"image_digest,omitempty"`
	NameSpace    string            `json:"namespace,omitempty"`
	ScanReport   *ScanWorkerReport `json:"scan_report,omitempty"`
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
