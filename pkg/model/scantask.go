package model

import (
	"fmt"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
)

const (
	// ScanTasksCollection is the collection name for the scan tasks
	ScanTasksCollection = "scantasks"

	ScanStatusInProgress = "inprogress"
	ScanStatusSucceeded  = "succeeded"
	ScanStatusFailed     = "failed"
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
	ID          primitive.ObjectID `json:"dbId,omitempty" bson:"_id, omitempty" query:"DbId"`
	Status      string             `json:"status" bson:"status"`
	Message     string             `json:"message" bson:"message"`
	StartedAt   int64              `json:"startedAt" bson:"startedAt"`
	FinishedAt  int64              `json:"finishedAt" bson:"finishedAt"`
	Image       string             `json:"name" form:"name" query:"name"`
	Tag         string             `json:"tag" form:"tag" query:"tag"`
	Repository  string             `json:"repository"`
	ImageDigest string             `json:"digest,omitempty"`
	ScanReport  ScanReport         `json:"scan_report,omitempty" bson:"scan_report,omitempty"`
	ForceRescan bool               `json:"-"`
}

// GetNameTag Switch an model.ScanTask into an string for more operation
func (task *ScanTask) GetNameTag() string {
	name := task.Image
	tag := task.Tag

	// Default Tag is `latest`
	if tag == "" {
		tag = "latest"
	}
	return fmt.Sprintf("%s:%s", name, tag)
}

// ScanReport ...
type ScanReport struct {
	Vulns    redclair.VulnerabilityReport `json:"vulnerability" bson:"vulnerability"`
	Files    []redclair.FileSignature     `json:"files" bson:"files"`
	Software []redclair.Software          `json:"software" bson:"software"`
}
