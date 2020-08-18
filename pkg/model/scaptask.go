package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	// ScapTasksCollection is the collection name for the Scap tasks
	ScapTasksCollection = "scaptasks"

	// ScannerStatusReady ready
	ScannerStatusReady ScannerStatus = iota
	// ScannerStatusWorking working
	ScannerStatusWorking
	// ScannerStatusPartiallyCompleted Partially Completed
	ScannerStatusPartiallyCompleted
	// ScannerStatusCompleted complete
	ScannerStatusCompleted
	// ScannerStatusFailed failed
	ScannerStatusFailed
)

//ScannerType Scanner Type
type ScannerType string

//ScannerStatus Status of Job
type ScannerStatus int

//CheckerConfig Checker's configuration
type CheckerConfig struct {
	ConfigFile      string
	Options         map[string]interface{}
	Version         string
	Description     string
	ConfigDirectory string
}

// ScapTask ...
type ScapTask struct {
	ID          primitive.ObjectID `json:"dbId,omitempty" bson:"_id,omitempty" query:"DbId"`
	ScannerType ScannerType        `json:"scanner_type" bson:"scanner_type"`
	Status      ScannerStatus      `json:"scanner_status" bson:"scanner_status"`
	Config      CheckerConfig      `json:"-" bson:"-"`
	CreatedAt   int64              `json:"created_at" bson:"created_at"`
	Result      string             `json:"result,omitempty" bson:"result,omitempty"`
}
