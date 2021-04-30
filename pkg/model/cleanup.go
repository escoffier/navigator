package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

const (
	GCInProgress = "inprogress"
	GCCompleted  = "completed"
	GCFailed     = "failed"
)

//HotStorageView ...
type HotStorageView struct {
	Total int64 `json:"total"`
	Used  int64 `json:"used"`
}

//GCTask ...
type GCTask struct {
	MetadataEntry `json:"-" bson:",inline"`
	StartTime     time.Time          `json:"startTime" bson:"startTime"`
	ID            primitive.ObjectID `json:"id" bson:"_id"`
	Status        string             `json:"status" bson:"status"`
}
