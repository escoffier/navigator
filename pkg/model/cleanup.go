package model

import (
	"gitlab.com/piccolo_su/vegeta/pkg/metadata"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	GCInProgress = "inprogress"
	GCCompleted  = "completed"
	GCFailed     = "failed"
)

const (
	GCTaskCollection = "gc"
)

//HotStorageView ...
type HotStorageView struct {
	Total int64 `json:"total"`
	Used  int64 `json:"used"`
}

//GCTask ...
type GCTask struct {
	ID                     primitive.ObjectID `json:"id" bson:"_id"`
	metadata.MetadataEntry `json:"-" bson:",inline"`
	Status                 string `json:"status" bson:"status"`
}
