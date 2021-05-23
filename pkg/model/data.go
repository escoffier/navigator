package model

import (
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

const (
	GCInProgress = "inprogress"
	GCCompleted  = "completed"
	GCFailed     = "failed"
)

const (
	DataTypeHotLogic   = "hotLogic"
	DataTypeHotOffline = "hotOffline"
	DataTypeCold       = "cold"
)

//StorageView ...
type StorageView struct {
	Total int64 `json:"total"`
	Used  int64 `json:"used"`
}

func (s *StorageView) String() string {
	return fmt.Sprintf("total:%dMB, used:%dMB", s.Total/1024/1024, s.Used/1024/1024)
}

//GCTask ...
type GCTask struct {
	MetadataEntry `json:"-" bson:",inline"`
	Category      string             `json:"category" bson:"category"`
	StartTime     time.Time          `json:"startTime" bson:"startTime"`
	ID            primitive.ObjectID `json:"id" bson:"_id"`
	Status        string             `json:"status" bson:"status"`
}

type DataTTLRecord struct {
	ID        primitive.ObjectID `json:"id" bson:"_id"`
	TTL       int                `bson:"ttl"`
	Category  string             `bson:"category"`
	UpdatedAt time.Time          `bson:"updated_at"`
}

type WaterlineRecord struct {
	ID         primitive.ObjectID `json:"id" bson:"_id"`
	Percentage int                `bson:"percentage"`
	UpdatedAt  time.Time          `bson:"updated_at"`
}
