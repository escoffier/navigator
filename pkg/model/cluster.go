package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Cluster struct {
	MetadataEntry `json:"-" bson:",inline"`
	ID            primitive.ObjectID   `json:"id" bson:"_id, omitempty"`
	CreatedAt     time.Time            `json:"-" bson:"created_at"`
	DeletedAt     time.Time            `json:"-" bson:"deleted_at,omitempty"`
	ClusterName   string               `json:"name" bson:"name"`
	KubeConfig    string               `json:"config" bson:"config"`
	CronConfig    ComplianceCronConfig `json:"cronConfig" bson:"cronConfig"`
}
