package model

import "go.mongodb.org/mongo-driver/bson/primitive"

type JobEntry struct {
	MetadataEntry `json:"-" bson:",inline"`
	ID            primitive.ObjectID     `json:"db_id,omitempty" bson:"_id,omitempty"`
	CheckID       string                 `json:"check_id" bson:"checkId"`
	NodeName      string                 `json:"node_name" bson:"nodeName"`
	ClusterID     string                 `json:"cluster_id" bson:"clusterId"`
	Status        string                 `json:"status" bson:"status,omitempty"`
	CreatedAt     int64                  `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt    int64                  `json:"finished_at" bson:"finishedAt,omitempty"`
	Logs          string                 `json:"logs" bson:"logs,omitempty"`
	Report        map[string]interface{} `json:"report" bson:"report,omitempty"`
}
