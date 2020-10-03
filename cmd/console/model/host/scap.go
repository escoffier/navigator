package host

import "go.mongodb.org/mongo-driver/bson/primitive"

type HostJobEntry struct {
	ID         primitive.ObjectID `json:"db_id,omitempty" bson:"_id,omitempty"`
	CheckID    string             `json:"check_id" bson:"checkId"`
	NodeName   string             `json:"node_name" bson:"nodeName"`
	ClusterID  string             `json:"cluster_id" bson:"clusterId"`
	Status     string             `json:"status" bson:"status,omitempty"`
	CreatedAt  int64              `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt int64              `json:"finished_at" bson:"finishedAt,omitempty"`
	Report     HostReportResult   `json:"report" bson:"report,omitempty"`
}

type HostReportResult struct {
	Profile string           `json:"profile" bson:"profile"`
	Results []HostReportTest `json:"results" bson:"results"`
}

type HostReportTest struct {
	Description string `json:"profile" bson:"profile"`
	Rationale   string `json:"rationale" bson:"rationale"`
	Result      string `json:"result" bson:"result"`
	RuleID      string `json:"rule-id" bson:"rule-id"`
	Title       string `json:"title" bson:"title"`
}
