package docker

import "go.mongodb.org/mongo-driver/bson/primitive"

type DockerJobEntry struct {
	ID         primitive.ObjectID `json:"db_id,omitempty" bson:"_id,omitempty"`
	CheckID    string             `json:"check_id" bson:"checkId"`
	NodeName   string             `json:"node_name" bson:"nodeName"`
	ClusterID  string             `json:"cluster_id" bson:"clusterId"`
	Status     string             `json:"status" bson:"status,omitempty"`
	CreatedAt  int64              `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt int64              `json:"finished_at" bson:"finishedAt,omitempty"`
	Report     DockerReportResult `json:"report" bson:"report,omitempty"`
}

type DockerReportResult struct {
	DockerBenchSecurity string          `json:"dockerbenchsecurity" bson:"dockerbenchsecurity"`
	Start               int64           `json:"start" bson:"start"`
	End                 int64           `json:"end" bson:"end"`
	Score               int64           `json:"score" bson:"score"`
	Checks              int64           `json:"checks" bson:"checks"`
	Hostname            string          `json:"hostname" bson:"hostname"`
	NodeType            string          `json:"node_type" bson:"node_type"`
	Tests               []DockerSection `json:"tests" bson:"tests"`
}

type DockerSection struct {
	ID          string       `json:"id" bson:"id"`
	Description string       `json:"description" bson:"description"`
	Results     []DockerTest `json:"results" bson:"results"`
}

type DockerTest struct {
	ID          string   `json:"id" bson:"id"`
	Description string   `json:"description" bson:"description"`
	Result      string   `json:"result" bson:"result"`
	Details     string   `json:"details" bson:"details"`
	Items       []string `json:"items" bson:"items"`
}
