package docker

import "gitlab.com/piccolo_su/vegeta/pkg/model"

type DockerJobEntry struct {
	model.ComplianceCheckEntryBase `bson:",inline"`
	Report                         DockerReportResult `json:"report" bson:"report,omitempty"`
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
