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
	ID            string       `json:"id" bson:"id"`
	DescriptionEn string       `json:"description_en" bson:"description_en"`
	DescriptionZh string       `json:"description_zh" bson:"description_zh"`
	Results       []DockerTest `json:"results" bson:"results"`
}

type DockerTest struct {
	ID            string   `json:"id" bson:"id"`
	DescriptionEn string   `json:"description" bson:"description"`
	DescriptionZh string   `json:"description_zh" bson:"description_zh"`
	Result        string   `json:"result" bson:"result"`
	DetailsEn     string   `json:"details_en" bson:"details_en"`
	DetailsZh     string   `json:"details_zh" bson:"details_zh"`
	Items         []string `json:"items" bson:"items"`
}
