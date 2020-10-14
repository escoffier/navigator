package kube

import "gitlab.com/piccolo_su/vegeta/pkg/model"

type KubeJobEntry struct {
	model.ComplianceCheckEntryBase `bson:",inline"`
	Report                         map[string]KubeReportResult `json:"report" bson:"report,omitempty"`
}

type KubeReportResult struct {
	ID       string        `json:"id" bson:"id"`
	Version  string        `json:"version" bson:"version"`
	Text     string        `json:"text" bson:"text"`
	NodeType string        `json:"node_type" bson:"node_type"`
	Tests    []KubeSection `json:"tests" bson:"tests"`
}

type KubeSection struct {
	Section     string           `json:"section" bson:"section"`
	Pass        int64            `json:"pass" bson:"pass"`
	Fail        int64            `json:"fail" bson:"fail"`
	Warn        int64            `json:"warn" bson:"warn"`
	Info        int64            `json:"info" bson:"info"`
	Description string           `json:"desc" bson:"desc"`
	Results     []KubeTestResult `json:"results" bson:"results"`
}

type KubeTestResult struct {
	TestNumber      string   `json:"test_number" bson:"test_number"`
	TestDescription string   `json:"test_desc" bson:"test_desc"`
	Audit           string   `json:"audit" bson:"audit"`
	Type            string   `json:"type" bson:"type"`
	Remediation     string   `json:"remediation" bson:"remediation"`
	TestInfo        []string `json:"test_info" bson:"test_info"`
	ExpectedResult  string   `json:"expected_result" bson:"expected_result"`
	IsMultiple      bool     `json:"IsMultiple" bson:"IsMultiple"`
	ActualValue     string   `json:"actual_value" bson:"actual_value"`
	Status          string   `json:"status" bson:"status"`
}
