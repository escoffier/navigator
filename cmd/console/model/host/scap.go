package host

import "gitlab.com/piccolo_su/vegeta/pkg/model"

type HostJobEntry struct {
	model.ComplianceCheckEntryBase `bson:",inline"`
	Report                         HostReportResult `json:"report" bson:"report,omitempty"`
}

type HostReportResult struct {
	Profile string           `json:"profile" bson:"profile"`
	Results []HostReportTest `json:"results" bson:"results"`
}

type HostReportTest struct {
	Result string `json:"result" bson:"result"`
	RuleID string `json:"rule-id" bson:"rule-id"`
	Title  string `json:"title" bson:"title"`
}
