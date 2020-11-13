package scap

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type CheckHistoryEntry struct {
	CheckID             string  `json:"checkId"`
	ClusterID           string  `json:"clusterId"`
	ClusterName         string  `json:"clusterName"`
	CreatedAt           int64   `json:"createdAt"`
	FinishedAt          int64   `json:"finishedAt,omitempty"`
	NumSuccessful       int64   `json:"numSuccessful"`
	NumFailed           int64   `json:"numFailed"`
	NumError            int64   `json:"numError"`
	NumWaiting          int64   `json:"numWaiting"`
	NumInconclusive     int64   `json:"numInconclusive"`
	Score               float32 `json:"score"`
	MaxScore            float32 `json:"maxScore"`
	TotalPoliciesPassed int64   `json:"-"`
	TotalPoliciesTried  int64   `json:"-"`
}

type CheckBreakdown struct {
	PolicyNumber  string `json:"policyNumber"`
	Section       string `json:"section"`
	Description   string `json:"description"`
	NumSuccessful int64  `json:"numSuccessful"`
	NumFailed     int64  `json:"numFailed"`
	NumInfo       int64  `json:"numInfo"`
	NumWarn       int64  `json:"numWarn"`
}

type NodeCheckDetails struct {
	CheckID       string               `json:"checkId"`
	ClusterID     string               `json:"clusterId"`
	Status        string               `json:"status"`
	NodeName      string               `json:"nodeName"`
	Logs          string               `json:"logs"`
	ComplianceMap []ComplianceMapEntry `json:"complianceMap"`
}

type ComplianceMapEntry struct {
	PolicyNumber string `json:"policyNumber"`
	Section      string `json:"section"`
	Description  string `json:"description"`
	TestStatus   string `json:"testStatus"`
}

type PolicyDetails struct {
	PolicyNumber   string   `json:"policyNumber"`
	Section        string   `json:"section"`
	Description    string   `json:"description"`
	Audit          string   `json:"audit"`
	ExpectedResult string   `json:"expectedResult"`
	Remediation    string   `json:"remediation"`
	Rationale      string   `json:"rationale"`
	TestInfo       []string `json:"testInfo"`
	Reason         string   `json:"reason"`

	Details string   `json:"details"`
	Items   []string `json:"items"`

	NumSuccessful int64    `json:"numSuccessful"`
	NumFailed     int64    `json:"numFailed"`
	NumInfo       int64    `json:"numInfo"`
	NumWarn       int64    `json:"numWarn"`
	NumError      int64    `json:"numError"`
	NumWaiting    int64    `json:"numWaiting"`
	FailedOn      []string `json:"failedOn"`
	WarnOn        []string `json:"warnOn"`
	InfoOn        []string `json:"infoOn"`
	SuccessfulOn  []string `json:"successfulOn"`
	ErrorOn       []string `json:"errorOn"`
	WaitingOn     []string `json:"waitingOn"`
}

type JobEntry struct {
	ID         primitive.ObjectID     `json:"db_id,omitempty" bson:"_id,omitempty"`
	CheckID    string                 `json:"check_id" bson:"checkId"`
	NodeName   string                 `json:"node_name" bson:"nodeName"`
	ClusterID  string                 `json:"cluster_id" bson:"clusterId"`
	Status     string                 `json:"status" bson:"status,omitempty"`
	CreatedAt  int64                  `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt int64                  `json:"finished_at" bson:"finishedAt,omitempty"`
	Logs       string                 `json:"logs" bson:"logs,omitempty"`
	Report     map[string]interface{} `json:"report" bson:"report,omitempty"`
}
