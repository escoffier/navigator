package model

type CheckHistoryEntry struct {
	CheckID         string `json:"checkId"`
	ClusterID       string `json:"clusterId"`
	CreatedAt       int64  `json:"createdAt"`
	FinishedAt      int64  `json:"finishedAt,omitempty"`
	NumSuccessful   int64  `json:"numSuccessful"`
	NumFailed       int64  `json:"numFailed"`
	NumError        int64  `json:"numError"`
	NumWaiting      int64  `json:"numWaiting"`
	NumInconclusive int64  `json:"numInconclusive"`
}

type CheckBreakdown struct {
	PolicyNumber  string `json:"policyNumber"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	NumSuccessful int64  `json:"numSuccessful"`
	NumFailed     int64  `json:"numFailed"`
	NumInfo       int64  `json:"numInfo"`
	NumWarn       int64  `json:"numWarn"`
}

type PolicyDetails struct {
	PolicyNumber   string   `json:"policyNumber"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Audit          string   `json:"audit"`
	ExpectedResult string   `json:"expectedResult"`
	Remediation    string   `json:"remediation"`
	TestInfo       []string `json:"testInfo"`
	NumSuccessful  int64    `json:"numSuccessful"`
	NumFailed      int64    `json:"numFailed"`
	NumInfo        int64    `json:"numInfo"`
	NumWarn        int64    `json:"numWarn"`
	FailedOn       []string `json:"failedOn"`
	WarnOn         []string `json:"warnOn"`
	InfoOn         []string `json:"infoOn"`
	SuccessfulOn   []string `json:"successfulOn"`
}
