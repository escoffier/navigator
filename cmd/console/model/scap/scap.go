package scap

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
