package scap

type CheckBreakdown struct {
	PolicyNumber  string `json:"policyNumber"`
	Section       string `json:"section"`
	Description   string `json:"description"`
	NumSuccessful int64  `json:"numSuccessful"`
	NumFailed     int64  `json:"numFailed"`
	NumInfo       int64  `json:"numInfo"`
	NumWarn       int64  `json:"numWarn"`
	Classified    string `json:"classified"`
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
	Remediation  string `json:"remediation"`
	TestStatus   string `json:"testStatus"`
	Classified   string `json:"classified"`
}

type PolicyNodeRet struct {
	NodeName    string `json:"nodeName"`
	Remediation string `json:"remediation"`
	TestStatus  string `json:"testStatus"`
}

type PolicyDetails struct {
	CheckID        string   `json:"-"`
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

	NumSuccessful int64 `json:"numSuccessful"`
	NumFailed     int64 `json:"numFailed"`
	NumInfo       int64 `json:"numInfo"`
	NumWarn       int64 `json:"numWarn"`
	NumError      int64 `json:"numError"`
	NumWaiting    int64 `json:"numWaiting"`

	FailedOn     []PolicyNodeRet `json:"failedOn"`
	WarnOn       []PolicyNodeRet `json:"warnOn"`
	InfoOn       []PolicyNodeRet `json:"infoOn"`
	SuccessfulOn []PolicyNodeRet `json:"successfulOn"`
	ErrorOn      []PolicyNodeRet `json:"errorOn"`
	WaitingOn    []PolicyNodeRet `json:"waitingOn"`
}

type Check struct {
	CheckType string
	CheckUUID string
	ClusterID string
	NodeName  string
	Namespace string
	Operator  string
}
