package model

import (
	"encoding/json"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type CheckHistoryEntry struct {
	CheckID             string  `json:"checkId" bson:"checkId"`
	CheckType           string  `json:"checkType" bson:"checkType"`
	ClusterID           string  `json:"clusterId" bson:"clusterId"`
	Operator            string  `json:"operator" bson:"operator"`
	ClusterName         string  `json:"clusterName" bson:"-"`
	CreatedAt           int64   `json:"createdAt" bson:"createdAt"`
	FinishedAt          int64   `json:"finishedAt,omitempty" bson:"finishedAt,omitempty"`
	NumSuccessful       int64   `json:"numSuccessful" bson:"numSuccessful"`
	NumFailed           int64   `json:"numFailed" bson:"numFailed"`
	NumError            int64   `json:"numError" bson:"numError"`
	NumWaiting          int64   `json:"numWaiting" bson:"numWaiting"`
	NumInconclusive     int64   `json:"numInconclusive" bson:"numInonclusive"`
	Score               float32 `json:"score" bson:"score"`
	MaxScore            float32 `json:"maxScore" bson:"maxScore"`
	TotalPoliciesPassed int64   `json:"-" bson:"totalPoliciesPassed"`
	TotalPoliciesTried  int64   `json:"-" bson:"totalPoliciesTried"`
	PolicyId            uint    `json:"policyId" bson:"policyId"`
	// 1.运行中 2.完成 3.失败
	State uint8 `json:"state" bson:"state"`
}

type HarborConfigScan struct {
	CheckID    string               `json:"check_id" bson:"checkId"`
	Harbor     string               `json:"harbor" bson:"harbor"`
	CreatedAt  int64                `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt int64                `json:"finished_at" bson:"finishedAt,omitempty"`
	Report     map[string][]CfgScan `json:"report" bson:"report,omitempty"`
}

type ProjectCfg struct {
	Metadata struct {
		AutoScan             string `json:"auto_scan"`
		EnableContentTrust   string `json:"enable_content_trust"`
		PreventVul           string `json:"prevent_vul"`
		Public               string `json:"public"`
		ReuseSysCveWhitelist string `json:"reuse_sys_cve_whitelist"`
		Severity             string `json:"severity"`
		HarborConfigLink     string `json:"harbor_config_link"`
	} `json:"metadata"`
}

type CfgScan struct {
	RuleName         string `json:"rule_name"`
	RuleDescEn       string `json:"rule_desc_en"`
	RuleDescCn       string `json:"rule_desc_cn"`
	Status           string `json:"status"`
	HarborConfigLink string `json:"harbor_config_link"`
}

type ScanResult struct {
	ID            uint32 `gorm:"column:id"`
	TaskID        string `gorm:"type:varchar(255);column:task_id"`
	CheckType     string `gorm:"type:varchar(255);column:check_type"`
	NodeName      string `gorm:"type:varchar(255);column:node_name"`
	ClusterKey    string `gorm:"type:varchar(255);column:cluster_key"`
	PolicyID      string `gorm:"type:varchar(255);column:policy_id"`
	State         string `gorm:"type:varchar(255);column:state"`
	ActualValue   string `gorm:"type:varchar(255);column:actual_value"`
	RemediationEn string `gorm:"type:varchar(255);column:remediation_en"`
	RemediationZh string `gorm:"type:varchar(255);column:remediation_zh"`
	CreatedAt     int64  `gorm:"column:create_at"`
	Status        int32  `gorm:"column:status"`
}

func (ScanResult) TableName() string {
	return "ivan_scanner_scan_bench_result"
}

type ScanHistory struct {
	TaskID      string    `gorm:"column:task_id"`
	CheckType   string    `gorm:"varchar(255);column:check_type"`
	ClusterKey  string    `gorm:"varchar(255);column:cluster_key"`
	ClusterName string    `gorm:"varchar(255);column:cluster_name"`
	Operator    string    `gorm:"varchar(255);column:operator"`
	State       ScanState `gorm:"column:state"`
	SucNode     int32     `gorm:"column:suc_node"`
	FailNode    int32     `gorm:"column:fail_node"`
	CreatedAt   int64     `gorm:"column:created_at"`
	FinishedAt  int64     `gorm:"column:finished_at"`
	PolicyID    uint      `gorm:"column:policy_id"`
}

func (ScanHistory) TableName() string {
	return "ivan_scanner_scan_bench_history"
}

type ScanNodeRecord struct {
	TaskID      string    `gorm:"column:task_id"`
	CheckType   string    `gorm:"type:varchar(255);column:check_type"`
	ClusterKey  string    `gorm:"type:varchar(255);column:cluster_key"`
	Operator    string    `gorm:"type:varchar(255);column:operator"`
	NodeName    string    `gorm:"type:varchar(255);column:node_name"`
	Namespace   string    `gorm:"type:varchar(255);column:namespace"`
	JobName     string    `gorm:"type:varchar(255);column:job_name"`
	State       ScanState `gorm:"column:state"`
	Message     string    `gorm:"type:varchar(255);column:message"`
	CreatedAt   int64     `gorm:"column:created_at"`
	FinishedAt  int64     `gorm:"column:finished_at"`
	AutoVariate string    `gorm:"type:text;column:auto_variate"`
}

func (ScanNodeRecord) TableName() string {
	return "ivan_scanner_scan_node_record"
}

type FileExport struct {
	Status     uint8  `gorm:"column:status"`
	CheckType  string `gorm:"column:check_type"`
	ClusterId  string `gorm:"column:cluster_key"`
	CheckId    string `gorm:"column:check_id"`
	FileName   string `gorm:"column:file_name"`
	UserName   string `gorm:"column:operator"`
	CreatedAt  int64  `gorm:"column:created_at"`
	FinishedAt int64  `gorm:"column:finished_at"`
}

func (FileExport) TableName() string {
	return "file_export_task"
}

type PolicyDetailInfo struct {
	Id             uint   `gorm:"primaryKey" json:"id"`
	PolicyId       string `json:"policy_id" gorm:"type:varchar(255);column:policy_id"`
	CheckType      string `json:"check_type" gorm:"type:varchar(255);column:check_type"`
	Status         int    `json:"status" gorm:"column:status"`
	Creator        string `json:"creator" gorm:"type:varchar(255);column:creator"`
	CreatedAt      int64  `json:"created_at" gorm:"column:created_at"`
	Updater        string `json:"updater" gorm:"type:varchar(255);column:updater"`
	UpdatedAt      int64  `json:"updated_at" gorm:"column:updated_at"`
	TitleEn        string `json:"title_en" gorm:"type:text;column:title_en"`
	TitleZh        string `json:"title_zh" gorm:"type:text;column:title_zh"`
	DetailEn       string `json:"detail_en" gorm:"type:text;column:detail_en"`
	DetailZh       string `json:"detail_zh" gorm:"type:text;column:detail_zh"`
	RemediationEn  string `json:"remediation_en" gorm:"type:text;column:remediation_en"`
	RemediationZh  string `json:"remediation_zh" gorm:"type:text;column:remediation_zh"`
	ExpectedResult string `json:"expeced_result" gorm:"type:varchar(255);column:expeced_result"`
	Audit          string `json:"audit" gorm:"type:varchar(255);column:audit"`
	AuditConfig    string `json:"audit_config" gorm:"type:varchar(255);column:audit_config"`
	ClassifiedZh   string `json:"classified_zh" gorm:"type:varchar(255);column:classified_zh"`
	ClassifiedEn   string `json:"classified_en" gorm:"type:varchar(255);column:classified_en"`

	// 保存策略信息
	ExtraInfo datatypes.JSON `json:"-" gorm:"column:extra_info;type:json"`

	Extra *struct {
		Os   string `json:"os"`
		Rule string `json:"rule"`
	} `json:"extraInfo" gorm:"-"`
}

func (p *PolicyDetailInfo) BeforeSave(tx *gorm.DB) (err error) {
	if p.Extra != nil {
		p.ExtraInfo, err = json.Marshal(p.Extra)
	}

	return
}

func (p *PolicyDetailInfo) AfterFind(tx *gorm.DB) (err error) {
	if p.ExtraInfo != nil {
		err = json.Unmarshal(p.ExtraInfo, &p.Extra)
	}

	return
}

func (PolicyDetailInfo) TableName() string {
	return "ivan_scanner_scan_policy_detail"
}

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
	PolicyID  uint `gorm:"-" json:"-"`
}

type CronScanTask struct {
	CreatedAt int64  `json:"created_at" gorm:"column:created_at"`
	CronTime  string `json:"cronString" gorm:"type:varchar(255);column:cron_time"`
	CheckType string `json:"check_type" gorm:"type:varchar(255);column:check_type"`
	ClusterID string `json:"cluster_id" gorm:"type:varchar(255);column:cluster_id"`
	CronId    int    `json:"cron_id" gorm:"column:cron_id"`
}

func (CronScanTask) TableName() string {
	return "ivan_scanner_cron_scan_task"
}
