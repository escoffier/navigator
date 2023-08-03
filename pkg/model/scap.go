package model

import (
	"encoding/json"

	"github.com/shopspring/decimal"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

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
	ID            uint64                  `gorm:"column:id"`
	TaskID        string                  `gorm:"type:varchar(255);column:task_id"`
	CheckType     ComplianceCheckType     `gorm:"type:varchar(255);column:check_type"`
	NodeName      string                  `gorm:"type:varchar(255);column:node_name"`
	ClusterKey    string                  `gorm:"type:varchar(255);column:cluster_key"`
	PolicyID      string                  `gorm:"type:varchar(255);column:policy_id"`
	State         ScapScanResultStateType `gorm:"type:varchar(255);column:state"`
	ActualValue   string                  `gorm:"type:varchar(255);column:actual_value"`
	RemediationEn string                  `gorm:"type:varchar(255);column:remediation_en"`
	RemediationZh string                  `gorm:"type:varchar(255);column:remediation_zh"`
	UDBCP         string                  `gorm:"type:varchar(32);column:udbcp"`
	Section       string                  `gorm:"type:varchar(32);column:section"`
	CreatedAt     int64                   `gorm:"column:create_at"`
}

func (ScanResult) TableName() string {
	return "ivan_scanner_scan_bench_result"
}

type ScanHistory struct {
	TaskID       string    `gorm:"column:task_id"`
	CheckType    string    `gorm:"column:check_type"`
	ClusterKey   string    `gorm:"column:cluster_key"`
	ClusterName  string    `gorm:"column:cluster_name"`
	Operator     string    `gorm:"column:operator"`
	State        ScanState `gorm:"column:state"`
	SucNode      int32     `gorm:"column:suc_node"`
	FailNode     int32     `gorm:"column:fail_node"`
	CreatedAt    int64     `gorm:"column:created_at"`
	FinishedAt   int64     `gorm:"column:finished_at"`
	PolicyID     uint      `gorm:"column:policy_id"`
	ScheduleType string    `gorm:"type:varchar(32)"`
}

func (ScanHistory) TableName() string {
	return "ivan_scanner_scan_bench_history"
}

type ScanNodeRecord struct {
	TaskID       string          `gorm:"column:task_id"`
	CheckType    string          `gorm:"type:varchar(255);column:check_type"`
	ClusterKey   string          `gorm:"type:varchar(255);column:cluster_key"`
	Operator     string          `gorm:"type:varchar(255);column:operator"`
	NodeName     string          `gorm:"type:varchar(255);column:node_name"`
	Namespace    string          `gorm:"type:varchar(255);column:namespace"`
	JobName      string          `gorm:"type:varchar(255);column:job_name"`
	State        ScanState       `gorm:"column:state"`
	Message      string          `gorm:"type:varchar(255);column:message"`
	CreatedAt    int64           `gorm:"column:created_at"`
	FinishedAt   int64           `gorm:"column:finished_at"`
	AutoVariate  datatypes.JSON  `gorm:"type:json;column:auto_variate"`
	Pass         int             `gorm:"column:pass"`
	Fail         int             `gorm:"column:fail"`
	Warn         int             `gorm:"column:warn"`
	Info         int             `gorm:"column:info"`
	PassRate     decimal.Decimal `gorm:"column:pass_rate"`
	ScheduleType string          `gorm:"type:varchar(32)"`
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

type PolicyDetailInfoExtraDetail struct {
	Description  string   `json:"description"`
	Rationale    string   `json:"rationale"`
	Audit        string   `json:"audit"`
	Remediation  string   `json:"remediation"`
	Impact       string   `json:"impact"`
	DefaultValue string   `json:"defaultValue"`
	References   []string `json:"references"`
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

	PolicyDetailInfoExtraDetail *struct {
		PolicyDetailInfoExtraDetail `json:",inline"`
		DescriptionEn               string `json:"description_en"`
		RationaleEn                 string `json:"rationale_en"`
		AuditEn                     string `json:"audit_en"`
		RemediationEn               string `json:"remediation_en"`
		ImpactEn                    string `json:"impact_en"`
		DefaultValueEn              string `json:"defaultValue_en"`
	} `json:"extraDetail" gorm:"-"`
	PolicyDetailInfoExtraDetailJson datatypes.JSON `json:"-" gorm:"column:extra_detail;type:json"`
}

func (p *PolicyDetailInfo) BeforeSave(tx *gorm.DB) (err error) {
	if p.PolicyDetailInfoExtraDetail != nil {
		p.PolicyDetailInfoExtraDetailJson, err = json.Marshal(p.PolicyDetailInfoExtraDetail)
	}

	return
}

func (p *PolicyDetailInfo) AfterFind(tx *gorm.DB) (err error) {
	// if p.ExtraInfo != nil {
	// 	err = json.Unmarshal(p.ExtraInfo, &p.Extra)
	// }

	if p.PolicyDetailInfoExtraDetailJson != nil {
		err = json.Unmarshal(p.PolicyDetailInfoExtraDetailJson, &p.PolicyDetailInfoExtraDetail)
	}

	return
}

func (PolicyDetailInfo) TableName() string {
	return "ivan_scanner_scan_policy_detail"
}

type CheckBreakdown struct {
	PolicyNumber string `json:"policyNumber" gorm:"column:policy_id"`
	Section      string `json:"section" gorm:"column:udbcap"`
	UDBCP        string `json:"udbcp"`
	Description  string `json:"description"`
	Pass         int    `json:"pass"`
	Fail         int    `json:"fail"`
	Warn         int    `json:"warn"`
	Info         int    `json:"info"`
	Runtime      string `json:"runtime,omitempty"`
}

type ScapScanRecordNodeItem struct {
	TaskID     string    `json:"taskID"`
	CheckType  string    `json:"checkType"`
	ClusterKey string    `json:"clusterKey"`
	NodeName   string    `json:"nodeName"`
	State      ScanState `json:"state"`
	FinishedAt int64     `json:"finishedAt"`
	Pass       int       `json:"pass"`
	Fail       int       `json:"fail"`
	Warn       int       `json:"warn"`
	Info       int       `json:"info"`
}

type NodeCheckDetails struct {
	TaskID     string    `json:"taskID"`
	ClusterKey string    `json:"clusterKey"`
	NodeName   string    `json:"nodeName"`
	NodeStatus int8      `json:"nodeStatus"`
	NodeReady  int8      `json:"nodeReady"`
	ScanStatus ScanState `json:"scanStatus"`
}

type ComplianceMapEntry struct {
	PolicyNumber string                  `json:"policyNumber"`
	PolicyId     uint                    `json:"policyId"`
	Section      string                  `json:"section"`
	Description  string                  `json:"description"`
	Remediation  string                  `json:"remediation"`
	TestStatus   ScapScanResultStateType `json:"testStatus"`
	TestResult   string                  `json:"TestResult"`
	UDBCP        string                  `json:"udbcp"`
}

type PolicyDetails struct {
	PolicyNumber string                       `json:"policyNumber"`
	Section      string                       `json:"section"`
	UDBCP        string                       `json:"udbcp"`
	Description  string                       `json:"description"`
	ExtraDetail  *PolicyDetailInfoExtraDetail `json:"extraDetail"`
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
