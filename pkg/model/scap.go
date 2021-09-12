package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var scapSortableFields = func() map[string]string {
	return map[string]string{
		"createdAt":       "createdAt",
		"finishedAt":      "finishedAt",
		"checkID":         "checkID",
		"numSuccessful":   "numSuccessful",
		"numFailed":       "numFailed",
		"numError":        "numError",
		"numWaiting":      "numWaiting",
		"numInconclusive": "numInconclusive",
	}
}

func GetScapSortableField(key string) string {
	return scapSortableFields()[key]
}

func GetScapSortableNames() []string {
	keys := make([]string, len(scapSortableFields()))

	i := 0
	for k := range scapSortableFields() {
		keys[i] = k
		i++
	}
	return keys
}

type CheckHistoryEntry struct {
	MetadataEntry       `json:"-" bson:",inline"`
	ID                  primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	CheckID             string             `json:"checkId" bson:"checkId"`
	CheckType           string             `json:"checkType" bson:"checkType"`
	ClusterID           string             `json:"clusterId" bson:"clusterId"`
	Operator            string             `json:"operator" bson:"operator"`
	ClusterName         string             `json:"clusterName" bson:"-"`
	CreatedAt           int64              `json:"createdAt" bson:"createdAt"`
	FinishedAt          int64              `json:"finishedAt,omitempty" bson:"finishedAt,omitempty"`
	NumSuccessful       int64              `json:"numSuccessful" bson:"numSuccessful"`
	NumFailed           int64              `json:"numFailed" bson:"numFailed"`
	NumError            int64              `json:"numError" bson:"numError"`
	NumWaiting          int64              `json:"numWaiting" bson:"numWaiting"`
	NumInconclusive     int64              `json:"numInconclusive" bson:"numInonclusive"`
	Score               float32            `json:"score" bson:"score"`
	MaxScore            float32            `json:"maxScore" bson:"maxScore"`
	TotalPoliciesPassed int64              `json:"-" bson:"totalPoliciesPassed"`
	TotalPoliciesTried  int64              `json:"-" bson:"totalPoliciesTried"`
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
	TaskID        string `gorm:"column:task_id"`
	CheckType     string `gorm:"column:check_type"`
	NodeName      string `gorm:"column:node_name"`
	ClusterKey    string `gorm:"column:cluster_key"`
	PolicyID      string `gorm:"column:policy_id"`
	State         string `gorm:"column:state"`
	ActualValue   string `gorm:"column:actual_value"`
	RemediationEn string `gorm:"column:remediation_en"`
	RemediationZh string `gorm:"column:remediation_zh"`
	CreatedAt     int64  `gorm:"column:create_at"`
	Status        int32  `gorm:"column:status"`
}

func (ScanResult) TableName() string {
	return "scan_bench_result"
}

type ScanHistory struct {
	TaskID      string `gorm:"column:task_id"`
	CheckType   string `gorm:"column:check_type"`
	ClusterKey  string `gorm:"column:cluster_key"`
	ClusterName string `gorm:"column:cluster_name"`
	Operator    string `gorm:"column:operator"`
	State       int32  `gorm:"column:state"`
	SucNode     int32  `gorm:"column:suc_node"`
	FailNode    int32  `gorm:"column:fail_node"`
	CreatedAt   int64  `gorm:"column:created_at"`
	FinishedAt  int64  `gorm:"column:finished_at"`
}

func (ScanHistory) TableName() string {
	return "scan_bench_history"
}

type ScanNodeRecord struct {
	TaskID      string `gorm:"column:task_id"`
	CheckType   string `gorm:"column:check_type"`
	ClusterKey  string `gorm:"column:cluster_key"`
	Operator    string `gorm:"column:operator"`
	NodeName    string `gorm:"column:node_name"`
	State       int32  `gorm:"column:state"`
	Message     string `gorm:"column:message"`
	CreatedAt   int64  `gorm:"column:created_at"`
	FinishedAt  int64  `gorm:"column:finished_at"`
	AutoVariate string `gorm:"column:auto_variate"`
}

func (ScanNodeRecord) TableName() string {
	return "scan_node_record"
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
	PolicyId       string `json:"policy_id" gorm:"column:policy_id"`
	CheckType      string `json:"check_type" gorm:"column:check_type"`
	Status         int    `json:"status" gorm:"column:status"`
	Creator        string `json:"creator" gorm:"column:creator"`
	CreatedAt      int64  `json:"created_at" gorm:"column:created_at"`
	Updater        string `json:"updater" gorm:"column:updater"`
	UpdatedAt      int64  `json:"updated_at" gorm:"column:updated_at"`
	TitleEn        string `json:"title_en" gorm:"column:title_en"`
	TitleZh        string `json:"title_zh" gorm:"column:title_zh"`
	DetailEn       string `json:"detail_en" gorm:"column:detail_en"`
	DetailZh       string `json:"detail_zh" gorm:"column:detail_zh"`
	RemediationEn  string `json:"remediation_en" gorm:"column:remediation_en"`
	RemediationZh  string `json:"remediation_zh" gorm:"column:remediation_zh"`
	ExpectedResult string `json:"expeced_result" gorm:"column:expeced_result"`
	Audit          string `json:"audit" gorm:"column:audit"`
	AuditConfig    string `json:"audit_config" gorm:"column:audit_config"`
}

func (PolicyDetailInfo) TableName() string {
	return "scan_policy_detail"
}
