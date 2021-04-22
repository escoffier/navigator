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

func GetDefaultScapSortableName() string {
	return "createdAt"
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

type JobEntry struct {
	MetadataEntry `json:"-" bson:",inline"`
	ID            primitive.ObjectID     `json:"db_id,omitempty" bson:"_id,omitempty"`
	CheckID       string                 `json:"check_id" bson:"checkId"`
	NodeName      string                 `json:"node_name" bson:"nodeName"`
	ClusterID     string                 `json:"cluster_id" bson:"clusterId"`
	Operator      string                 `json:"operator" bson:"operator"`
	Status        string                 `json:"status" bson:"status,omitempty"`
	CreatedAt     int64                  `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt    int64                  `json:"finished_at" bson:"finishedAt,omitempty"`
	Logs          string                 `json:"logs" bson:"logs,omitempty"`
	Report        map[string]interface{} `json:"report" bson:"report,omitempty"`
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
