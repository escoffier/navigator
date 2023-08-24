package model

import (
	"database/sql/driver"

	json "github.com/json-iterator/go"
)

type WafService struct {
	TableBase
	Name         string `gorm:"column:name"`
	ClusterKey   string `gorm:"column:cluster_key"`
	Namespace    string `gorm:"column:namespace"`
	Kind         string `gorm:"column:kind"`
	ResourceName string `gorm:"column:resource_name"`
	UriPrefix    string `gorm:"column:uri_prefix"`
	Mode         string `gorm:"column:mode"`
	Host         string `gorm:"column:host"`
	Description  string `gorm:"column:description"`
	Protocol     string `gorm:"column:protocol"`
	ExprID       uint32 `gorm:"column:expr_id"`
	AttackNumber uint64 `gorm:"column:attack_number"`
}

func (WafService) TableName() string {
	return "ivan_waf_services"
}

type IntSlice []uint32

func (sl *IntSlice) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &sl)
}
func (sl IntSlice) Value() (driver.Value, error) {
	data, err := json.Marshal(sl)
	return data, err
}

type MatcherExpr struct {
	TableBase
	Name   string   `gorm:"column:name"`
	Scope  IntSlice `gorm:"column:scope"`
	Mode   string   `gorm:"column:mode"`
	Expr   string   `gorm:"column:expr"`
	Global bool     `gorm:"column:global"`
}

func (MatcherExpr) TableName() string {
	return "ivan_waf_blackwhitelists"
}

type WafCert struct {
	TableBase
	Key       string `gorm:"column:file_key"`
	Content   []byte `gorm:"column:content"`
	ServiceID int32  `gorm:"column:service_id"`
}

func (WafCert) TableName() string {
	return "ivan_waf_credentials"
}

type Rule struct {
	ID          int    `json:"id"`
	Level       int    `json:"level"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Expr        string `json:"expr"`
	Mode        string `json:"mode"`
}

type Langs struct {
	EN string `json:"en"`
	ZH string `json:"zh"`
}

type RuleGroup struct {
	ID            string `gorm:"column:id"`
	CategoryID    string `gorm:"column:category_id"`
	CategoryEN    string `gorm:"column:category_en"`
	CategoryZH    string `gorm:"column:category_zh"`
	DescriptionEN string `gorm:"column:description_en"`
	DescriptionZH string `gorm:"column:description_zh"`
	Status        int    `gorm:"column:status"`
}

func (RuleGroup) TableName() string {
	return "ivan_waf_rule_groups"
}

type AttackLogDetail struct {
	Id             string `json:"id,omitempty"`
	RuleId         int64  `json:"rule_id"`
	Action         string `json:"action"`
	RuleName       string `json:"rule_name"`
	AttackIp       string `json:"attack_ip,omitempty"`
	AttackType     string `json:"attack_type"`
	AttackedApp    string `json:"attacked_app"`
	AttackedUrl    string `json:"attacked_url"`
	AttackLoad     string `json:"attack_load"`
	AttackTime     int64  `json:"attack_time"`
	ReqPkg         string `json:"req_pkg,omitempty"`
	RspPkg         string `json:"rsp_pkg,omitempty"`
	RspContentType string `json:"rsp_content_type,omitempty"`
}

type WafAttackLogs struct {
	ClusterKey  string            `json:"cluster_key"`
	Namespace   string            `json:"namespace"`
	ResKind     string            `json:"res_kind"`
	ResName     string            `json:"res_name"`
	ServiceId   int64             `json:"service_id"`
	AppName     string            `json:"app_name"`
	AttackedLog []AttackLogDetail `json:"attacked_log"`
}
