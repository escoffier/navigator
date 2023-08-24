package waf

import "gitlab.com/piccolo_su/vegeta/pkg/model"

// globlal config of waf
type WafOption struct {
	WasmUrl string
	// rule    []*Rule
}

type LogConfig struct {
	Enable int    `json:"attack_enable,omitempty"`
	Level  string `json:"level,omitempty"`
}

type WhiteBlackList struct {
	Name string
}

type RuleGroupResp struct {
	CategoryID  string       `json:"category_id"`
	Category    string       `json:"category"`
	Description string       `json:"description"`
	Rules       []model.Rule `json:"rules"`
	Status      int          `json:"status"`
}

type RuleGroup struct {
	CategoryID  string            `json:"category_id" yaml:"category_id"`
	Category    map[string]string `json:"category"`
	Description map[string]string `json:"description"`
	Rules       []model.Rule      `json:"rules"`
	Status      int               `json:"status"`
}

type AttackLogDetail struct {
	Id          string `json:"id,omitempty"`
	RuleId      int64  `json:"rule_id"`
	Action      string `json:"action"`
	RuleName    string `json:"rule_name"`
	AttackIp    string `json:"attack_ip,omitempty"`
	AttackType  string `json:"attack_type"`
	AttackedApp string `json:"attacked_app"`
	AttackedUrl string `json:"attacked_url"`
	AttackLoad  string `json:"attack_load"`
	AttackTime  int64  `json:"attack_time"`
	ReqPkg      string `json:"req_pkg,omitempty"`
	RspPkg      string `json:"rsp_pkg,omitempty"`
}

type AttackLog struct {
	Uuid         string `json:"uuid"`
	AttackIp     string `json:"attack_ip"`
	AttackedAddr string `json:"attacked_addr"`
	AttackType   string `json:"attack_type"`
	AttackTime   int64  `json:"attack_time"`
	AttackedApp  string `json:"attacked_app"`
	ClusterKey   string `json:"cluster_key"`
	Action       string `json:"action"`
}

type AttackLogFilter struct {
	Offset     int    `json:"offset"`
	Limit      int    `json:"limit"`
	ServiceId  int64  `json:"service_id"`
	Cluster    string `json:"cluster"`
	AttackUrl  string `json:"attack_url"`
	AttackIp   string `json:"attack_ip"`
	AttackType string `json:"attack_type"`
	AttackApp  string `json:"attack_app"`
	Action     string `json:"action"`
	Token      string `json:"token"`
	StartTime  int64  `json:"start_time"`
	EndTime    int64  `json:"end_time"`
}

type AttackClasses struct {
	Id         int    `json:"id"`
	En         string `json:"en,omitempty"`
	Describe   string `json:"describe"`
	AttackType string `json:"type"`
}

type AttackRspPkg struct {
	Uuid        string `json:"uuid"`
	Intact      bool   `json:"intact"`
	ContentType string `json:"content_type"`
	RspPkg      string `json:"rspPkg"`
}

type StringMatch struct {
	Prefix string `json:"prefix,omitempty"`
	Exact  string `json:"exact,omitempty"`
}

type WafConfig struct {
	ExcludedFileTypes []string `json:"excluded_file_type"`
	DetectHeaders     []string `json:"detect_headers"`
}

type Config struct {
	Mode             string
	Rules            []*model.Rule
	Log              LogConfig `json:"log,omitempty"`
	ExcludeFileTypes []string
	DetectHeaders    []string
	WhiteBlackList   []string
	Uri              StringMatch
	Hosts            []string
}

var DefAttackClass = []AttackClasses{{1, "Remote Command Execution", "远程代码执行", "RCE_OS"},
	{2, "SQL Injection", "SQL注入", "SQLI"},
	{3, "Cross-Site Scripting", "跨站脚本攻击", "XSS"},
	{4, "Access of Internal Components", "内部组件访问", "AOIC"},
	{5, "Directory Traversal", "路径穿越", "DT"},
	{6, "Data Leakage", "数据泄露", "DL"},
	{7, "Source Code Disclosure", "源码泄露", "SCD"},
	{8, "Php remote code execution", "PHP远程代码执行", "RCE_PHP"},
	{9, "Java remote code execution", "JAVA远程代码执行", "RCE_JAVA"},
	{10, "Local file include", "本地文件包含", "LFI"},
	{11, "Remote file include", "远程文件包含", "RFI"},
	{12, "Url Redirect", "URL重定向（CVE）", "UR"},
	{13, "DOS", "DOS攻击", "DOS"},
	{14, "Unauthorized File Upload", "未授权文件上传", "UFL"},
	{15, "General Rule", "一般文件规则", "GR"},
	{16, "Site Scanning/Probing", "网站扫描/探测", "SS"},
	{17, "Server-side request forgery", "跨站请求伪造", "SSRF"},
	{18, "Famous application vulnerable", "针对知名应用的针对性规则", "FAPPV"},
	{19, "Other", "其它", "Other"},
	{20, "black list", "黑名单", "black"},
	{21, "white list", "白名单", "white"},
	{22, "force white list", "强白名单", "force-white"}}
