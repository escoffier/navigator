package model

import (
	"errors"
	"strings"
	"time"
)

type MessageEventType string

const (
	MHeaderKeyEventType                  = "etype"
	MEventTypeHolmes    MessageEventType = "hd" // holmes runtime detection
	MEventTypeDrift     MessageEventType = "dp" // drift prevention
)

type ATTCKRuleData struct {
	ID      uint32 `gorm:"primaryKey;autoIncrement;column:id"`
	Content []byte `gorm:"column:content"`
	ATTCKConfVersion
}

type ATTCKConfVersion struct {
	Version   string    `gorm:"column:version"`
	Username  string    `gorm:"column:username"`
	CreatedAt time.Time `gorm:"index:attck_rule_data_created_at_key;column:created_at"`
}

func (ATTCKRuleData) TableName() string {
	return "ivan_platform_attck_rule_datas"
}

type ATTCKRuleMask struct {
	ID   uint32 `gorm:"primaryKey;autoIncrement;column:id"`
	Name string `gorm:"index:attck_rule_masks_name;column:name"`
}

func (ATTCKRuleMask) TableName() string {
	return "ivan_platform_attck_rule_masks"
}

type ATTCKRuleMaskVersion struct {
	Version uint32 `gorm:"column:version"`
}

func (ATTCKRuleMaskVersion) TableName() string {
	return "ivan_platform_attck_rule_mask_versions"
}

type ATTCKRuleSwitch struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type ATTCKRuleDisplay struct {
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Severity    uint8             `json:"severity"`
	Hthreats    uint8             `json:"hthreats"`
	Enabled     bool              `json:"enabled"`
	Adapter     map[string]string `json:"adapter"`
}

type LatestATTCKRuleInfo struct {
	DataChanged          bool            `json:"dataChanged"`
	LatestDataVersion    uint32          `json:"latestDataVersion"`
	SettingChanged       bool            `json:"settingChanged"`
	LatestSettingVersion uint32          `json:"latestSettingVersion"`
	Data                 string          `json:"data"`
	ClosedRules          []string        `json:"closedRules"`
	AttackRules          []*RuleFromYaml `json:"-"`
}

type RuleFromYaml struct {
	Rule                  string         `yaml:"rule,omitempty"`
	Hthreats              uint8          `yaml:"hthreats,omitempty"`
	HID                   string         `yaml:"hid,omitempty"`
	Priority              string         `yaml:"priority,omitempty"`
	Desc                  string         `yaml:"desc,omitempty"`
	Output                string         `yaml:"output,omitempty"`
	Condition             string         `yaml:"condition,omitempty"`
	Suggestion            map[string]*KV `yaml:"suggestion,omitempty"`
	Category              string         `yaml:"category,omitempty"`
	CategoryZh            string         `yaml:"categoryZh,omitempty"`
	Tags                  []string       `yaml:"tags,omitempty"`
	EnabledPtr            *bool          `yaml:"enabled,omitempty"` // the default value is true, so set it to a pointer
	Macro                 string         `yaml:"macro,omitempty"`
	List                  string         `yaml:"list,omitempty"`
	Items                 []string       `yaml:"items,omitempty"`
	RequiredEngineVersion int            `yaml:"required_engine_version,omitempty"`
}

func (r *RuleFromYaml) Enabled() bool {
	if r.EnabledPtr == nil {
		return true
	}
	return *r.EnabledPtr
}
func (r *RuleFromYaml) SetEnabled(e bool) {
	if e {
		r.EnabledPtr = nil
	} else {
		r.EnabledPtr = &e
	}
}

type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func Str2SeverityNum(s string) uint8 {
	retNum := uint8(0)
	switch s {
	case "EMERGENCY":
		return 10
	case "ALERT":
		return 9
	case "CRITICAL":
		return 8
	case "ERROR":
		return 7
	case "WARNING":
		return 6
	case "NOTICE":
		return 5
	case "INFO":
		return 2
	case "DEBUG":
		return 1
	}
	return retNum
}

var (
	ErrKeyNotFound = errors.New("key not found")
)

func GetInfoFromOutput(key, output string) (string, error) {
	if key == "" || output == "" {
		return "", ErrKeyNotFound
	}
	retStr := ""
	resultList := strings.Split(output, key)
	if len(resultList) < 2 {
		return "", ErrKeyNotFound
	}
	retStr = resultList[1]
	resultList = strings.Split(retStr, ",")
	retStr = resultList[0]
	resultList = strings.Split(retStr, ")")
	retStr = resultList[0]
	resultList = strings.Split(retStr, " ")
	retStr = resultList[0]
	return retStr, nil
}

func TranslateRuleType(in string) string {
	retStr := "其他"
	switch in {
	case "Execution":
		return "命令执行"
	case "Privilege_Escalation":
		return "权限提升"
	case "Persistence":
		return "后门维持"
	case "Discovery":
		return "内网信息探测"
	case "Credential_Access":
		return "凭证获取"
	case "Defense_Evasion":
		return "检测避免"
	case "Exfiltration":
		return "数据泄漏"
	case "Lateral_Movement":
		return "横向移动"
	}
	return retStr
}
