package model

import (
	"errors"
	"strings"
	"time"
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
	return "attck_rule_datas"
}

type ATTCKRuleMask struct {
	ID   uint32 `gorm:"primaryKey;autoIncrement;column:id"`
	Name string `gorm:"index:attck_rule_masks_name;column:name"`
}

func (ATTCKRuleMask) TableName() string {
	return "attck_rule_masks"
}

type ATTCKRuleMaskVersion struct {
	Version uint32 `gorm:"column:version"`
}

func (ATTCKRuleMaskVersion) TableName() string {
	return "attck_rule_mask_version"
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
	Rule       string         `yaml:"rule"`
	Hthreats   uint8          `yaml:"hthreats"`
	HID        uint16         `yaml:"hid"`
	Priority   string         `yaml:"priority"`
	Desc       string         `yaml:"desc"`
	Output     string         `yaml:"output"`
	Suggestion map[string]*KV `yaml:"suggestion"`
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

func GetInfoFromOutput(k, output string) (string, error) {
	retStr := ""
	resultList := strings.Split(output, k)
	if len(resultList) < 2 {
		return "", errors.New("can't find key")
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
	case "Privilege Escalation":
		return "权限提升"
	case "Persistence":
		return "后门维持"
	case "Discovery":
		return "内网信息探测"
	case "Credential Access":
		return "凭证获取"
	case "Defense Evasion":
		return "检测避免"
	case "Exfiltration":
		return "数据泄漏"
	case "Lateral Movement":
		return "横向移动"
	}
	return retStr
}
