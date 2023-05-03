package model

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"time"

	json "github.com/json-iterator/go"
)

type MessageEventType string

const (
	FieldProcessPid        = "proc.pid"
	FieldProcessName       = "proc.name"
	FieldParentProcessPid  = "proc.ppid"
	FieldCmdline           = "proc.cmdline"
	FieldParentProcessName = "proc.pname"
	FieldK8sNsName         = "k8s.ns.name"
	FieldPodUID            = "k8s.pod.id"
	FieldK8sPodName        = "k8s.pod.name"
	FieldContainerID       = "container.id"
	FieldEvtTime           = "evt.time"
	FieldEvtType           = "evt.type"
	FieldEvtCategory       = "evt.category"
	FieldSyscallType       = "syscall.type"
	FieldEvtArgName        = "evt.arg.name"
	FieldEvtArgOldPath     = "evt.arg.oldpath"
	FieldEvtArgPath        = "evt.arg.path"
	FieldPorcCmd           = "proc.cmdline"
	FieldPorcLoginShellID  = "proc.loginshellid"
	FieldProcFDC           = "proc.fdopencount"
	FieldProcTerm          = "proc.tty"
	FieldUserName          = "user.name"
	FieldUserLoginUID      = "user.loginuid"
	FieldImageRepo         = "container.image.repository"
	FieldImageTag          = "container.image.tag"
	FieldContainerName     = "container.name"
	FieldContainerType     = "container.type"
	FieldContainerPriv     = "container.privileged"
	FieldImageDigest       = "container.image.digest"
	FieldFDName            = "fd.name"
	FieldFDType            = "fd.type"

	MHeaderKeyEventType                  = "etype"
	MEventTypeHolmes    MessageEventType = "hd" // holmes runtime detection
	MEventTypeDrift     MessageEventType = "dp" // drift prevention
)

type ATTCKRuleData struct {
	ID               uint64 `gorm:"primaryKey;autoIncrement;column:id"`
	Content          []byte `gorm:"column:content"`
	CconfigIDversion uint64 `gorm:"column:cconfig_idversion"`
	ATTCKConfVersion
}

type ATTCKConfVersion struct {
	Version1  uint16    `gorm:"column:version1"`
	Version2  uint16    `gorm:"column:version2"`
	Username  string    `gorm:"column:username"`
	CreatedAt time.Time `gorm:"index:attck_rule_data_created_at_key;column:created_at"`
}

func (v ATTCKConfVersion) VString() string {
	return fmt.Sprintf("v%d.%d", v.Version1, v.Version2)
}

func (ATTCKRuleData) TableName() string {
	// TODO FIXME
	return "ivan_platform_attck_rule_datas"
}

type ATTCKRuleMask struct {
	Version1 uint16 `gorm:"column:version1"`
	ID       uint32 `gorm:"primaryKey;autoIncrement;column:id"`
	Name     string `gorm:"index:attck_rule_masks_name;column:name"`
}

func (ATTCKRuleMask) TableName() string {
	return "ivan_platform_attck_rule_masks"
}

type ATTCKRuleMaskVersion struct {
	Version1 string `gorm:"column:version1"`
	Version  uint64 `gorm:"column:version"`
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
	DataChanged          bool     `json:"dataChanged"`
	LatestDataVersion    int64    `json:"latestDataVersion"`
	SettingChanged       bool     `json:"settingChanged"`
	LatestSettingVersion int64    `json:"latestSettingVersion"`
	Data                 string   `json:"data"`
	ClosedRules          []string `json:"closedRules"`
}

type RuleFromYaml struct {
	Rule                  string         `yaml:"rule,omitempty"`
	Hthreats              uint8          `yaml:"hthreats,omitempty"`
	HID                   string         `yaml:"hid,omitempty"`
	Priority              string         `yaml:"priority,omitempty"`
	Desc                  string         `yaml:"desc,omitempty"`
	Output                string         `yaml:"output,omitempty"`
	Condition             string         `yaml:"condition"`
	Suggestion            map[string]*KV `yaml:"suggestion,omitempty"`
	Category              string         `yaml:"category,omitempty"`
	CategoryZh            string         `yaml:"categoryZh,omitempty"`
	Tags                  []string       `yaml:"tags,omitempty"`
	EnabledPtr            *bool          `yaml:"enabled,omitempty"` // the default value is true, so set it to a pointer
	Macro                 string         `yaml:"macro,omitempty"`
	List                  string         `yaml:"list,omitempty"`
	Items                 []string       `yaml:"items"`
	RequiredEngineVersion int            `yaml:"required_engine_version,omitempty"`
	Source                string         `yaml:"source,omitempty"`

	Mozart      []ConfigMozart      `yaml:"mozart,omitempty"`
	MozartMarco []ConfigMozartMarco `yaml:"mozart_marco,omitempty"`
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
		return 0
	case "ALERT":
		return 1
	case "CRITICAL":
		return 2
	case "ERROR":
		return 3
	case "WARNING":
		return 4
	case "NOTICE":
		return 5
	case "INFO":
		return 6
	case "DEBUG":
		return 7
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
	if strings.Count(retStr, "(") != strings.Count(retStr, ")") {
		resultList = strings.Split(retStr, ")")
		retStr = resultList[0]
	}
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

func TranslateENRuleType(in string) string {
	retStr := in
	switch in {
	case "Execution":
		return "Execution"
	case "Privilege_Escalation":
		return "Privilege Escalation"
	case "Persistence":
		return "Persistence"
	case "Discovery":
		return "Discovery"
	case "Credential_Access":
		return "Credential Access"
	case "Defense_Evasion":
		return "Defense Evasion"
	case "Exfiltration":
		return "Exfiltration"
	case "Lateral_Movement":
		return "Lateral Movement"
	}
	return retStr
}

type CconfigStatus int

const (
	StatusOK      CconfigStatus = 0
	StatusDeleted CconfigStatus = -1
	StatusPending CconfigStatus = 1
	StatusExpired CconfigStatus = 2
)

type AttckCustomConfig struct {
	ID           uint64        `gorm:"column:id"`
	RuleKey      string        `gorm:"column:rule_key"`
	RuleCategory string        `gorm:"column:rule_category"`
	CconfigKey   string        `gorm:"column:cconfig_key"`
	CconfigValue string        `gorm:"column:cconfig_value"`
	Creator      string        `gorm:"column:creator"`
	CreatedAt    int64         `gorm:"column:created_at"`
	Updater      string        `gorm:"column:updater"`
	UpdatedAt    int64         `gorm:"column:updated_at"`
	Status       CconfigStatus `gorm:"column:status"` // status: 0 status: -1 deleted status: 1 pending
}

func (r AttckCustomConfig) TableName() string {
	return "ivan_platform_attck_custom_configs"
}

type HolaJSON map[string]string

func (ev *HolaJSON) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return TypeAssertErr
	}
	return json.Unmarshal(b, &ev)
}
func (ev HolaJSON) Value() (driver.Value, error) {
	return json.Marshal(ev)
}
