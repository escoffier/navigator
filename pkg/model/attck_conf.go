package model

import "time"

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
	Enabled     bool              `json:"enabled"`
	Adapter     map[string]string `json:"adapter"`
}

type LatestATTCKRuleInfo struct {
	DataChanged          bool     `json:"dataChanged"`
	LatestDataVersion    uint32   `json:"latestDataVersion"`
	SettingChanged       bool     `json:"settingChanged"`
	LatestSettingVersion uint32   `json:"latestSettingVersion"`
	Data                 string   `json:"data"`
	ClosedRules          []string `json:"closedRules"`
}
