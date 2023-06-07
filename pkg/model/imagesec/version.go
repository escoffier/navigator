package imagesec

import (
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 病毒引擎及病毒库元信息
type MalwareVersion struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 数据库的中唯一建，去重效率高
	EngineVersion string `gorm:"column:engine_version" json:"engineVersion"`
	EngineComment string `gorm:"column:engine_comment" json:"engineComment"`
	DBVersion     string `gorm:"column:db_version" json:"dBVersion"`
	DBComment     string `gorm:"column:db_comment" json:"dbBComment"`
	DBHash        string `gorm:"column:db_hash" json:"dbBHash"`
	Updater       string `gorm:"column:updater" json:"updater"`
	Enable        bool   `gorm:"column:enable" json:"enable"`                             // 是否启用
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *MalwareVersion) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.EngineVersion == "" {
		return fmt.Errorf("not get EngineVersion")
	}
	// if vi.DBVersion == "" {
	// 	return fmt.Errorf("not get DBVersion")
	// }
	if vi.UniqueID <= 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
	if vi.UniqueID <= 0 {
		return fmt.Errorf("not get uniqueID")
	}
	// if vi.Updater == "" {
	// 	return fmt.Errorf("not get Updater")
	// }
	return nil
}

func (vi *MalwareVersion) GenUniqueID() uint64 {
	key := fmt.Sprintf("%s-%s-%s", vi.EngineVersion, vi.DBVersion, vi.DBHash)
	return util.GenerateUUID64(key)
}

func (vi *MalwareVersion) TableName() string {
	return "ivan_scan_malware_version"
}

// 漏洞库元信息
type VulnVersion struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 数据库的中唯一建，去重效率高
	EngineVersion string `gorm:"column:engine_version" json:"engineVersion"`
	EngineComment string `gorm:"column:engine_comment" json:"engineComment"`
	DBVersion     string `gorm:"column:db_version" json:"DBVersion"`
	DBComment     string `gorm:"column:db_comment" json:"DBComment"`
	DBHash        string `gorm:"column:db_hash" json:"DBHash"`
	Updater       string `gorm:"column:updater" json:"updater"`
	Enable        bool   `gorm:"column:enable" json:"enable"`                             // 是否启用
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *VulnVersion) TableName() string {
	return "ivan_scan_vuln_version"
}

func (vi *VulnVersion) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.EngineVersion == "" {
		return fmt.Errorf("not get EngineVersion")
	}
	if vi.DBVersion == "" {
		return fmt.Errorf("not get DBVersion")
	}
	if vi.UniqueID <= 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
	if vi.UniqueID <= 0 {
		return fmt.Errorf("not get uniqueID")
	}
	if vi.Updater == "" {
		return fmt.Errorf("not get Updater")
	}
	return nil
}

func (vi *VulnVersion) GenUniqueID() uint64 {
	return 0
}

// Webshell引擎及Webshell规则元信息
type WebshellVersion struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 数据库的中唯一建，去重效率高
	EngineVersion string `gorm:"column:engine_version" json:"engineVersion"`
	EngineComment string `gorm:"column:engine_comment" json:"engineComment"`
	DBVersion     string `gorm:"column:db_version" json:"DBVersion"`
	DBComment     string `gorm:"column:db_comment" json:"DBComment"`
	EngineHash    string `gorm:"column:engine_hash" json:"engineHash"`
	DBHash        string `gorm:"column:db_hash" json:"DBHash"`
	Updater       string `gorm:"column:updater" json:"updater"`
	Enable        bool   `gorm:"column:enable" json:"enable"`                             // 是否启用
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *WebshellVersion) TableName() string {
	return "ivan_scan_webshell_version"
}

func (vi *WebshellVersion) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.EngineVersion == "" {
		return fmt.Errorf("not get EngineVersion")
	}
	// if vi.DBVersion == "" {
	// 	return fmt.Errorf("not get DBVersion")
	// }
	if vi.UniqueID <= 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
	if vi.UniqueID <= 0 {
		return fmt.Errorf("not get uniqueID")
	}
	// if vi.Updater == "" {
	// 	return fmt.Errorf("not get Updater")
	// }
	return nil
}

func (vi *WebshellVersion) GenUniqueID() uint64 {
	key := fmt.Sprintf("%s-%s-%s-%s", vi.EngineVersion, vi.DBVersion, vi.DBHash, vi.EngineHash)
	return util.GenerateUUID64(key)
}

// SensitiveFile引擎及SensitiveFile规则元信息
type SensitiveVersion struct {
	ID        int64    `gorm:"primaryKey" json:"id"`
	UniqueID  uint64   `gorm:"column:unique_id" json:"uniqueID,string"` // 数据库的中唯一建，去重效率高
	RulesJSON string   `gorm:"column:rules" json:"-"`
	Rules     []uint64 `gorm:"-" json:"rules"`
	RuleHash  string   `gorm:"column:rule_hash" json:"ruleHash"`
	Updater   string   `gorm:"column:updater" json:"updater"`
	Enable    bool     `gorm:"column:enable" json:"enable"`                             // 是否启用
	CreatedAt int64    `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64    `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *SensitiveVersion) TableName() string {
	return "ivan_scan_sensitive_version"
}

func (vi *SensitiveVersion) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.UniqueID <= 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
	if vi.UniqueID <= 0 {
		return fmt.Errorf("not get UniqueID")
	}
	if vi.Updater == "" {
		return fmt.Errorf("not get Updater")
	}
	return nil
}

func (vi *SensitiveVersion) GenUniqueID() uint64 {
	return 0
}
