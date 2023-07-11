package imagesec

import (
	"encoding/json"
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 扫描所用的 DB 信息
type ScanDbMeta struct {
	ID        int64  `gorm:"primaryKey" json:"id"`
	UniqueID  uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	DBType    string `gorm:"column:db_type" json:"dBType"`
	DBVersion string `gorm:"column:db_version" json:"dBVersion"`
	Enable    bool   `gorm:"column:enable" json:"enable"` // 是否启用
	MetaJson  string `gorm:"column:meta" json:"-"`
	DBMeta    DBMeta `json:"-" json:"dBMeta"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

type DBMeta struct {
	DBVersion     string `json:"dBVersion"` // 上传时的毫秒时间戳
	DBComment     string `json:"dbComment"`
	DBHash        string `json:"dbBHash"`
	EngineHash    string `json:"engineHash"`
	EngineVersion string `json:"engineVersion"`
	EngineComment string `json:"engineComment"`
	Enable        bool   `json:"enable"` // 是否启用
	Updater       string `json:"updater"`
	Filename      string `json:"filename"` // zip包的绝对路径位置
}

type DBVersion struct {
	Version  string `json:"version"`
	Comment  string `json:"comment"`
	Hash     string `json:"hash"`
	UpdateAt int64  `json:"updateAt"`
}

func (vi *ScanDbMeta) Same(after *ScanDbMeta) bool {
	if vi.UniqueID != after.UniqueID || vi.MetaJson != after.MetaJson {
		return false
	}
	return true
}

func (vi *ScanDbMeta) Serialize() {
	vi.DBVersion = vi.DBMeta.DBVersion

	if bys, err := json.Marshal(vi.DBMeta); err != nil {
		vi.MetaJson = string(bys)
	}

	vi.UniqueID = vi.GenUniqueID()
}

func (vi *ScanDbMeta) Deserialize() {
	if vi.MetaJson != "" {
		m := DBMeta{}
		if err := json.Unmarshal([]byte(vi.MetaJson), &m); err == nil {
			vi.DBMeta = m
		}
	}
}

func (vi *ScanDbMeta) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.DBMeta.EngineVersion == "" {
		return fmt.Errorf("not get EngineVersion")
	}
	if vi.DBVersion == "" || vi.DBMeta.DBVersion == "" {
		return fmt.Errorf("not get ScanDbMeta")
	}
	if vi.UniqueID <= 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
	if vi.UniqueID <= 0 {
		return fmt.Errorf("not get uniqueID")
	}
	return nil
}

func (vi *ScanDbMeta) GenUniqueID() uint64 {
	key := fmt.Sprintf("%s-%s", vi.DBType, vi.DBVersion)
	return util.GenerateUUID64(key)
}

func (vi *ScanDbMeta) TableName() string {
	return "ivan_scan_db_meta"
}

type SearchScanDbMetaParam struct {
	DBType    string
	DBVersion string
	Enable    string
	Keyword   string
	ID        int64
	UniqueID  uint64
	Filter    *model.Filter
}
