package imagesec

import (
	"encoding/json"
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 扫描所用的 DB 信息
type ScanConfigDB struct {
	ID        int64  `gorm:"primaryKey" json:"id"`
	UniqueID  uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	DBVersion string `gorm:"db_version" json:"dbVersion"`
	DBType    string `gorm:"column:db_type" json:"dBType"`
	DBMd5     string `gorm:"column:db_md5" json:"dBMd5"`
	MetaJson  string `gorm:"column:meta" json:"-"`
	DBMeta    DBMeta `gorm:"-" json:"dBMeta"`
	Updater   string ` gorm:"column:updater" json:"updater"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

type DBMeta struct {
	DBVersion string `json:"dBVersion"` // 上传时的毫秒时间戳
	DBComment string `json:"dbComment"`
	DBHash    string `json:"dbBHash"`
}

type DBVersion struct {
	Version       string     `json:"version"`
	Comment       string     `json:"comment"`
	Hash          string     `json:"hash"`
	UpdateAt      int64      `json:"updateAt"`
	DBVersion     string     `json:"dBVersion"` // 上传时的毫秒时间戳
	DBComment     string     `json:"dbComment"`
	DBHash        string     `json:"dbBHash"`
	EngineHash    string     `json:"engineHash"`
	EngineVersion string     `json:"engineVersion"`
	EngineComment string     `json:"engineComment"`
	Enable        bool       `json:"enable"` // 是否启用
	Updater       string     `json:"updater"`
	DBPathInfo    DBPathInfo `json:"dBPathInfo"`
}

// 路径信息做统一规整
type DBPathInfo struct {
	WorkVersionFilename   string `json:"workVersionFile"`   // 正在使用的文件中version文件的绝对路径文件名,由这个文件解析出版本号
	UpdateVersionFilename string `json:"updateVersionFile"` // 上传文件中version文件的绝对路径文件名
	WorkPath              string `json:"workPath"`          // 执行执行所加载的二进制文件目录
	BinFilename           string `json:"binFile"`           // 二制进执行文件名
	WorkConfFilename      string `json:"savApiConfFile"`    // 配置文件名
	UpdatePath            string `json:"updatePath"`        // 上传文件所保存的目录
	UpdateZipFilename     string `json:"updateZipFile"`     // 上传zip文件的绝对路径文件名
	UpdateUnZipPath       string `json:"updateUnZipPath"`   // 上传文件的解压路径
}

func (vi *DBPathInfo) DeepCopy() DBPathInfo {
	pa := DBPathInfo{
		WorkVersionFilename:   vi.WorkVersionFilename,
		UpdateVersionFilename: vi.UpdateVersionFilename,
		WorkPath:              vi.WorkPath,
		BinFilename:           vi.BinFilename,
		WorkConfFilename:      vi.WorkConfFilename,
		UpdatePath:            vi.UpdatePath,
		UpdateZipFilename:     vi.UpdateZipFilename,
		UpdateUnZipPath:       vi.UpdateUnZipPath,
	}
	return pa
}

// 版本信息，和scanner 一起调整，统一结构
type DBVersionInfo struct {
	RootPath string `json:"rootPath"`
	DBType   string `json:"dBType"`
	Version  string `json:"version"`
	UpdateAt int64  `json:"updateAt"`
	Comment  string `json:"comment"`
	Hash     string `json:"hash"`
}

func (vi *ScanConfigDB) Same(after *ScanConfigDB) bool {
	return false
}

func (vi *ScanConfigDB) Serialize() {
	// vi.DBVersion = vi.DBMeta.DBVersion

	if bys, err := json.Marshal(vi.DBMeta); err != nil {
		vi.MetaJson = string(bys)
	}
	vi.UniqueID = vi.GenUniqueID()
}

func (vi *ScanConfigDB) Deserialize() {
	if vi.MetaJson != "" {
		m := DBMeta{}
		if err := json.Unmarshal([]byte(vi.MetaJson), &m); err == nil {
			vi.DBMeta = m
		}
	}
}

func (vi *ScanConfigDB) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.DBVersion == "" {
		return fmt.Errorf("not get db version")
	}
	return nil
}

func (vi *ScanConfigDB) GenUniqueID() uint64 {
	key := fmt.Sprintf("%s-%s-%s", vi.DBType, vi.DBVersion, vi.DBMd5)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *ScanConfigDB) TableName() string {
	return "ivan_scan_db_config"
}

type SearchScanDbParam struct {
	DBType    string
	DBVersion string
	Keyword   string
	ID        int64
	UniqueID  uint64
	Filter    *Filter
}

type UpdateDbParam struct {
	Updater      string
	DbType       string
	Data         []byte `json:"-"`
	CheckVersion bool
	Path         string // 文件写入的最后层级，用于执行失败时的收尾工作
}

type LastDB struct {
	VulnDb     ScanConfigDB `json:"vulnDb"`
	AviraDB    ScanConfigDB `json:"aviraDB"`
	ClamavDB   ScanConfigDB `json:"clamavDB"`
	WebshellDB ScanConfigDB `json:"webshellDB"`
}
