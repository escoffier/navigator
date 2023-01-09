package scannermodel

import (
	"fmt"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	WebshellKafkaTopic   = "ivan_scanner_webshell"
	WebshellKafkaGroupID = "ivan_scanner_webshell_scanner"
	WebshellSize         = (1 << 20) * 10
)

var LevelToString = map[int]string{
	1: "maybe",
	2: "certainly",
}

type Webshell struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	CreatedAt     int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"`
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"`
	LayerDigest   string `gorm:"column:layer_digest;type:varchar(255)" json:"layerDigest"`
	FileMd5       string `gorm:"column:file_md5;type:varchar(255)" json:"fileMd5"`
	FileName      string `gorm:"column:file_name;type:varchar(255)" json:"fileName"`
	FileType      string `gorm:"column:file_type;type:varchar(64)" json:"fileType"`
	FileMode      string `gorm:"column:file_mode;type:varchar(64)" json:"fileMode"`
	FileSize      int    `gorm:"column:file_size" json:"fileSize"`
	FileModtime   int64  `gorm:"column:file_modtime" json:"fileModtime"`
	Description   string `gorm:"column:description;type:varchar(255)" json:"description"`
	Level         string `gorm:"column:level;type:varchar(64)" json:"level"`
	UniqueID      uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	MaliciousData string `gorm:"column:malicious_data" json:"maliciousData"`
}

func (w *Webshell) GenUniqueVuln() uint64 {
	key := fmt.Sprintf(consts.UniqueWebshellFamat, w.FileMd5, w.LayerDigest, w.FileName)
	uid := util.GenerateUUID64(key)
	if uid == 0 {
		logging.GetLogger().Warn().Msgf("UID IS 0 KEY:%s", key)
	}
	return uid
}

func (Webshell) TableName() string {
	return "ivan_scanner_webshell"
}

type TblB struct {
	ID            int64  `json:"id" gorm:"column:id"`
	Size          int64  `json:"size" gorm:"column:size"`
	FilePath      string `json:"filePath" gorm:"column:filePath;type:text"`
	Md5Hash       string `json:"md5Hash" gorm:"column:md5hash;type:text"`
	Description   string `json:"description" gorm:"column:description;type:text"`
	MaliciousData string `json:"maliciousData" gorm:"malicous_data;type:text"`
}

func (TblB) TableName() string {
	return "tbl_b"
}

type TblS struct {
	ID            int64  `json:"id" gorm:"column:id"`
	Size          int64  `json:"size" gorm:"column:size"`
	FilePath      string `json:"filePath" gorm:"column:filePath;type:text"`
	Md5Hash       string `json:"md5Hash" gorm:"column:md5hash;type:text"`
	Description   string `json:"description" gorm:"column:description;type:text"`
	MaliciousData string `json:"maliciousData" gorm:"malicous_data;type:text"`
}

type WebshellMalicous struct {
	Name   string `json:"name"`
	Offset int64  `json:"offset"`
	Data   string `json:"data"`
	LineNo int64  `json:"line_no"`
}

type WebshellFileInfo struct {
	FileName      string
	Size          int64
	Mode          string
	LayerDigest   string
	Level         int
	Md5Hash       string
	ModeTime      int64
	Description   string
	MaliciousData string
	Ext           string
	FilePath      string
	UID           int64
	GID           int64
	UName         string
	GName         string
}

type WebshellMd5AndLayer struct {
	Md5Hash     string `json:"md5"`
	LayerDigest string `json:"layerDigest"`
}

type WebshellResult struct {
	FileInfos []WebshellFileInfo
}

type WebshellSaveInfo struct {
	FileMd5 string `json:"fileMd5"`
	Data    []byte `json:"data"`
}

func (w *WebshellFileInfo) TransToWebshell() Webshell {
	res := Webshell{}
	res.LayerDigest = w.LayerDigest
	res.Description = w.Description
	res.FileMd5 = w.Md5Hash
	res.FileMode = fmt.Sprintf("%v(用户名:%v 用户组名:%v)", w.Mode, w.UName, w.GName)
	res.FileModtime = w.ModeTime
	res.FileName = w.FileName
	res.FileSize = int(w.Size)
	res.Level = LevelToString[w.Level]
	res.FileType = w.Ext
	res.MaliciousData = w.MaliciousData
	return res
}

type WebshellList struct {
	FileNmae string `json:"fileName"`
	FilePath string `json:"filePath"`
	Level    string `json:"level"`
	Download int    `json:"download"`
	FileMd5  string `json:"fileMd5"`
	Tip      string `json:"tip"`
	UUID     uint64 `json:"uuid,string"`
}

type WebshellDetail struct {
	FilePath   string          `json:"filePath"`
	Ext        string          `json:"ext"`
	FileMode   string          `json:"fileMode"`
	FileSize   int             `json:"fileSize"`
	LastModify int64           `json:"lastModify"`
	Detail     string          `json:"detail"`
	Suggestion string          `json:"suggestion"`
	Code       []WebshellCode  `json:"code"`
	Images     []WebshellImage `json:"images"`
}

type WebshellImage struct {
	Image    string `json:"name"`
	Registry string `json:"registry"`
}
type WebshellCode struct {
	Offset int64  `json:"offset"`
	Data   []byte `json:"data"`
}

type BeforeDecode struct {
	Name   string `json:"name"`
	Offset int64  `json:"offset"`
	Data   string `json:"data"`
}

type ProblemCode struct {
	Data    []byte
	Problem []string
}

type IDMap struct {
	UIDMap map[int64]string
	GIDMap map[int64]string
}
