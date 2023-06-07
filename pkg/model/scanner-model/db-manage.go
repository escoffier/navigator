package scannermodel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/mq"
)

type SubScannerToMainSql struct {
	DalName string `json:"dalName"` // 不指定将会使用default分支，详见subscanner-log.go
	Action  string `json:"action"`  // 需要在对应dal中实现
	Data    []byte `json:"data"`    // struct marshal
	Params  string `json:"params"`  // if need something condition
}

const (
	SubSqlUpdate           = "update"
	SubSqlCreate           = "create"
	MainScannerObject      = "mainScanner"
	SubScannerObject       = "subScanner"
	DaemonObject           = "daemon"
	SubScannerKafkaTopic   = "ivan_scanner_subscanner"
	SubScannerKafkaGroupID = "ivan_subscanner_scanner"
	VulnType               = "vuln"
)

const (
	TrivyDB  = "trivy"
	CustomDB = "custom"
	ClamavDB = "clamav"
	AviraDB  = "avira"
)

const (
	VulnDir              = "/trivy"
	MaliciousDir         = "malicious"
	VulnVersionPath      = VulnDir + "/version"
	MaliciousVersionPath = MaliciousDir + "/version"
	ClamavVersionPath    = ClamavDBPath + "/version"
	AviraVersionPath     = AviraDBPath + "/version"
	TrivyDBPath          = VulnDir + "/trivy.db"
	CustomDBPath         = VulnDir + "/custom.db"
	ClamavDBPath         = MaliciousDir + "/clamav"
	AviraDBPath          = MaliciousDir + "/avira"

	DefaultDBName    = "default db name"
	DownVulnZip      = "DownVuln.zip"
	PushVulnZip      = "VulnDB.zip"
	DownMaliciousZip = "DownMalicious.zip"
	PushMaliciousZip = "MaliciousDB.zip"
	UnzipPath        = "offline/"
)

type DBMateData struct {
	Version string `json:"version"`
	Comment string `json:"comment"`
	Hash    string `json:"hash"`
}

func (d *DBMateData) GetUUID() uint64 {
	return util.GenerateUUID64(fmt.Sprintf("%s-%s-%s", d.Version, d.Comment, d.Hash))
}

type MaliciousDBVersion struct {
	Clamav ClamavDBVersion `json:"clamavVersion"`
	Avira  AviraDBVersion  `json:"AviraVersion"`
}

type ClamavDBVersion struct {
	ComPressDBVersion string     `json:"compressDBVersion"`
	ClamavVersion     DBMateData `json:"clamavVersion"`
	UpdateTime        int64      `gorm:"autoUpdateTime:milli;column:update_time" json:"updateTime"`
}

func (cdv *ClamavDBVersion) GetVersion() int64 {
	var nowTime time.Time
	var err error
	nowTime, err = time.Parse("200601021504", cdv.ClamavVersion.Version)
	if err != nil {
		logging.GetLogger().Warn().Msgf("parse time %v error %v", cdv.ClamavVersion.Version)
	}
	return nowTime.UnixMilli()
}

type AviraDBVersion struct {
	ComPressDBVersion string     `json:"compressDBVersion"`
	AvriaVersion      DBMateData `json:"AviraVersion"`
	UpdateTime        int64      `gorm:"autoUpdateTime:milli;column:update_time" json:"updateTime"`
}

type VulnDBVersion struct {
	ComPressDBVersion string     `json:"compressDBVersion"`
	TrivyVersion      DBMateData `json:"trivyVersion"`
	CustomDBVersion   DBMateData `json:"customDBVersion"`
	UpdateTime        int64      `gorm:"autoUpdateTime:milli;column:update_time" json:"updateTime"`
}

func (vdv *VulnDBVersion) GetVersion(objType string) int64 {
	var nowTime time.Time
	var err error
	if objType == TrivyDB {
		nowTime, err = time.Parse("200601021504", vdv.TrivyVersion.Version)
		if err != nil {
			logging.GetLogger().Warn().Msgf("parse time %v error %v", vdv.TrivyVersion.Version, err)
		}
	} else {
		nowTime, err = time.Parse("200601021504", vdv.CustomDBVersion.Version)
		if err != nil {
			logging.GetLogger().Warn().Msgf("parse time %v error %v", vdv.CustomDBVersion.Version, err)
		}
	}
	return nowTime.UnixMilli()
}

func (vdv *VulnDBVersion) Same(version VulnDBVersion) bool {
	if vdv.GetVersion(TrivyDB) == version.GetVersion(TrivyDB) && vdv.GetVersion(CustomDB) == version.GetVersion(CustomDB) {
		return true
	}
	return false
}

type ScannerDBVersion struct {
	VulnVersion      VulnDBVersion      `json:"vulnVersion"`
	MaliciousVersion MaliciousDBVersion `json:"maliciousVersion"`
}

func (v *ClamavDBVersion) CompareVersion(nowVer MaliciousDBVersion) bool {

	if v.ClamavVersion.Version < nowVer.Clamav.ClamavVersion.Version {
		return true
	}

	return false
}

func (v *AviraDBVersion) CompareVersion(nowVer MaliciousDBVersion) bool {
	if v.AvriaVersion.Version < nowVer.Avira.AvriaVersion.Version {
		return true
	}
	return false
}

func (v *VulnDBVersion) CompareVersion(nowVer VulnDBVersion) bool {
	if v.GetVersion(TrivyDB) < nowVer.GetVersion(TrivyDB) || v.GetVersion(CustomDB) < nowVer.GetVersion(CustomDB) {
		return true
	}
	return false
}

type UpdateResult struct {
	DBPath string
	Result chan bool
}

func ReadMaliciousDBVersion(versionPath string, objType string) (MaliciousDBVersion, error) {
	resByte, err := os.ReadFile(versionPath)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("read version file error %v", versionPath)
		return MaliciousDBVersion{}, err
	}
	res := MaliciousDBVersion{}
	if objType == ClamavDB {
		err = json.Unmarshal(resByte, &res.Clamav)
	} else if objType == AviraDB {
		err = json.Unmarshal(resByte, &res.Avira)
	}
	if err != nil {
		logging.GetLogger().Err(err).Msgf("Unmarshal version file error %v", versionPath)
		return MaliciousDBVersion{}, err
	}
	return res, nil
}

func ReadVulnDBVersion(versionPath string) (VulnDBVersion, error) {
	resByte, err := os.ReadFile(versionPath)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("read version file error %v", versionPath)
		return VulnDBVersion{}, err
	}
	res := VulnDBVersion{}
	err = json.Unmarshal(resByte, &res)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("Unmarshal version file error %v", versionPath)
		return VulnDBVersion{}, err
	}
	return res, nil
}

type ScanDBVersion struct {
	ID              int64           `gorm:"primaryKey" json:"id"`
	CreatedAt       int64           `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt       int64           `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
	KeyPath         string          `gorm:"column:key_path;type:varchar(255)" json:"keyPath"`        // if daemon or subscanner clusterkey-hostname streamNodeKey
	VulnDBVersion   VulnDBVersion   `gorm:"column:vuln_db_version;type:text;serializer:json" json:"vulnDBVersion"`
	ClamavDBVersion ClamavDBVersion `gorm:"column:clamav_db_version;type:text;serializer:json" json:"clamavDBVersion"`
	AviraDBVersion  AviraDBVersion  `gorm:"column:avira_db_version;type:text;serializer:json" json:"aviraDBVersion"`
	ObjectType      string          `gorm:"column:object_type;type:varchar(255)" json:"objectType"`
}

func (s *ScanDBVersion) TableName() string {
	return "ivan_scanner_scan_db_version"
}

func SubScannerSendToKafka(wr mq.Writer, data SubScannerToMainSql) error {
	logging.GetLogger().Info().Msgf("data will send to kafka")
	msg, err := json.Marshal(data)
	if err != nil {
		logging.GetLogger().Err(err).Msg("marshal data error when send kafka")
		return err
	}
	err = wr.Write(context.Background(), SubScannerKafkaTopic, kafka.Message{
		Topic: SubScannerKafkaTopic,
		Key:   []byte("support subscanner sql"),
		Value: msg,
	})
	if err != nil {
		logging.GetLogger().Err(err).Msg("send to kakfa error")
		return err
	}
	return nil
}

type ScanDbMateData struct {
	ID        int64      `gorm:"primaryKey" json:"id"`
	CreatedAt int64      `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64      `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
	UUID      uint64     `gorm:"column:uuid;type:bigint" json:"uuid"`                     // if daemon or subscanner clusterkey-hostname
	DBMata    DBMateData `gorm:"column:db_mata;type:text;serializer:json" json:"dbMata"`
	DBType    string     `gorm:"column:db_type;type:varchar(255)" json:"dbType"`
}

func (sdm *ScanDbMateData) GetUUID() uint64 {
	return util.GenerateUUID64(fmt.Sprintf("%v-%v", sdm.DBMata.GetUUID(), sdm.DBType))
}

func (ScanDbMateData) TableName() string {
	return "ivan_scanner_scan_db_mate"
}

type ScanDBUpdateHistroy struct {
	ID                int64  `gorm:"primaryKey" json:"id"`
	CreatedAt         int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt         int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
	UUID              uint64 `gorm:"column:uuid" json:"uuid"`
	DBType            string `gorm:"column:db_type" json:"dbType"`
	ComPressDBVersion string `gorm:"column:compress_db_version;type:varchar(255)" json:"compressDBVersion"`
	Updater           string `gorm:"column:updater;type:varchar(255)" json:"updater"`
	Result            string `gorm:"column:result;type:text" json:"result"`
}

func (sdh *ScanDBUpdateHistroy) GetUUID() uint64 {
	return util.GenerateUUID64(fmt.Sprintf("%v-%v-%v", sdh.ComPressDBVersion, sdh.DBType, time.Now()))
}

func (ScanDBUpdateHistroy) TableName() string {
	return "ivan_scanner_scan_db_history"
}

type VersionResp struct {
	CompressVersion string `json:"version"`
	UpdateTime      int64  `json:"updateTime"`
	DBType          string `json:"dbType"`
}

type HistoryResp struct {
	CompressVersion string `json:"version"`
	UpdateTime      int64  `json:"updateTime"`
	DBType          string `json:"dbType"`
	Updater         string `json:"updater"`
}
