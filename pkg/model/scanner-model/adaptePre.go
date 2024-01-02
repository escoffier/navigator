package scannermodel

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

type ScannerDBVersion struct {
	VulnVersion      VulnDBVersion      `json:"vulnVersion"`
	MaliciousVersion MaliciousDBVersion `json:"maliciousVersion"`
}
type MaliciousDBVersion struct {
	Clamav ClamavDBVersion `json:"clamavVersion"`
	Avira  AviraDBVersion  `json:"AviraVersion"`
}

type AviraDBVersion struct {
	ComPressDBVersion string     `json:"compressDBVersion"`
	AvriaVersion      DBMateData `json:"AviraVersion"`
	UpdateTime        int64      `gorm:"autoUpdateTime:milli;column:update_time" json:"updateTime"`
}

type ClamavDBVersion struct {
	ComPressDBVersion string     `json:"compressDBVersion"`
	ClamavVersion     DBMateData `json:"clamavVersion"`
	UpdateTime        int64      `gorm:"autoUpdateTime:milli;column:update_time" json:"updateTime"`
}

type VulnDBVersion struct {
	ComPressDBVersion string     `json:"compressDBVersion"`
	TrivyVersion      DBMateData `json:"trivyVersion"`
	CustomDBVersion   DBMateData `json:"customDBVersion"`
	UpdateTime        int64      `gorm:"autoUpdateTime:milli;column:update_time" json:"updateTime"`
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
