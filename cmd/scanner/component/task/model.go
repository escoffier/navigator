package task

import (
	"time"
)

type Task struct {
	ID         int64
	Scope      ScanScope
	ScanType   map[ScanType]ScanPolicy // scan type and policy
	Trigger    Trigger
	FlowConf   string // flow conf name
	Priority   int    // reserve,
	Status     int    // current status
	Result     int    // success,error
	Msg        string // error msg
	Comment    string // some comment about this task
	UpdateAt   time.Time
	StartedAt  *time.Time
	CreateAt   time.Time
	FinishedAt *time.Time
	HeartBeat  *time.Time
	Operator   string
	ScannerID  string
}

type ScanScope struct {
	Type     int // full-scan,partial-scan
	SubTasks []SubTask
}

type ScanConfig struct {
	Type   string
	Policy ScanPolicy
}

type ScanType string // vuln-scan,virus-scan,...

type ScanPolicy interface{} // scan policy correlated to scan type,eg: VulnPolicy,SensitiveFilePolicy

type SingleVulnPolicy struct {
	CustomPackageName    string `json:"name"`
	CustomPackageVersion string `json:"version"`
}

type VulnPolicy struct {
	Pkgs string
}

type LicensePolicy struct {
	LicenseName string
}

type SensitiveFilePolicy struct {
	CustomFileName string
}

type MaliciousPolicy struct {
}

type WebshellPolicy struct {
}

type EnvPolicy struct {
	EnvName string
}

type Trigger struct {
	Type int // trigger by cicd,vuln-data-updater,timer...
}

type SubTask struct {
	ID       int64
	TaskID   int64
	Image    ImageInfo
	Registry RegistryInfo
	Status   uint8 // ImageScanPending,ImageScanInprogress...
	Result   int   // success,error
	ErrMsg   string

	CreateAt   time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
	UpdatedAt  time.Time
	HeartBeat  *time.Time
}

type ImageInfo struct {
	ID         int64  // image id in db
	RepoName   string // library/redis
	Tag        string // 1.10
	Manifest   string // image manifest content
	ConfigJSON string // image config json content
}

type RegistryInfo struct {
	ID       int64  // registry id in db
	Host     string // http(s)://docker.io
	Secure   bool   // indicate registry which use self-signed certificates, or use an unencrypted HTTP connection
	Username string // username who will log registry
	Password string
}
