package apimodel

import (
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

type ImageLayerInfo struct {
	Digest        string   `json:"digest"`
	CreatedAt     int64    `json:"createdAt"`
	CreatedBy     string   `json:"createdBy"`
	Vulns         []string `json:"vulns"`
	Viruses       []string `json:"viruses"`
	SensitiveFile []string `json:"sensitiveFile"`
	WebshellInfo  []string `json:"webshell_info"`
	ImageID       int64    `json:"imageId"`
}

type SummaryEnv struct {
	EnvName    string `json:"envName"`
	EnvValue   string `json:"envValue"`
	IsAbnormal bool   `json:"isAbnormal"` // 标记是否异常
}

type Vuln struct {
	Name          string   `json:"name"`
	Severity      string   `json:"severity"`
	FixedVersion  string   `json:"fixedVersion"`
	Description   string   `json:"description"`
	FixSuggestion string   `json:"fixSuggestion"`
	References    []string `json:"references"`
	Title         string   `json:"title"`
	PkgName       string   `json:"pkgName"`
	PkgVersion    string   `json:"pkgVersion"`
	CVSS          Cvss     `json:"cvss"`
}

type ImageDetail struct {
	ID            int64                           `json:"id"`
	Digest        string                          `json:"digest"`
	FromType      string                          `json:"fromType"`
	Image         string                          `json:"image"`
	RegistryURL   string                          `json:"registryUrl"`
	SensitiveFile []string                        `json:"sensitiveFile"`
	Viruses       []model.VirusFileInfo           `json:"viruses"`
	Envs          []SummaryEnv                    `json:"envs"`
	Webshell      []scannermodel.Webshell         `json:"webshell"`
	NodeHostname  string                          `json:"nodeHostname"`
	NodeIP        string                          `json:"nodeIp"`
	Size          int                             `json:"size"`
	ImageAttr     imagesecModel.ImageAttrResponse `json:"imageAttr"`
}

type ImageListResponse struct {
	ID            int64   `json:"id"`
	LastScannedAt int64   `json:"lastScannedAt"`
	Digest        string  `json:"digest"`
	FromType      string  `json:"fromType"`
	HasFixedVuln  int64   `json:"hasFixedVuln"`
	ImageType     int64   `json:"imageType"`
	Reinforced    int64   `json:"reinforced"`
	NodeHostname  string  `json:"nodeHostname"`
	NodeIP        string  `json:"nodeIp"`
	Online        bool    `json:"online"`
	SecurityIssue []int   `json:"securityIssue"`
	RegistryName  string  `json:"registryName"`
	RegistryURL   string  `json:"registryUrl"`
	RiskScore     float64 `json:"riskScore"`
	ScanStatus    int     `json:"scanStatus"`
	Image         string  `json:"image"`
	Trusted       int64   `json:"trusted"`
}

type OverView struct {
	ImageTotal  int64    `json:"imageTotal"`
	OnlineTotal int64    `json:"onlineTotal"`
	Total       SafeOver `json:"total"`
	Online      SafeOver `json:"online"`
}

type SafeOver struct {
	Vulns                int64 `json:"vulns"`
	Viruses              int64 `json:"viruses"`
	SensitiveFile        int64 `json:"sensitiveFile"`
	Webshell             int64 `json:"webshell"`
	ExceptEnvs           int64 `json:"exceptEnvs"`
	NonCompliantSoftware int64 `json:"NonCompliantSoftware"`
	NotAllowedLicense    int64 `json:"notAllowedLicense"`
	PrivilegedBoot       int64 `json:"privilegedBoot"`
}

type ScanStrategy struct {
	ID            int64    `json:"id"`
	Name          string   `json:"name"` // 策略名唯一
	Description   string   `json:"description"`
	Operator      string   `json:"operator"`
	IsDefault     bool     `json:"isDefault"`
	SensitiveFile []string `json:"sensitiveFile"`
	ExceptEnvs    []string `json:"exceptEnvs"`

	NonComplianceSoftware []model.Software `json:"nonComplianceSoftware"`
	NotAllowedLicense     []string         `json:"notAllowedLicense"`
}

type SubTask struct {
	ID           int64      `json:"id"`
	TaskID       int64      `json:"task_id"`
	ImageID      int64      `json:"image_id"` // image id in db
	Result       uint8      `json:"result"`   // deprecated,1:failed, 2:success
	ErrMsg       string     `json:"err_msg"`
	ErrNo        int        `json:"err_no"`
	ErrMsgEnu    string     `json:"err_msg_enu"` // 错误信息的枚举值，用于前端展示
	CreatedAt    time.Time  `json:"created_at"`  // subtask create time
	StartedAt    *time.Time `json:"started_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	FinishedAt   *time.Time `json:"finished_at"`
	HeartBeat    *time.Time `json:"heart_beat"`
	RetryCount   int        `json:"retry_count"`
	Status       string     `json:"status"`         // 1:pending,2:inprogress,3:scan success,4:scan failed
	FullRepoName string     `json:"full_repo_name"` // eg:library/redis,may not use,could fetch by image list table
	Tag          string     `json:"tag"`            // eg:1.10, may not use
	Library      string     `json:"library"`        // registry name
}

type ImageSensitiveFile struct {
	ID           int64                      `json:"id"`
	Name         string                     `json:"name"`
	Path         string                     `json:"path"`
	PolicyDetect imagesecModel.PolicyDetect `gorm:"-" json:"policyDetect"` // 对各个策略的检测结果
}
