package apimodel

import (
	"gitlab.com/piccolo_su/vegeta/pkg/model"
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
	IsAbnormal int    `json:"isAbnormal"` // 标记是否异常
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
	Digest         string                   `json:"digest"`
	FromType       string                   `json:"fromType"`
	Image          string                   `json:"image"`
	RegistryURL    string                   `json:"registryUrl"`
	SensitiveFile  []string                 `json:"sensitiveFile"`
	Viruses        []model.VirusFileInfo    `json:"viruses"`
	Envs           []SummaryEnv             `json:"envs"`
	Webshell       []model.WebshellFileInfo `json:"webshell"`
	Vulns          []Vuln                   `json:"vulns"`
	ImageType      int64                    `json:"imageType"`
	Reinforced     int                      `json:"reinforced"`
	NodeHostname   string                   `json:"nodeHostname"`
	NodeIP         string                   `json:"nodeIp"`
	PrivilegedBoot int64                    `json:"privilegedBoot"`
	Size           int                      `json:"size"`
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
