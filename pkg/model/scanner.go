package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/types"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnnvd"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnvd"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

var VulnerabilityInImagesRiskFilters = map[string]int{
	"default":      ScanTypeBySeverity,
	"medToCrit":    ScanTypeByMedToCritical,
	"networkBased": ScanTypeNetWorkBased,
}

func GetDefaultVulnerabilityInImagesRiskFilterName() string {
	return "default"
}

var ScannedImagesSortableFields = map[string]string{
	"finishedAt":      "finishedAt",
	"overallSeverity": "scan_report.overallSeverityInt",
	"repository":      "repository",
	"tag":             "tag",
	"imageDigest":     "digest",
}

func GetDefaultScannedImagesSortableName() string {
	return "finishedAt"
}

func GetScannedImagesSortableNames() []string {
	keys := make([]string, len(ScannedImagesSortableFields))

	i := 0
	for k := range ScannedImagesSortableFields {
		keys[i] = k
		i++
	}
	return keys
}

type ImageScanSummaryResult struct {
	Vulns             []*Vuln               `json:"vulns"`
	OverallSeverity   string                `json:"overallSeverity"`
	Repository        string                `json:"repository"`
	HarborURL         string                `json:"harborURL"`
	Tag               string                `json:"tag"`
	Digest            string                `json:"digest"`
	SensitiveFiles    []Sensitive           `json:"sensitiveFiles"`
	StartedAt         int64                 `json:"startedAt"`
	FinishedAt        int64                 `json:"finishedAt"`
	SeverityHistogram SeverityHistogramInfo `json:"severityHistogram"`
	RiskScore         float64               `json:"risk_score"`
	VirusScore        float64               `json:"virus_score"`
	VulnScore         float64               `json:"vuln_score"`
	SensitiveScore    float64               `json:"sensitive_score"`
	WebshellScore     float64               `json:"webshell_score"`
}

type ImageScanDetailedResult struct {
	TopVulns          []VulnerabilityInfo        `json:"topVulnerabilities"`
	OverallSeverity   string                     `json:"overallSeverity"`
	Repository        string                     `json:"repository"`
	HarborURL         string                     `json:"harborURL"`
	Tag               string                     `json:"tag"`
	Digest            string                     `json:"digest"`
	PerLayerReport    []VulnerabilityLayerReport `json:"perLayerReport"`
	TaskID            primitive.ObjectID         `json:"taskID"`
	SeverityHistogram SeverityHistogramInfo      `json:"severityHistogram"`
}

type ScanReportAffectedImage struct {
	Repository string             `json:"repository"`
	Tag        string             `json:"tag"`
	Digest     string             `json:"digest"`
	HarborURL  string             `json:"harborURL"`
	FinishedAt int64              `json:"finishedAt"`
	TaskID     primitive.ObjectID `json:"taskID"`
}

type VulnerabilityInImages struct {
	MetadataEntry  `json:"-" bson:",inline"`
	ID             primitive.ObjectID         `json:"id,omitempty" bson:"_id,omitempty"`
	VulnInfo       VulnerabilityInfo          `json:"vulnInfo" bson:"vulnInfo"`
	AffectedImages *[]ScanReportAffectedImage `json:"affectedImages" bson:"affectedImages"`
	ScanType       int                        `json:"-" bson:"scanType"` // By Severity 1 Med to Critical 2 Network based 3
}

// Sensitive ...
type Sensitive struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	DescriptionEn string `json:"description_en"`
	DescriptionZh string `json:"description_zh"`
}

const (
	ScanTypeBySeverity      = 1
	ScanTypeByMedToCritical = 2
	ScanTypeNetWorkBased    = 3
)

type VulnInfoEx struct {
	// Helper struct that creates one to one mapping between vulnerability and affected image.
	VulnerabilityInfo
	AffectedRepository string
	AffectedTag        string
	AffectedDigest     string
	AffectedHarborURL  string
	FinishedAt         int64
	TaskID             primitive.ObjectID
}

type SeverityCount struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Unknown  int64 `json:"unknown"`
}

type ImageSeverityCount struct {
	ImageID  int64         `json:"image_id"`
	Severity SeverityCount `json:"severity"`
}

type ImageRiskScore struct {
	Name      string  // servicename
	Score     float64 `gorm:"column:vuln_score" json:"Score"`
	Tag       string  `json:"tag"`
	ImageID   int64   `gorm:"column:image_id" json:"id"`
	ImageType int64   `json:"image_type"`
	FromType  int64   `json:"from_type"`
	Library   string  `json:"registryUrl"`
}

type ConstMapScore struct {
	MaxScore    float64
	SingleScore float64
}

type VulnOverview struct {
	VulnTotal int64         `json:"vuln_total"`
	Severity  SeverityCount `json:"severity"`
	// Top5      []ImageRiskScore `json:"top5"`
}

type VulnDetailInfo struct {
	ID          int64                   `json:"id"`
	UniqueID    uint64                  `json:"uniqueID,string"` // uint64在前端传
	Name        string                  `json:"name"`
	Severity    string                  `json:"severity"`
	Pkgname     string                  `json:"pkgname"`
	Pkgversion  string                  `json:"pkgversion"`
	Cvss        CVSSVulnerabilityInfo   `json:"cvss"`
	CvssMap     map[string]string       `json:"cvssMap"`
	Cnvd        []cnvd.Metadata         `json:"cnvds"`
	CNNVDs      cnnvd.VulnerabilityInfo `json:"cnnvds"`
	Links       []string                `json:"links"`
	Fixedby     string                  `json:"fixedby"`
	Description string                  `json:"description"`
}

type VulnDetailContainer struct {
	ImageName    string `json:"image_name"`
	ServiceName  string `json:"service_name"`
	Namespace    string `json:"namespace"`
	Alias        string `json:"alias"`
	Digest       string `json:"digest"`
	FullRepoName string `json:"full_repo_name"`
	Library      string `json:"library"`
	Tag          string `json:"tag"`
	Id           int    `json:"id"`
}
type VulnImageList struct {
	FullRepoName string `json:"full_repo_name"`
	Library      string `json:"library"`
	Tags         string `json:"tags"`
	Digest       string `json:"digest"`
	ImageId      int    `json:"id" gorm:"column:id"`
}

type VulnDetail struct {
	VulninfoApi VulnDetailInfo        `json:"vulninfo"`
	Containers  []VulnDetailContainer `json:"containers"`
}

// ReportImgBackInfo 镜像回溯时给前端返回的数据
type ReportImgBackInfo struct {
	ImageDigest    string    `json:"image_digest"`
	Created        time.Time `json:"created"`
	CreatedBy      string    `json:"created_by"`
	Vulus          []string  `json:"vulus"`
	Pkgs           []string  `json:"pkgs"`
	Malicious      []string  `json:"malicious"`
	SensitiveFiles []string  `json:"sensitive_files"`
	WebshellInfo   []string  `json:"webshell_info"`
	ImageID        int64     `json:"image_id"`
}

type SimpleImageDetail struct {
	Vulnerabilities []VulnerabilityInfo `json:"vuln_info"`
	Sensitives      []Sensitive         `json:"sensitive_info"`
}

type ImageVulnsSumData struct {
	CriticalNum int64 `json:"critical_num"`
	HighNum     int64 `json:"high_num"`
	MediumNum   int64 `json:"medium_num"`
	LowNum      int64 `json:"low_num"`
	UnknownNum  int64 `json:"unknown_num"`
}

type ImageSeverityScore struct {
	RiskScore int64 `json:"riskScore"`
}

type ImageRiskOver struct {
	CriticalNum int64 `json:"critical_num"` // 只需写入这个字段，含有病毒的文件数量。
	HighNum     int64 `json:"high_num"`
	MediumNum   int64 `json:"medium_num"`
	LowNum      int64 `json:"low_num"`
	UnknownNum  int64 `json:"unknown_num"`
}

type ImageRiskOverRedis struct {
	Data ImageSeverityScore `json:"data"`
	Key  string             `json:"Key"`
}

func (ir *ImageRiskOverRedis) Valid() bool {
	// if ir.Key == "" {
	// 	return false
	// }
	// if ir.Data.LowNum <= 0 && ir.Data.UnknownNum <= 0 && ir.Data.MediumNum <= 0 && ir.Data.HighNum <= 0 && ir.Data.CriticalNum <= 0 {
	// 	return false
	// }
	return true
}

type ImageVirusSumData struct {
	CriticalNum int64 `json:"critical_num"` // 只需写入这个字段，含有病毒的文件数量。
	HighNum     int64 `json:"high_num"`
	MediumNum   int64 `json:"medium_num"`
	LowNum      int64 `json:"low_num"`
	UnknownNum  int64 `json:"unknown_num"`
}

type PerLayerMaliciousResult struct {
	LayerDigest string
	VirusInfos  []*VirusInfo
}

type PerLayerSensitiveResult struct {
	LayerDigest string
	Sensitives  []Sensitive
}

type PerLayerWebshellResult struct {
	LayerDigest   string
	WebShellInfos []WebShellInfo
}

type PerLayerLicenseResult struct {
	LayerDigest  string
	LicenseInfos []LicenseInfo
}

type NewVulnDetail struct {
	CVEID string                        `json:"CVEID"`
	Cnvd  []cnvd.Metadata               `json:"cnvd"`
	Cnnvd cnnvd.VulnerabilityInfo       `json:"cnnvd"`
	Trivy []types.DetectedVulnerability `json:"TVuln"`
}

type LayerVulnDetail struct {
	Target string                    `json:"target"`
	Class  string                    `json:"class"`
	Type   string                    `json:"type"`
	Vulns  map[string]*NewVulnDetail `json:"vulns"`
}

type SingleScanDetail struct {
	Target string          `json:"target"`
	Class  string          `json:"class"`
	Type   string          `json:"type"`
	Vulns  []NewVulnDetail `json:"vulns"`
}

type ScanDetailScanImage struct {
	VulnDetails          []SingleScanDetail
	MaliciousDetails     []Malicious
	Sentitives           []Sensitive
	WebshellInfos        []scannermodel.WebshellFileInfo
	EnvDetails           []EnvKeyValue
	Software             []Software
	LicenseDetail        []LicenseInfo
	HasFixedVuln         int `json:"has_fixed_vuln"`
	ScanEnableCollection ScanEnableCollection
	SeverityHistogram    SeverityHistogramInfo
	VulnScore            float64
	MaliciousScore       float64
	WebShellScore        float64
	SensitiveScore       float64
}

type SubScannerLogData struct {
	ScanDetail  ScanDetailScanImage         `json:"scanDetail"`
	LayerMp     map[string]*LayerScanDetail `json:"layerMp"`
	ImageID     int64                       `json:"imageID"`
	ImageDigest string                      `json:"imageDigest"`
}

type LayerScanDetail struct {
	Vulns            []uint64
	MaliciousDetails []Malicious
	Sentitives       []Sensitive
	WebshellInfos    []string
}

type RespSingleVulnDetail struct {
	Language       string
	Frame          string
	Gobinary       string
	TargetFileNmae string `json:"target_file_name"`
	NewVulnDetail  `json:"new_vuln_detail"`
}

type EnvKeyValue struct {
	Key        string `json:"key"`
	Value      string `json:"value"`
	IsAbnormal int    `json:"is_abnormal"`
}

type ScanEnableCollection struct {
	EnvEnable       int `json:"env_enable"`
	SoftwareEnable  int `json:"software_enable"`
	SensitiveEnable int `json:"sensitive_enable"`
	LicenseEnable   int `json:"license_enable"`
}

type SummaryEnv struct {
	EnvName    string `json:"env_name"`
	EnvValue   string `json:"env_value"`
	IsAbnormal int    `json:"is_abnormal"`  // 标记是否异常
	IsInPolicy int    `json:"is_in_policy"` // 标记是否被所有策略引用
}

type LicenseInfo struct {
	Value       string `json:"value"`
	Description string `json:"description"`
	Name        string `json:"name"`
}

type WebFrameInfo struct {
	FrameName string `json:"frame_name"`
	Version   string `json:"version"`
	FilePath  string `json:"file_path"`
	FileName  string `json:"file_name"`
	Language  string `json:"language"`
}

type RespSingleVulnDetails []RespSingleVulnDetail

func (rvs RespSingleVulnDetails) Len() int {
	return len(rvs)
}

func (rvs RespSingleVulnDetails) Less(i, j int) bool {
	if len(rvs[i].NewVulnDetail.Trivy) > 0 && len(rvs[j].NewVulnDetail.Trivy) == 0 {
		return true
	} else if len(rvs[i].NewVulnDetail.Trivy) == 0 && len(rvs[j].NewVulnDetail.Trivy) > 0 {
		return false
	}
	subScore := map[string]int64{
		SeverityCritical:   6,
		SeverityHigh:       5,
		SeverityMedium:     4,
		SeverityLow:        3,
		SeverityNegligible: 2,
		SeverityUnknown:    1,
	}
	// 降序排列
	return subScore[rvs[i].NewVulnDetail.Trivy[0].Severity] >= subScore[rvs[j].NewVulnDetail.Trivy[0].Severity]
}

func (rvs RespSingleVulnDetails) Swap(i, j int) {
	rvs[i], rvs[j] = rvs[j], rvs[i]
}
