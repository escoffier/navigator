package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
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
	TopVulns          []VulnerabilityInfo   `json:"topVulnerabilities"`
	OverallSeverity   string                `json:"overallSeverity"`
	Repository        string                `json:"repository"`
	HarborURL         string                `json:"harborURL"`
	Tag               string                `json:"tag"`
	Digest            string                `json:"digest"`
	TaskID            primitive.ObjectID    `json:"taskID"`
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
	Name          string `json:"name" bson:"name"`
	Description   string `json:"description" bson:"description"`
	DescriptionEn string `json:"description_en" bson:"description_en"`
	DescriptionZh string `json:"description_zh" bson:"description_zh"`
}

const (
	ScanTypeBySeverity      = 1
	ScanTypeByMedToCritical = 2
	ScanTypeNetWorkBased    = 3
)

const (
	SeverityCritical   = "Critical"
	SeverityHigh       = "High"
	SeverityMedium     = "Medium"
	SeverityLow        = "Low"
	SeverityNegligible = "Negligible"
	SeverityUnknown    = "Unknown"
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
	Critical   int
	High       int
	Medium     int
	Low        int
	Negligible int
	Unknown    int
}

type ImageRiskScore struct {
	Name                  string // servicename
	Score                 float64
	SeverityHistogramInfo SeverityHistogramInfo
	Tag                   string `json:"tag"`
	ImageId               int    `json:"id"`
	ImageType             int64  `json:"image_type"`
}

type ConstMapScore struct {
	// Severity    string
	MaxScore    float64
	SingleScore float64
}
type VulnOverview struct {
	VulnTotal int              `json:"vuln_total"`
	Severity  SeverityCount    `json:"severity"`
	Top5      []ImageRiskScore `json:"top5"`
}

type VulnList struct {
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	PkgName    string `json:"pkg_name"`
	PkgVersion string `json:"pkg_version"`
}

type VulnDetailInfo struct {
	Name        string                   `json:"name"`
	Severity    string                   `json:"severity"`
	Pkgname     string                   `json:"pkgname"`
	Pkgversion  string                   `json:"pkgversion"`
	Cvss        CVSSVulnerabilityInfo    `json:"cvss,omitempty"`
	Cnvd        []CNVDVulnerabilityInfo  `json:"cnvds,omitempty"`
	CNNVDs      []CNNVDVulnerabilityInfo `json:"cnnvds,omitempty"`
	Links       []string                 `json:"links"`
	Fixedby     string                   `json:"fixedby"`
	Description string                   `json:"description"`
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
	VulninfoApi   VulnDetailInfo        `json:"vulninfo"`
	VulnImageList []VulnImageList       `json:"vuln_image_list"`
	Containers    []VulnDetailContainer `json:"containers"`
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

type ImageVirusSumData struct {
	CriticalNum int64 `json:"critical_num"` // 只需写入这个字段，含有病毒的文件数量。
	HighNum     int64 `json:"high_num"`
	MediumNum   int64 `json:"medium_num"`
	LowNum      int64 `json:"low_num"`
	UnknownNum  int64 `json:"unknown_num"`
}
