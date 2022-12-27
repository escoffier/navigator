package scanner_ci

import (
	"github.com/docker/docker/api/types/image"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnnvd"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnvd"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type WebhookVulnList struct {
	Name       string `json:"name"` // 形如CVE-2021-28831
	Severity   string `json:"severity"`
	PkgName    string `json:"pkgName"`    // 软件包来源
	PkgVersion string `json:"pkgVersion"` // 软件包版本
	FixedBy    string `json:"fixedBy"`    // 修复建议
	Match      int    `json:"match"`
}

type VulnList struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"` // 形如CVE-2021-28831
	SeverityInt int    `json:"severityInt"`
	Severity    string `json:"severity"`
	PkgName     string `json:"pkgName"`    // 软件包来源
	PkgVersion  string `json:"pkgVersion"` // 软件包版本
	FixedBy     string `json:"fixedBy"`    // 修复建议
	UniqueVuln  uint64 `json:"uniqueVuln,string"`
	Language    string `json:"language"` // 把编程语言
	Match       int
	White       bool
}
type VulnLists []VulnList

func (vl VulnLists) Len() int {
	return len(vl)
}

func (vl VulnLists) Less(i, j int) bool {
	return vl[i].SeverityInt >= vl[j].SeverityInt
}

func (vl VulnLists) Swap(i, j int) {
	vl[i], vl[j] = vl[j], vl[i]
}

type PkgList struct {
	PkgName    string
	PkgVersion string
	Histogram  model.SeverityHistogramInfo
}

type Whitelist struct {
	Image string //name
	Time  string //endtime
}

type WhitelistParams struct {
	Image     string
	Limit     int
	Offset    int
	StartTime int64
	EndTime   int64
	NowTime   int64
}

const (
	CiAlert  = 1
	CiReject = 2
)

const (
	VulnQuestion      = 1
	SenSitiveQuestion = 2
)

func GenQuestionFlag() []int {
	return []int{VulnQuestion, SenSitiveQuestion}
}

type ImageRecordTop5 struct {
	ImageName string
	Count     int
}

type ImageOverviewNode struct {
	Sum    int
	Alert  int
	Reject int
	Time   string
}
type ImageOverviewNodes []ImageOverviewNode

func (ion ImageOverviewNodes) Len() int {
	return len(ion)
}

func (ion ImageOverviewNodes) Less(i, j int) bool {
	return ion[i].Time < ion[j].Time
}

func (ion ImageOverviewNodes) Swap(i, j int) {
	ion[i], ion[j] = ion[j], ion[i]
}

type ImageFilter struct {
	Image         string //imageName
	Kind          []int  //question
	TaskName      string //
	Status        []int  //normal,alarm,reject
	StartTime     int64
	EndTime       int64
	Limit         int
	Offset        int
	KindAttribute string
}

type ImageParams struct {
	Image         string //imageName
	Kind          string //question
	TaskName      string //
	Status        string //normal,alarm,reject
	StartTime     int64
	EndTime       int64
	KindAttribute string //and,or
	Limit         int
	Offset        int
}

type ImageRecord struct {
	ID                int64 `json:"id"`
	ImageName         string
	SeverityHistogram model.SeverityHistogramInfo `json:"severityHistogram"`
	Questions         string
	TaskName          string `json:"pipeline_name"`
	ScanTime          int64
	InWhitelist       bool   `json:"in_whitelist"`
	MatchWhitelist    bool   `json:"match_whitelist"`
	Status            string `json:"status"`
}

type ImageRemediation struct {
	Vuln      string `json:"vuln"`
	Sensitive string `json:"sensitive"`
}

type ImageRecordDetail struct {
	ID                int64                       `gorm:"primaryKey"`
	ImageName         string                      `gorm:"type:varchar(255);" json:"image_name"`
	OS                string                      `gorm:"type:varchar(64);column:os" json:"os"`
	PipelineName      string                      `gorm:"type:varchar(255);" json:"pipeline_name"`
	SensitiveFile     SensitiveFileDetail         `json:"sensitive_file"`
	SeverityHistogram model.SeverityHistogramInfo `gorm:"-" json:"severityHistogram"` // 评级集合
	InWhitelist       bool                        `gorm:"column:in_whitelist" json:"in_whitelist"`
	MatchWhitelist    bool                        `gorm:"column:match_whitelist" json:"match_whitelist"`
	Status            string                      `gorm:"column:mode" json:"mode"`
	PolicySnap        Policy                      `json:"policy_snapshot"`
	Message           string                      `gorm:"type:varchar(255)" json:"message"` // 错误信息
	AllRemediation    ImageRemediation            `json:"all_remediation"`
	Layers            []image.HistoryResponseItem `json:"layers"`
	Questions         string                      `json:"questions"`
	VulnFlag          bool                        `json:"vulnFlag"`
	SensitiveFlag     bool                        `json:"sensitiveFlag"`
	ScanTime          int64                       `json:"scan_time"`
}

type SearchVulnParam struct {
	PkgKeyword      string
	LanguageKeyword string
	TargetKeyword   string
	FrameKeyword    string
	VulnKeyword     string // 漏洞名搜索
	UniqueVulns     []uint64
	Fields          []string
	ImageID         int64
	LayerDigest     string
	PkgName         string  // 软件包来源
	PkgVersion      string  // 软件包版本
	Sources         string  // 来源筛选,用逗号分隔
	CanFixed        string  // 是否可修复筛选
	SeverityInt     []int64 // 漏洞级别筛选
	MatchPolicy     bool
}
type SearchVulnParm struct {
	VulnKeyword     string
	PkgKeyword      string
	LanguageKeyword string
	FrameKeyword    string
	TargetKeyword   string
	UniqueVulns     []uint64
	Fields          []string
	OmitFields      []string
	Where           string
	ImageID         int64
	PkgName         string
	PkgVersion      string
	Sources         []string // 漏洞来源筛选
	CanFixed        string
	SeverityInt     []int64
	JustReturnCount bool
	MatchPolicy     bool
}

type Sensitive struct {
	Name  string `json:name`
	Path  string `json:path`
	Match bool   `json:match`
}
type SensitiveFileDetail struct {
	Files       []Sensitive
	Remediation string // remediation for sensitive files, eg. "delete /etc/id.rsa"
	Match       bool   //
}

type CountServerity struct {
	Severity string `json:"severity"`
	Cnt      int    `json:"cnt"`
}
type VulnDetailInfo struct {
	ID          int64                       `json:"id"`
	UniqueVuln  uint64                      `json:"uniqueVuln,string"` // uint64在前端传
	Name        string                      `json:"name"`
	Severity    string                      `json:"severity"`
	Pkgname     string                      `json:"pkgname"`
	Pkgversion  string                      `json:"pkgversion"`
	Cvss        model.CVSSVulnerabilityInfo `json:"cvss"`
	CvssMap     map[string]string           `json:"cvssMap"`
	Cnvd        []cnvd.Metadata             `json:"cnvds"`
	CNNVDs      cnnvd.VulnerabilityInfo     `json:"cnnvds"`
	Links       []string                    `json:"links"`
	Fixedby     string                      `json:"fixedby"`
	Description string                      `json:"description"`
}
type VulnDetail struct {
	VulninfoApi VulnDetailInfo `json:"vulninfo"`
}
