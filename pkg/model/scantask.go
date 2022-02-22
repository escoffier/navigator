package model

import (
	"math"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	ScanStatusInProgress = "inprogress"
	ScanStatusSucceeded  = "succeeded"
	ScanStatusFailed     = "failed"
	ScanStatusPending    = "pending"
	ScanStatusNotScan    = "not_scan"
)

type ScannerReq struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization,omitempty"`
	Repository    string `json:"repository"`
	Digest        string `json:"digest,omitempty"`
	Tag           string `json:"tag,omitempty"`
	ResultsURL    string `json:"resultsUrl,omitempty"`
}

// ScanTask ...
type ScanTask struct {
	MetadataEntry     `json:"-" bson:",inline"`
	ID                primitive.ObjectID    `json:"dbId,omitempty" bson:"_id,omitempty"`
	URL               string                `json:"url" bson:"url"`
	Authorization     string                `json:"-" bson:"-"` // Do NOT persist or return authorization
	Status            string                `json:"status" bson:"status"`
	Message           string                `json:"message" bson:"message"`
	StartedAt         int64                 `json:"startedAt" bson:"startedAt"`
	FinishedAt        int64                 `json:"finishedAt" bson:"finishedAt"`
	Tag               string                `json:"tag" form:"tag" query:"tag"`
	Repository        string                `json:"repository" bson:"repository"`
	ImageDigest       string                `json:"digest,omitempty" bson:"digest,omitempty"` // sha256:2166fca0902583220885c81e7dd194e51c05c2b58029c00d33b3c25a1448f108
	ScanReport        ScanReport            `json:"scan_report,omitempty" bson:"scan_report,omitempty"`
	HarborURL         string                `json:"harborURL,omitempty" bson:"harborURL,omitempty"`
	FirstScanAt       int64                 `json:"firstScanAt" bson:"firstScanAt"` // tracks the first ever scan of this image (digest)
	Stale             bool                  `json:"stale" bson:"stale"`             // if true, there are newer scans of this image (digest)
	SeverityHistogram SeverityHistogramInfo `json:"severityHistogram" bson:"severityHistogram"`
	ImageID           int64                 `json:"-" bson:"-"`
	TableID           int64                 `json:"-" bson:"-"`
}

type ScanReport struct {
	Vulns              VulnerabilityReport   `json:"vulnerability" bson:"vulnerability"`
	OverallSeverity    string                `json:"overallSeverity" bson:"overallSeverity"`
	OverallSeverityInt int                   `json:"overallSeverityInt" bson:"overallSeverityInt"`
	SeverityHistogram  SeverityHistogramInfo `json:"severityHistogram" bson:"severityHistogram"`
}

type SeverityHistogramInfo struct {
	NumCritical   int64 `json:"numCritical"`
	NumHigh       int64 `json:"numHigh"`
	NumMedium     int64 `json:"numMedium"`
	NumLow        int64 `json:"numLow"`
	NumNegligible int64 `json:"numNegligible"`
	NumUnknown    int64 `json:"numUnknown"`
}

type VulnerabilityReport struct {
	Repository        string                     `json:"repository"`
	Tag               string                     `json:"tag"`
	Digest            string                     `json:"digest"`
	Vulnerabilities   []VulnerabilityInfo        `json:"vulnerabilities"`
	Sensitives        []Sensitive                `json:"sensitives"`
	PerLayerReport    []VulnerabilityLayerReport `json:"perLayerReport"`
	SeverityHistogram SeverityHistogramInfo      `json:"severityHistogram" bson:"severityHistogram"`
}

type VulnerabilityLayerReport struct {
	LayerNo                int                   `json:"layerNo"`
	LayerDigest            string                `json:"layerDigest"`
	VulnerabilitiesAdded   []VulnerabilityInfo   `json:"vulnerabilitiesAdded"`
	VulnerabilitiesRemoved []VulnerabilityInfo   `json:"vulnerabilitiesRemoved"`
	Sensitives             []Sensitive           `json:"sensitives"`
	OverallSeverity        string                `json:"overallSeverity"`
	OverallSeverityInt     int                   `json:"overallSeverityInt"`
	SeverityHistogram      SeverityHistogramInfo `json:"severityHistogram" bson:"severityHistogram"`
}

type ImageResponse struct {
	ID                int64          `json:"id"`
	Digest            string         `json:"digest"`
	Library           string         `json:"library"`
	NodeIP            string         `json:"node_ip"`
	ScanStatus        int            `json:"scan_status"`
	CompleteTime      int64          `json:"complete_time"`
	Questions         []QuestionInfo `json:"questions"`
	FullRepoName      string         `json:"full_repo_name"`
	Tags              string         `json:"tags"`
	ImageType         int64          `json:"image_type"`
	RiskScore         float64        `json:"risk_score"`
	RegistryID        int64          `json:"registry_id"`
	RegistryName      string         `json:"registry_name"`
	RegistryDeletedAt int64          `json:"registry_deleted_at"`
	FromType          int64          `json:"from_type"`
	Trusted           int64          `json:"trusted"`
	HasFixedVulu      int64          `json:"has_fixed_vulu"`
	Online            bool           `json:"online"`
	Os                string         `json:"os"`
	NodeHostname      string         `json:"node_hostname"`
	IsReinforce       int64          `json:"is_reinforce"`
	PrivilegedBoot    int64          `json:"privileged_boot"`
	ImageUUID         uint32         `json:"image_uuid"`
}

func ImageToImageResponse(img ImageList) ImageResponse {
	im := ImageResponse{
		ID:           img.ID,
		Digest:       img.Digest,
		Library:      img.Library,
		ScanStatus:   img.ScanStatus,
		Questions:    img.Questions,
		FullRepoName: img.FullRepoName,
		Tags:         img.Tags,
		ImageType:    img.ImageType,
		NodeIP:       img.NodeIP,
		NodeHostname: img.NodeHostname,
		Os:           img.OS,
	}
	if img.ScanImage != nil {
		im.CompleteTime = img.ScanImage.FinishAt
		im.RiskScore = img.ScanImage.VulnScore + img.ScanImage.SensitiveScore + math.Min(img.ScanImage.WebshellScore+img.ScanImage.VirusScore, 40)
	}

	if img.Registry != nil {
		im.RegistryName = img.Registry.Name
		im.Library = img.Registry.Url
		im.RegistryDeletedAt = img.Registry.DeletedAt
	}
	return im
}

type ScanOneStatusResponse struct {
	ScanStatus         int     `json:"scan_status"`
	EndTime            string  `json:"end_time"`
	HasVulu            bool    `json:"has_vulu"`      // 是否有漏洞
	HasMalicious       bool    `json:"has_malicious"` // 是否有病毒
	HasSensitive       bool    `json:"has_sensitive"` // 是否有敏感文件
	RiskScore          float64 `json:"risk_score"`
	OverallSeverity    string  `json:"overall_severity"`
	OverallSeverityInt int     `json:"overall_severity_int"`
}

// RejectPolicyResponse 阻断策略表
type RejectPolicyResponse struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`     // 策略名
	Library  string `json:"library"`  // 生效仓库名
	Comment  string `json:"comment"`  // 备注
	Operator string `json:"operator"` // 操作员名字

	VulnScore int64 `json:"vuln_score"` // 漏洞按分数阻断(低于多少分后阻断)
	VulnLevel int64 `json:"vuln_level"` // 漏洞按严重级别阻断

	SensitiveFilePolicy int64 `json:"sensitive_file_policy"` // 敏感文件规则
	MaliciousPolicy     int64 `json:"malicious_policy"`      // 恶意文件规则

	// 使用方式，是用于cicd,还是k8s上线部署,int64的每一位表示一种使用场景
	RejectVulns []RejectVuln `gorm:"-" json:"reject_vulns"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	Enable      bool         `json:"enable"` // 是否启用该策略
	DeletedAt   int          `json:"deleted_at,omitempty"`
}

type ImageRejectOverview struct {
	OneDayCount   int64                   `json:"one_day_count"`
	SevenDayCount int64                   `json:"seven_day_count"`
	Graphs        []int64                 `json:"graphs"`
	RejectTop5    []RejectReasonStatistic `json:"reject_top5"`
}

type RejectReasonStatistic struct {
	RejectReason         int64  `gorm:"column:reject_reason" json:"-"`
	RejectReasonStringCN string `gorm:"-" json:"reject_reason_cn"`
	RejectReasonStringEN string `gorm:"-" json:"reject_reason_en"`
	Count                int64  `gorm:"column:cnt" json:"count"`
}

type GlobalRejectPolicy struct {
	CICDEnable    bool   `json:"cicd_enable"`
	K8sEnable     bool   `json:"k8s_enable"`
	Mode          string `json:"mode"`
	OnlineMonitor bool   `json:"online_monitor"`
} // @name GlobalRejectPolicy

type RejectOnlineMonitorImage struct {
	Image    string `json:"image"`
	Digest   string `json:"digest"`
	FromType string `json:"type"`
	// CustomKV      []KVHash      `json:"custom_KV"`
	NotifyContext NotifyContext `json:"notify_context"`
}

type RejectReasonStatistics []RejectReasonStatistic

func (rrs RejectReasonStatistics) Len() int {
	return len(rrs)
}

// Less 到序
func (rrs RejectReasonStatistics) Less(i, j int) bool {
	return rrs[i].Count > rrs[j].Count
}

func (rrs RejectReasonStatistics) Swap(i, j int) {
	rrs[i], rrs[j] = rrs[j], rrs[i]
}

type RejectReasons struct {
	CH map[int64]string `json:"ch"`
	EN map[int64]string `json:"en"`
}

func NewReqBody(ruleKey EventCenterRule, notify NotifyContext, uuid uint64) ReqBody {
	reqBody := ReqBody{
		RuleKey: ruleKey,
		NotifyContext: NotifyContext{
			PodUID:    notify.PodUID,
			PodName:   notify.PodName,
			Namespace: notify.Namespace,
			Cluster:   notify.Cluster,
			ServiceID: notify.ServiceID,
			CustomKV:  notify.CustomKV,
		},
		Timestamp: time.Now().Unix(),
		UUID:      uuid,
	}
	if reqBody.NotifyContext.PodUID == "" {
		reqBody.NotifyContext.PodUID = "-"
	}
	if reqBody.NotifyContext.PodName == "" {
		reqBody.NotifyContext.PodName = "-"
	}

	if reqBody.NotifyContext.Namespace == "" {
		reqBody.NotifyContext.Namespace = "-"
	}
	if reqBody.NotifyContext.Cluster == "" {
		reqBody.NotifyContext.Cluster = "default"
	}

	return reqBody
}

func NewEventCenterRule(name, module, category string) EventCenterRule {
	return EventCenterRule{
		Name:     name,
		Module:   module,
		Category: category,
	}
}

type ReqBody struct {
	RuleKey       EventCenterRule `json:"RuleKey"`
	NotifyContext NotifyContext   `json:"NotifyContext"`
	Timestamp     int64           `json:"Timestamp"`
	UUID          uint64          `json:"UUID"`
}

type EventCenterRule struct {
	Name     string `json:"Name"`
	Module   string `json:"Module"`
	Category string `json:"Category"`
}

type NotifyContext struct {
	PodUID    string    `json:"PodUID"`
	PodName   string    `json:"PodName"`
	Namespace string    `json:"Namespace"`
	Cluster   string    `json:"Cluster"`
	ServiceID string    `json:"ServiceID"`
	CustomKV  []KVHashs `json:"CustomKV"`
}

type KVHashs struct {
	KVHash KVHash `json:"KVHash"`
}

type KVHash struct {
	EN KeyValue `json:"en,omitempty"`
	ZH KeyValue `json:"zh,omitempty"`
}

type KeyValue struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

func NewKeyValue(key, value string) KeyValue {
	return KeyValue{
		Key:   key,
		Value: value,
	}
}

type ScanOneForCICDRequest struct {
	Image     string `json:"image"`
	MaxSecond string `json:"max_second"`
	Insecure  bool   `json:"insecure"`
}

type ScanOneForCICDResponse struct {
	IsScan      bool       `json:"is_scan"`
	Safe        bool       `json:"safe"`
	ImageDetail *ImageList `json:"-"`
	Msg         []KVHashs  `json:"-"`

	RejectMsg [][]string `json:"reject_msg"`

	Vulu      [][]string `json:"vulu"`
	Sensitive [][]string `json:"sensitive"`
	Virus     [][]string `json:"virus"`
	Webshell  [][]string `json:"webshell"`
	Envs      [][]string `json:"envs"`
}

type ScanOneCICDResultRequest struct {
	ImageID int64  `json:"id"`
	Library string `json:"library"`
}

type ListBaseImageResponse struct {
	FullRepoName string         `json:"full_repo_name"`
	Library      string         `json:"library"`
	Questions    []QuestionInfo `json:"questions"`
	Score        int            `json:"score"`
}

type RejectReasonMap struct {
	En map[int64]string `json:"en"`
	Zh map[int64]string `json:"zh"`
}

type ScanLayerResponse struct { // 层级扫描结果
	ID            uint                   `json:"id"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	DeletedAt     int                    `json:"deleted_at"`
	ImageID       int64                  `json:"image_id"`
	LayerDigest   string                 `json:"layer_digest"`
	VulnInfo      []RespSingleVulnDetail `json:"vuln_info"`
	PkgInfo       interface{}            `json:"pkg_info"`
	MaliciousInfo []VirusInfo            `json:"malicious_info"` // 恶意文件
	WebshellInfo  []WebShellInfo         `json:"webshell_info"`  // webshell
	SensitiveFile []Sensitive            `json:"sensitive_file"`
	IsBasic       int                    `json:"is_basic"`
}
