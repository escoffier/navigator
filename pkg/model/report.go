package model

import (
	"time"

	json "github.com/json-iterator/go"
)

const (
	ReportTaskTypeOneTime = "oneTime"
	ReportTaskTypeMonthly = "monthly"
	ReportTaskTypeWeekly  = "weekly"
)

const (
	ReportCategoryImages = "images"
	ReportCategoryAssets = "assets"
	ReportCategoryEvents = "events"
)

const (
	ReportRecordStatusInit     = 0
	ReportRecordStatusComplete = 1
	ReportRecordStatusFailed   = 2
	ReportRecordStatusExpired  = 3
)

type ReportTaskTemplate struct {
	ID                     int32    `json:"id"`
	Name                   string   `json:"name"`
	Type                   string   `json:"type"`
	Categories             []string `json:"categories"`
	Emails                 []string `json:"emails"`
	Clusters               []string `json:"clusters"`
	Description            string   `json:"description"`
	CycleDay               uint8    `json:"cycleDay"`
	StartTimestamp         int64    `json:"startTimestamp"`
	EndTimestamp           int64    `json:"endTimestamp"`
	LatestTriggerTimestamp int64    `json:"latestTriggerTimestamp"`
	CreatedTimestamp       int64    `json:"createdTimestamp"`
}

func (r *ReportTaskTemplate) Convert() *ReportTaskTemplateMeta {
	result := &ReportTaskTemplateMeta{
		ID:             r.ID,
		Name:           r.Name,
		Type:           r.Type,
		Description:    r.Description,
		CycleDay:       r.CycleDay,
		StartTimestamp: r.StartTimestamp,
		EndTimestamp:   r.EndTimestamp,
	}

	categories, _ := json.Marshal(r.Categories)
	clusters, _ := json.Marshal(r.Clusters)
	emails, _ := json.Marshal(r.Emails)

	result.Categories = string(categories)
	result.Clusters = string(clusters)
	result.Emails = string(emails)

	return result
}

type ReportTaskTemplateMeta struct {
	ID                      int32     `gorm:"primaryKey;column:id"`
	Name                    string    `gorm:"column:name"`
	Type                    string    `gorm:"column:type"`
	Clusters                string    `gorm:"column:clusters"`
	Categories              string    `gorm:"column:categories"`
	Emails                  string    `gorm:"column:emails"`
	Description             string    `gorm:"column:description"`
	CycleDay                uint8     `gorm:"column:cycle_day"`
	StartTimestamp          int64     `gorm:"column:start_timestamp"`
	EndTimestamp            int64     `gorm:"column:end_timestamp"`
	LatestGenerateTimestamp int64     `gorm:"column:latest_generate_timestamp"`
	CreatedAt               time.Time `gorm:"column:created_at"`
	UpdatedAt               time.Time `gorm:"column:updated_at"`
}

func (r *ReportTaskTemplateMeta) Convert() *ReportTaskTemplate {
	result := &ReportTaskTemplate{
		ID:                     r.ID,
		Name:                   r.Name,
		Type:                   r.Type,
		Description:            r.Description,
		CycleDay:               r.CycleDay,
		StartTimestamp:         r.StartTimestamp,
		EndTimestamp:           r.EndTimestamp,
		LatestTriggerTimestamp: r.LatestGenerateTimestamp,
		CreatedTimestamp:       r.CreatedAt.UnixNano() / 1e6,
	}

	_ = json.Unmarshal([]byte(r.Categories), &result.Categories)
	_ = json.Unmarshal([]byte(r.Clusters), &result.Clusters)
	_ = json.Unmarshal([]byte(r.Emails), &result.Emails)
	return result
}

func (ReportTaskTemplateMeta) TableName() string {
	return "ivan_platform_report_task_templates"
}

type ReportRecord struct {
	UUID           string    `json:"uuid" gorm:"primaryKey;column:uuid"`
	TemplateID     int32     `json:"templateID" gorm:"column:template_id"`
	StartTimestamp int64     `json:"startTimestamp" gorm:"column:start_timestamp"`
	EndTimestamp   int64     `json:"endTimestamp" gorm:"column:end_timestamp"`
	Status         uint8     `json:"-" gorm:"column:status"`
	Content        []byte    `json:"-" gorm:"column:content"`
	CreatedAt      time.Time `json:"-" gorm:"column:created_at"`
	UpdatedAt      time.Time `json:"-" gorm:"column:updated_at"`
}

func (ReportRecord) TableName() string {
	return "ivan_platform_report_records"
}

type ReportDetail struct {
	TemplateName   string        `json:"templateName"`
	Categories     []string      `json:"categories"`
	StartTimestamp int64         `json:"startTimestamp"`
	EndTimestamp   int64         `json:"endTimestamp"`
	Type           string        `json:"type"`
	EventsReport   *EventsReport `json:"eventsReport"`
	AssetsReport   *AssetsReport `json:"assetsReport"`
	ImagesReport   *ImagesReport `json:"imagesReport"`
}

type EventsReport struct {
	Events []*EventItem `json:"events"`
}

type EventItem struct {
	RuleCategory string `json:"ruleCategory"`
	RuleName     string `json:"ruleName"`
	Cluster      string `json:"cluster"`
	Namespace    string `json:"namespace"`
	NodeKey      string `json:"nodeKey"`
	Severity     uint8  `json:"severity"`
	Timestamp    int64  `json:"timestamp"`
}

type AssetsReport struct {
	Clusters   []*ClusterItem   `json:"clusters"`
	Nodes      []*NodeItem      `json:"nodes"`
	Containers []*ContainerItem `json:"containers"`
}

type ClusterItem struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"createdAt"`
}

type NodeItem struct {
	Cluster string `json:"cluster"`
	Name    string `json:"name"`
}

type ContainerItem struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	ResourceName string `json:"resourceName"`
	Namespace    string `json:"namespace"`
	Cluster      string `json:"cluster"`
	CreatedAt    int64  `json:"createdAt"`
}

func CheckType(t string) bool {
	return t == ReportTaskTypeOneTime ||
		t == ReportTaskTypeMonthly ||
		t == ReportTaskTypeWeekly
}

func CheckCategory(category string) bool {
	return category == ReportCategoryImages ||
		category == ReportCategoryEvents ||
		category == ReportCategoryAssets
}

type ImagesReport struct {
	ImageCount         *ImageCount         `json:"imageCount"`
	VulnerabilityCount *VulnerabilityCount `json:"vulnerabilityCount"`
	RiskImages         []*RiskImageItem    `json:"riskImages"`
}

type ImageCount struct {
	TotalImageCount      int `json:"totalImageCount"`
	OnlineImageCount     int `json:"onlineImageCount"`
	TrustedImageCount    int `json:"trustedImageCount"`
	RepairableImageCount int `json:"repairableImageCount"`
	ReinforcedImageCount int `json:"reinforcedImageCount"`
	VulnerabilityCount   int `json:"vulnerabilityCount"`
	SensitiveFileCount   int `json:"sensitiveFileCount"`
	MaliciousCount       int `json:"maliciousCount"`
	WebShellCount        int `json:"webShellCount"`
	AbnormalEnvCount     int `json:"abnormalEnvCount"`
	LicenceCount         int `json:"licenceCount"`
	SoftwareCount        int `json:"softwareCount"`
	PrivilegedCount      int `json:"privilegedCount"`
}

type VulnerabilityCount struct {
	TotalVulnerabilityCount    int `json:"totalVulnerabilityCount"`
	CriticalVulnerabilityCount int `json:"criticalVulnerabilityCount"`
	HighVulnerabilityCount     int `json:"highVulnerabilityCount"`
	MediumVulnerabilityCount   int `json:"mediumVulnerabilityCount"`
	LowVulnerabilityCount      int `json:"lowVulnerabilityCount"`
	UnknownVulnerabilityCount  int `json:"unknownVulnerabilityCount"`
}

type RiskImageItem struct {
	Name      string  `json:"name"`
	Version   string  `json:"version"`
	RiskScore float64 `json:"riskScore"`
}
