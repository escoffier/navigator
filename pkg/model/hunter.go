package model

import (
	"time"
)

const (
	KubeHunterRecordStatusInit     = 0
	KubeHunterRecordStatusComplete = 1
	KubeHunterRecordStatusFailed   = 2
	KubeHunterRecordStatusExpired  = 3
)

type KubeHunterRecord struct {
	UUID      string    `gorm:"column:uuid"`
	Username  string    `gorm:"column:username"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
	Status    uint8     `gorm:"column:status"`    // 0代表初始状态 1代表成功 2代表失败
	MetaInfo  []byte    `gorm:"column:meta_info"` // KubeHunterRecordMeta json bytes
	Cluster   string    `gorm:"column:cluster"`
}

func (KubeHunterRecord) TableName() string {
	return "ivan_platform_kube_hunter_records"
}

type KubeHunterTranslateConf struct {
	// 严重级别翻译映射
	SeverityTransConf map[string]map[string]string
	// location翻译映射 遍历映射 采用字符串替换的方式
	LocationTransConf map[string]map[string]string `json:"locationReplaceTransConf"`
	// 漏洞信息
	Vulnerabilities map[string]map[string]KubeHunterVulnerabilityInfo `json:"vulnerabilities"` // key为 category@subCategory@name
}

type KubeHunterVulnerabilityInfo struct {
	Name        string `json:"name"`        //漏洞名称
	Category    string `json:"category"`    // 目录
	SubCategory string `json:"subCategory"` // 子目录
	Description string `json:"description"` // 描述
	IssueDetail string `json:"issueDetail"` // 扩展描述
	Remediation string `json:"remediation"` // 处理建议
}

type VulnerabilityDisplay struct {
	Location string `json:"location"`
	Evidence string `json:"evidence"`
	Severity string `json:"severity"`
	KubeHunterVulnerabilityInfo
}

type KubeHunterRecordMeta struct {
	Nodes           []*Node              `json:"nodes"`
	Services        []*Service           `json:"services"`
	Vulnerabilities []*VulnerabilityMeta `json:"vulnerabilities"` // 漏洞元信息列表
}

type VulnerabilityMeta struct {
	Category    string `json:"category"`
	SubCategory string `json:"subCategory"`
	Name        string `json:"name"`
	Location    string `json:"location"`
	Evidence    string `json:"evidence"`
	Severity    string `json:"severity"`
}

type Node struct {
	Type     string `json:"type"`
	Location string `json:"location"`
}

type Service struct {
	Service  string `json:"service"`
	Location string `json:"location"`
}

type KubeHunterTotalDisplay struct {
	UUID            string                  `json:"uuid"` // 唯一id
	Cluster         string                  `json:"cluster"`
	StartTimestamp  int64                   `json:"startTimestamp"`  // 开始时间 毫秒时间戳
	EndTimestamp    int64                   `json:"endTimestamp"`    // 结束时间 毫秒时间戳
	Username        string                  `json:"username"`        // 触发用户
	Vulnerabilities []*VulnerabilityDisplay `json:"vulnerabilities"` // 漏洞展示
	Statistics                              // 统计信息
}

type Statistics struct {
	NodeCount          int            `json:"nodeCount"`
	ServiceCount       int            `json:"serviceCount"`
	VulnerabilityCount int            `json:"vulnerabilityCount"`
	Severities         map[string]int `json:"severities"`
}

type RawKubeHunterContent struct {
	Nodes           []*Node             `json:"nodes"`
	Services        []*Service          `json:"services"`
	Vulnerabilities []*RawVulnerability `json:"vulnerabilities"`
}

type RawVulnerability struct {
	Location      string `json:"location"`
	VID           string `json:"vid"`
	Category      string `json:"category"`
	Severity      string `json:"severity"`
	Vulnerability string `json:"vulnerability"`
	Description   string `json:"description"`
	Evidence      string `json:"evidence"`
	AvdReference  string `json:"avd_reference"`
	Hunter        string `json:"hunter"`
}
