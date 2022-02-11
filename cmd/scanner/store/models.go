package store

import (
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type SearchImageParam struct {
	Library       string
	Libraries     []string
	Ids           []int64
	Search        string // full_repo_name和tag字段的模糊匹配
	Tag           string // tag字段的精确匹配
	OnlineCount   string // "true","false" //这样写是为了应对go的默认值
	Digests       []string
	Status        int64  // 是否删除等状态
	FullRepoName  string // 这里是精确匹配
	Where         string // 外面传一个附加的字符串的where条件
	StartID       int64  // 取大于该ID的数据
	LastID        int64  // 取大于该ID的数据
	FromType      int64
	NotFromType   int64
	ImageType     string
	Fields        []string // 只想要的字端
	LayersPrefix  string
	RegistryIds   []int64 // 仓库Id列表
	NodeHostnames []string
	JustCount     bool
}

type SearchImageWithScanParam struct {
	RegistryIds      []int64
	Library          string
	SearchWord       string
	Kind             string
	ScanStatus       []string // 是否删除等状态
	FromType         int64
	ImageType        string
	InIDs            []int64  //
	NotInIDs         []int64  //
	InDigests        []string //
	NotInDigests     []string //
	NodeHostname     string
	SpecialImageType string

	HasFixedVulu string
	IsReinforce  string
}

type GetImageParam struct {
	Library        string
	ID             int64
	FullRepoSearch string // full_repo_name字段的模糊匹配
	TagSearch      string // tag字段的模糊匹配
	Tag            string // tag字段的精确匹配
	Digest         string
	Status         int64  // 是否删除等状态
	FullRepoName   string // 这里是精确匹配
	FromType       int
	NotFromType    int
}

type DeleteImageParam struct {
	ImageID      int64
	FullRepoName string
	Tags         string
	Library      string
	FromType     int
}

type DeleteScanImageParam struct {
	ImageID int64
}

type SearchScanLayerParam struct {
	ImageIds     []int64
	LayerDigests []string
	DeletedAt    int64
}

type SearchScanImageParam struct {
	FromType        int64
	Kind            string
	TaskIds         []string
	Ids             []int64
	Digests         []string
	ImageIds        []int64
	NoSerialization bool
	NoStatus        string
	Status          string
	Fields          []string // 只想要的字端
}

type SearchRegistryParam struct {
	RegistryIds []int64
	Fields      []string // 只想要的字端
	LibraryURL  string
	UseTypes    []int64
	UseType     int64
	RegType     []string
	ID          int64
	Search      string

	Name     string
	NoDelete bool
}

type GetImageOverViewParm struct {
	SQL string
}
type SearchRejectPolicyParam struct {
	ID                int64
	Library           string
	Global            string
	UpdateRejectVulns bool
	RejectVulns       []model.RejectVuln
}
type SearchRejectRejectVulnParam struct {
	RejectID int64
}

type GetOnlineImageParam struct {
	SQL string
}

type SearchScanOneStatusParam struct {
	RepositoryName string
	Tag            string
	Digest         string
	FromURL        string
}

type OnlineImage struct {
	ID        int64  `json:"id"`
	ImageUUID uint32 `json:"image_uuid"`
}

type ImageGroup struct {
	Digest    string `json:"digest"`
	ImageID   int64  `json:"image_id"`
	Library   string `json:"library"`
	ImageUUID uint32 `json:"image_uuid"`
	Count     int    `json:"count"`
}

type OverviewReasonParam struct {
	TopN int
}

type SearchRejectRecordParam struct {
	Search        string
	Libraries     []string `json:"libraries"`
	RejectReasons []int64  `json:"reject_reasons"`
	StartAt       time.Time
	EndAt         time.Time
	RejectAt      time.Time
	FullRepoName  string // 镜像名
	Tag           string // 版本号
	Fields        []string
}

type SearchImageWhitelistParam struct {
	Library      string
	FullRepoName string // full_repo_name字段的模糊匹配
	Tag          string // tag字段的精确匹配
	Digest       string
	SearchWord   string
}

type DeleteImageWhitelistParam struct {
	WhiteID int64
}

type IntervalDateGroups []IntervalDateGroup

func (idg IntervalDateGroups) Len() int {
	return len(idg)
}

func (idg IntervalDateGroups) Less(i, j int) bool {
	return idg[i].IntervalDateTime.Before(idg[j].IntervalDateTime)
}

func (idg IntervalDateGroups) Swap(i, j int) {
	idg[i], idg[j] = idg[j], idg[i]
}

type IntervalDateGroup struct {
	IntervalDate     string    `gorm:"column:interval_date" json:"interval_date"`
	Count            int64     `gorm:"column:cnt" json:"-"`
	IntervalDateTime time.Time `gorm:"-" json:"interval_date_time"`
}

type SearchBaseImageParam struct {
}

type SearchTaskParam struct {
	Ids           []int64 // task id
	ExcludeStatus []int   // exclude tasks with these statuses
	Statuses      []int8  // task status
	StrategyID    int64
}

type SearchSubTaskParam struct {
	Ids     []int64 // subtask id
	TaskIds []int64
	// TaskId   int64
	// Status   int   // task status
	Statuses []int // subtask status
}

type SearchStrategyParam struct {
	IsDefault  string
	StrategyID int64
	Name       string
}
type SearchScanConfigParam struct {
	ScanConfigID int64
}

type DeleteSoftWareParam struct {
	StrategyID int64
	SoftID     int64
}

type SearchTrustedImageParam struct {
	Digests   []string
	IsTrusted string
}
