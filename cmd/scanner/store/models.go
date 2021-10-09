package store

import (
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type SearchImageParam struct {
	Library        string
	Libraries      []string
	Ids            []int64
	FullRepoSearch string // full_repo_name字段的模糊匹配
	TagSearch      string // tag字段的模糊匹配
	Tag            string // tag字段的精确匹配
	OnlineCount    string // "true","false" //这样写是为了应对go的默认值
	Digests        []string
	Status         int64  // 是否删除等状态
	FullRepoName   string // 这里是精确匹配
	Where          string // 外面传一个附加的字符串的where条件
	StartId        int64  // 取大于该ID的数据
	LastId         int64  // 取大于该ID的数据
	FromType       int64
	NotFromType    int64
	ImageType      string
	Fields         []string // 只想要的字端
	LayersPrefix   string
	RegistryIds    []int64 // 仓库Id列表
}

type SearchImageWithScanParam struct {
	Library         string
	FullRepoSearch  string // full_repo_name字段的模糊匹配
	TagSearch       string // tag字段的模糊匹配
	NodeImageSearch string // 节点镜像的搜索字段
	Kind            string

	Digests    []string
	ScanStatus string // 是否删除等状态
	FromType   int64
	ImageType  string
	InIDs      []int64 //
	NotInIDs   []int64 //
}

type GetImageParam struct {
	Library        string
	Id             int64
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
	ImageId      int64
	FullRepoName string
	Tags         string
	Library      string
	FromType     int
}

type DeleteScanImageParam struct {
	ImageId int64
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
	RegistryIds []uint
	Fields      []string // 只想要的字端
	LibraryUrl  string
	UseTypes    []int64
	UseType     int64
	RegType     []string
	Id          int64
	Search      string

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
	FromUrl        string
}

type OnlineImage struct {
	ID        int64  `json:"id"`
	ImageUUID uint32 `json:"image_uuid"`
}

type ImageGroup struct {
	Digest    string `json:"digest"`
	ImageId   int64  `json:"image_id"`
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
	Library       string // 仓库名
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
	WhiteId int64
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
