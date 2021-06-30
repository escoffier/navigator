package store

import (
	"time"
)

type SearchImageParam struct {
	Library        string
	Ids            []int64
	FullRepoSearch string // full_repo_name字段的模糊匹配
	TagSearch      string // tag字段的模糊匹配
	Tag            string // tag字段的精确匹配
	OnlineCount    string // "true","false" //这样写是为了应对go的默认值
	Digests        []string
	Status         int64  // 是否删除等状态
	FullRepoName   string // 这里是精确匹配
	Where          string // 外面传一个附加的字符串的where条件
	BiggerID       int64  // 取大于该ID的数据
}

type SearchScanLayerParam struct {
	ImageIds     []int64
	LayerDigests []string
	DeletedAt    int64
}

type SearchScanImageParam struct {
	Kind            string
	TaskIds         []string
	Ids             []int64
	Digests         []string
	ImageIds        []int64
	NoSerialization bool
	NoStatus        string
	Status          string
}

type SearchAssetsContainersParam struct {
	Digests    []string
	NotDeleted string   // true,false,all
	Fields     []string // 只想要的字段
}

type SearchRegistryParam struct {
	RegistryIds []uint
	Fields      []string // 只想要的字端
	LibraryUrls []string
}

type GetImageOverViewParm struct {
	SQL string
}
type SearchRejectPolicyParam struct {
	Library string
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
	Digest  string `json:"digest"`
	Library string `json:"library"`
	Count   int    `json:"count"`
}

type ImageGroup struct {
	Digest  string `json:"digest"`
	ImageId int64  `json:"image_id"`
	Library string `json:"library"`
	Count   int    `json:"count"`
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
	if idg[i].IntervalDateTime.Before(idg[j].IntervalDateTime) {
		return true
	}
	return false
}

func (idg IntervalDateGroups) Swap(i, j int) {
	idg[i], idg[j] = idg[j], idg[i]
}

type IntervalDateGroup struct {
	IntervalDate     string    `gorm:"column:interval_date" json:"interval_date"`
	Count            int64     `gorm:"column:cnt" json:"-"`
	IntervalDateTime time.Time `gorm:"-" json:"interval_date_time"`
}
