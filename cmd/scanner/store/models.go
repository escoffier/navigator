package store

import (
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type SearchImageParam struct {
	Libraries    []string
	InIds        []int64
	NotInIds     []int64
	Keyword      string // full_repo_name和tag字段的模糊匹配
	Digests      []string
	FullRepoName string // 这里是精确匹配
	Tag          string
	StartID      int64 // 取大于该ID的数据
	LastID       int64 // 取大于该ID的数据
	FromType     int64
	ImageType    string
	RepoKeyword  string // full_repo_name的模糊匹配
	TagKeyword   string // tag的模糊匹配

	Fields            []string // 只想要的字端
	OmitFields        []string // 不想要的字端
	LayersPrefix      string
	RegistryIds       []int64 // 仓库Id列表
	NodeHostnames     []string
	JustCount         bool
	UUIDs             []uint32
	SecurityIssueFlag uint64
	AttrFlag          uint64
	ScanStatusFlag    uint64

	Flag               uint64
	Where              string
	UniqueImage        uint64
	Projects           []RegProject
	NodeHostname       string
	NotCount           bool
	TrustedImageIds    []int64
	NotTrustedImageIds []int64
	NotParseNodeImage  bool // 解析节点镜像的imageName

	AttrIntersection  string // 属性交集还是并集 and or
	IssueIntersection string // 安全问题交集还是并集 and or
}

type GetSubTaskListWithImageParam struct {
	TaskIds []int64
	Status  []int64
}

func (sp *SearchImageParam) GetDefaultOmitFields() []string {
	omit := []string{"config_json", "manifest_v1_json", "manifest_v2_json"}
	return omit
}

type GroupVulnSeverityParma struct {
	ImageId int64
}

type SearchImageWithScanParam struct {
	RegistryIds      []int64
	Library          string
	SearchWord       string
	Kind             string
	ScanStatus       []string
	FromType         int64
	ImageType        string
	InIDs            []int64
	NotInIDs         []int64
	InDigests        []string
	NotInDigests     []string
	NodeHostname     string
	SpecialImageType string
	UUIDs            []uint32
	HasFixedVulu     string
	IsReinforce      string
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
	ImageId      int64
	LayerDigests []string
	DeletedAt    int64
}

type SearchScanImageParam struct {
	FromType        int64
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
	RegistryIds     []int64
	Fields          []string // 只想要的字端
	LibraryURL      string
	UseTypes        []int64
	UseType         int64
	RegType         []string
	ID              int64
	Search          string
	Name            string
	NoDelete        bool
	ScannerInstance string
}

func (s *SearchRegistryParam) Compatible() {
	s.RegType = util.DeDuplicationStringSlice(s.RegType)
	for i := range s.RegType {
		if s.RegType[i] == consts.HarborVersion {
			s.RegType = append(s.RegType, consts.HarborV2Version, consts.HarborV1Version)
		}
	}
}

type SearchImageRetryParam struct {
	LessRetryCount int64
	MoreRetryCount int64
	UniqueImage    uint64
}

type SearchSyncTaskParam struct {
	RegIds   []int64
	Finished string
	SyncType string
}

type GetImageOverViewParam struct {
	ImageUUIDs  []uint32
	FlagMore    int
	FlagLess    int
	FromType    int64
	RegistryIds []int64
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
	RejectReasons uint64   `json:"reject_reasons"`
	StartAt       time.Time
	EndAt         time.Time
	RejectAt      time.Time
	FullRepoName  string // 镜像名
	Tag           string // 版本号
	Fields        []string
	JustCount     bool
	Where         string
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
	GroupID       int64
	DistinctFiled string
	RegIds        []int64
}

type SearchSubTaskParam struct {
	Ids                   []int64 // subtask id
	TaskIds               []int64
	Statuses              []int // subtask status
	LessThanRetryCount    int64
	GreaterThanRetryCount int64
	LastID                int64
	ImageID               int64
	JustCount             bool // 计计算总数
	GroupID               int64
}

type SearchStrategyParam struct {
	IsDefault  string
	StrategyID int64
	Name       string
	GetDeleted bool // 是否获取已删除的
}

type GetProjectParam struct {
	RegistryID int64
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

type SearchVulnParam struct {
	VulnKeyword     string
	PkgKeyword      string
	LanguageKeyword string
	FrameKeyword    string
	TargetKeyword   string
	UniqueVulns     []uint64
	Fields          []string
	OmitFields      []string
	Where           string
	ImageIds        []int64
	PkgName         string
	PkgVersion      string
	Sources         []string // 漏洞来源筛选
	CanFixed        string
	SeverityInt     []int64
	JustReturnCount bool
	NotReturnCount  bool
	StartID         int64
	ClassType       []string
}

type SearchVulnImageParam struct {
	ImageIds    []int64
	UniqueVulns []uint64
	Fields      []string
}

type SearchImageScanResultParam struct {
	UniqueTarget []uint64
	ImageID      int64
	LayerDigest  string
	Fields       []string
	NormalEnv    string
	Keyword      string
	Flag         uint64
	License      []string
}

func (vi *SearchImageScanResultParam) Serialize() {

}

type SearchDistinctUniqueVulnParam struct {
	ImageIds []int64
}

type VulnPkg struct {
	PkgName    string
	PkgVersion string
}

type SearchExportVulnDuplicateParam struct {
	TaskID      int64
	UniqueVulns []uint64
	UseType     int64
}

type SearchExportTensorTask struct {
	ExecuteType     []string
	TaskType        string
	Parameter       string
	Finished        string
	Failure         string
	ID              int64
	NotIds          []int64
	ExpirationDate  time.Time
	ExportHtmlReady string
}

type SearchExportTaskImageParam struct {
	TaskID   int64
	StartID  int64
	ImageIds []int64
}

type SearchHtmlVulnImageParam struct {
	TaskID      int64
	UniqueVulns []uint64
	CanFixed    string
	Severity    int
	Fields      []string
	StartID     int64
}

type GroupImageVuln struct {
	ImageID     int64 `gorm:"column:image_id"  json:"imageID"`
	SeverityInt int64 `gorm:"column:severity_int" json:"severityInt"`
	Count       int64 `gorm:"column:cnt" json:"count"`
}

type RSAListParam struct {
	Name string
}

type RegProject struct {
	RegistryID int64  `json:"registryID"`
	Project    string `json:"project"`
	Name       string `json:"name"`
	Key        string `json:"key"`
}

type GroupRegistryRepoParam struct {
	RegID          int64
	ProjectKeyword string
}

type GroupVulnSeverityParam struct {
	ImageIds []int64
}

type ScannerInstanceInfoDaoParam struct {
	ScannerInstance string
}

type SearchWebshellParam struct {
	ImageID     int64
	UUIDS       []uint64
	Search      string
	Md5         string
	LayerDigest string
	Level       []string
}
type SearchIdempotentParam struct {
	TableId   int64
	TableNAME string
}

func (s SearchIdempotentParam) Valid() error {
	if s.TableId == 0 || s.TableNAME == "" {
		return fmt.Errorf("not param SearchIdempotentParam")
	}
	return nil
}
