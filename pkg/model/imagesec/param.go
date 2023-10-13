package imagesec

import (
	"fmt"
	"strings"
	"time"

	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type SearchSecurityPolicyParam struct {
	PolicyType  string
	Keyword     string
	JustRegName bool
	Ids         []int64
	UniqueID    uint64
	UniqueIds   []uint64
	NotCount    bool
	ImageDetect *ImageDetectSearchParam
	DeployMod   []string
	Filter      *model.Filter
	Deleted     string
	Filed       []string
	Enable      []string
	Default     string
}

type UpdatePolicyParam struct {
	ID               int64
	Policy           SecurityPolicy
	CreateSnapshot   bool
	CreateDetectTask bool
}

func (vi *SearchSecurityPolicyParam) Check() error {
	// 容许查全部
	return nil
}

type SearchDetectResultParam struct {
	ImageUniqueID uint64
	DetectType    string // 检测类别，漏洞，敏感文件等
	PolicyIds     []int64
	PolicyID      int64
	Ids           []int64
	StartID       int64
	Filter        *model.Filter
	Fields        []string // 只想要的字端
}

func (vi SearchDetectResultParam) Check() error {
	if vi.ImageUniqueID <= 0 && len(vi.PolicyIds) == 0 && len(vi.Ids) == 0 && vi.PolicyID <= 0 {

		return fmt.Errorf("not get ImageID or PolicyID or ID")
	}
	if vi.DetectType == "" {
		return fmt.Errorf("not get DetectType")
	}
	return nil
}

type SearchDetectBriefParam struct {
	ImageUniqueID uint64
	NotPolicyID   int64
	PolicyID      int64
	PolicyIds     []int64
	Ids           []int64
	LastID        int64
	Filter        *model.Filter
	NeedPolicy    bool
	Fields        []string // 只想要的字端
}

func (vi SearchDetectBriefParam) Check() error {
	return nil
}

type ImageDetectSearchParam struct {
	ImageID uint64
	Flag    uint64
}

// 镜像列表的查询条件
type SearchImageParam struct {
	ImageFromType          string
	InIds                  []int64
	NotInIds               []int64
	ImageKeyword           string
	RepoKeyword            string
	TagKeyword             string
	NodeKeyword            string   // 节点名模糊搜索
	StartID                int64    // 取大于该ID的数据
	JustGetAppImage        bool     // 只取app image
	Fields                 []string // 只想要的字端
	OmitFields             []string // 不想要的字端
	LayersPrefix           string
	RegIds                 []int64 // 仓库IdD列表
	JustCount              bool
	UUIDs                  []uint32
	VulnStaticFlag         uint64 // 漏洞统计flag
	SecurityIssueFlag      uint64 // 安全问题flag
	ImageAttrFlag          uint64 // 属性flag
	AttrIntersection       string // 属性交集还是并集 and or
	IssueIntersection      string // 安全问题交集还是并集 and or
	VulnStaticIntersection string // 漏洞统计交集还是并集 and or
	ScanStatusFlag         uint64 // 扫描状态flag
	SafeAttrFlag           uint64 // 是否安全flag
	OnlineFlag             uint64 // 在线 离线
	UniqueIds              []uint64
	UniqueId               uint64
	Projects               []SearchProjectParam
	NotCount               bool
	StartTime              time.Time
	OnlineImage            string // 在线离线查询
	TrustedImage           string // 可信息镜像的查询

	Libraries     []string
	Digests       []string
	FullRepoName  string // 这里是精确匹配
	Tag           string
	RegistryIds   []int64 // 仓库Id列表
	Where         string
	ClusterKey    []string // 集群搜索
	LessHeartbeat int64    // 低于一个心跳值，用于镜像删除
}

// 镜像 DB 查询条件
type ImageDalParam struct {
	ImageFromType          string
	ImageIds               []int64
	ID                     int64
	NotUniqueId            uint64
	ImageKeyword           string
	Projects               []SearchProjectParam
	NodeKeyword            string // 节点名模糊搜索
	RegKeyword             string //  仓库搜索
	PolicyKeyword          string
	StartID                int64    // 取大于该ID的数据
	Fields                 []string // 只想要的字端
	OmitFields             []string // 不想要的字端
	UUIDs                  []uint32
	UniqueIds              []uint64
	UniqueId               uint64
	WebshellMD5            string
	MalwareMD5             string
	SensitiveMD5           string
	SecurityIssueFlag      uint64 // 安全问题: 前端传字符串统一转为 flag
	ImageAttrFlag          uint64 //
	SafeAttrFlag           uint64
	DeployActionFlag       uint64
	VulnStaticFlag         uint64 // 镜像漏洞统计
	OnlineFlag             uint64
	AttrIntersection       string // 属性交集还是并集 and or
	IssueIntersection      string // 安全问题交集还是并集 and or
	VulnStaticIntersection string // 漏洞统计交集还是并集 and or
	NotNeedCount           bool
	ClusterKey             []string // 集群搜索
	LessHeartbeat          int64    // 低于一个心跳值，用于镜像删除
	Digests                []string
	RegIds                 []int64
	VulnUniqueID           uint64
	PkgUniqueID            uint64
	LayerStrPrefix         string
	PolicyUniqueID         []string
	PolicyIntersection     string
	CheckRegDeleted        string // 检查镜像所属仓库是否删除
	DeployFlag             uint64
	StartTime              int64
	EndTime                int64

	Filter *model.Filter
}

func (vi *SearchImageParam) Check() error {
	return nil
}

type SearchProjectParam struct {
	ImageFromType string
	RegID         int64
	NodeID        int64
	Keyword       string
	ProjectName   string
}

func (vi *SearchProjectParam) Check() error {
	if err := ImageFromType(vi.ImageFromType).Check(); err != nil {
		return err
	}
	return nil
}

// 给前端返回的数据，不可变动
type GroupProject struct {
	Children []Project `json:"children"` // 第二层
	Label    string    `json:"label"`    // 用于前端展示
	Value    string    `json:"value"`    // 前端向后端传数据

	RegistryID   int64  `json:"-"`
	NodeUniqueID uint64 `json:"-"`
}

// 用于前端返回，不可更改
type Project struct {
	RegID        int64  `json:"-"`
	NodeUniqueID uint64 `json:"-"`
	Project      string `json:"-"`
	Label        string `json:"label"` // 用于前端展示
	Value        string `json:"value"` // 前端向后端传数据
}

type CreateMalwareToImageParam struct {
	ImageUniqueID uint64
	Data          []*MalwareToImage
}

func (vi *CreateMalwareToImageParam) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.ImageUniqueID <= 0 {
		return fmt.Errorf("not get ImageUniqueID")
	}

	for i := range vi.Data {
		vi.Data[i].ImageUniqueID = vi.ImageUniqueID
		vi.Data[i].UniqueID = vi.Data[i].GenUniqueID()
	}

	return nil
}

type CreateSensitiveToImageParam struct {
	ImageUniqueID uint64
	Data          []*SensitiveToImage
}

func (vi *CreateSensitiveToImageParam) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.ImageUniqueID <= 0 {
		return fmt.Errorf("not get ImageID")
	}

	for i := range vi.Data {
		vi.Data[i].ImageUniqueID = vi.ImageUniqueID
		vi.Data[i].UniqueID = vi.Data[i].GenUniqueID()
	}

	return nil
}

type CreatePkgToImageParam struct {
	ImageUniqueID uint64
	Data          []*PkgToImage
}

func (vi *CreatePkgToImageParam) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.ImageUniqueID <= 0 {
		return fmt.Errorf("not get ImageUniqueID")
	}

	for i := range vi.Data {
		vi.Data[i].ImageUniqueID = vi.ImageUniqueID
		vi.Data[i].UniqueID = vi.Data[i].GenUniqueID()
	}

	return nil
}

type CreateVulnToImageParam struct {
	ImageUniqueID uint64
	Data          []*VulnToImage
}

func (vi *CreateVulnToImageParam) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.ImageUniqueID <= 0 {
		return fmt.Errorf("not get ImageUniqueID")
	}

	for i := range vi.Data {
		vi.Data[i].ImageUniqueID = vi.ImageUniqueID
		vi.Data[i].UniqueID = vi.Data[i].GenUniqueID()
	}

	return nil
}

type CreateWebshellToImageParam struct {
	ImageUniqueID uint64
	Data          []*WebshellToImage
}

func (vi *CreateWebshellToImageParam) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.ImageUniqueID <= 0 {
		return fmt.Errorf("not get ImageUniqueID")
	}

	for i := range vi.Data {
		vi.Data[i].ImageUniqueID = vi.ImageUniqueID
		vi.Data[i].UniqueID = vi.Data[i].GenUniqueID()
	}

	return nil
}

type SearchIssueImageParam struct {
	TargetUniqueID uint64
	Filter         *model.Filter
}

type CreateLicenseToImageParam struct {
	ImageUniqueID uint64
	Data          []*LicenseToImage
}

func (vi *CreateLicenseToImageParam) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.ImageUniqueID <= 0 {
		return fmt.Errorf("not get ImageUniqueID")
	}

	for i := range vi.Data {
		vi.Data[i].ImageUniqueID = vi.ImageUniqueID
		vi.Data[i].UniqueID = vi.Data[i].GenUniqueID()
	}

	return nil
}

type UpdateImageParam struct {
	ID        int64
	UniqueID  uint64
	UniqueIds []uint64

	Updater map[string]interface{}
	Where   string
}

func (vi UpdateImageParam) Check() error {
	if vi.ID <= 0 && vi.UniqueID <= 0 && len(vi.UniqueIds) == 0 {
		return fmt.Errorf("not get ID or UniqueID")
	}
	if len(vi.Updater) == 0 {
		return fmt.Errorf("not get updater")
	}
	return nil
}

type UpdateScanVersionParam struct {
	ID       int64
	UniqueID uint64
	Updater  map[string]interface{}
}

func (vi UpdateScanVersionParam) Check() error {
	if vi.ID <= 0 && vi.UniqueID <= 0 {
		return fmt.Errorf("not get ID or UniqueID")
	}
	if len(vi.Updater) == 0 {
		return fmt.Errorf("not get updater")
	}
	return nil
}

type UpdateSecurityPolicyParam struct {
	ID            int64
	Updater       map[string]interface{}
	UpdateDefault bool
}

type UpdateTaskParam struct {
	ID      int64
	Updater map[string]interface{}
	Where   string
}

func (vi UpdateTaskParam) Check() error {
	if vi.ID <= 0 && vi.Where == "" {
		return fmt.Errorf("not get where condition")
	}
	if len(vi.Updater) == 0 {
		return fmt.Errorf("not get updater")
	}
	return nil
}

type SearchTaskParam struct {
	SubtaskID        int64
	TaskID           int64
	SubtaskIds       []int64
	TaskIds          []int64
	StartID          int64
	ImageUniqueID    uint64
	JustCount        bool
	ImageFromType    string
	PolicyID         int64
	Finished         string
	Started          string
	ScanType         []string // 扫描类型
	ScanStatus       []int64
	ScanStatusStr    []string
	NotScanStatus    []int64
	NotScanStatusStr []string
	ClusterKey       string
	NodeNameKeyword  string
	NodeUniqueID     uint64
	Priority         int64
	ScanSubtaskIds   []int64
	Where            string
	Fields           []string // 只想要的字端
	IsSearchSubtask  bool
	Filter           *model.Filter
}

func (vi *SearchTaskParam) Serialize() {
	for i := range vi.ScanStatusStr {
		vi.ScanStatus = append(vi.ScanStatus, ScanStatusStrToInt(vi.ScanStatusStr[i]))
		if vi.ScanStatusStr[i] == TaskStatusInprogressStr {
			vi.ScanStatus = append(vi.ScanStatus, TaskStatusSendFinished, TaskStatusScanFinished, TaskStatusInprogress)
		}
		if vi.ScanStatusStr[i] == TaskStatusPendingStr {
			if vi.IsSearchSubtask {
				vi.ScanStatus = append(vi.ScanStatus, TaskStatusPause, TaskStatusPending)
			}
		}
		if vi.ScanStatusStr[i] == TaskStatusFailedStr && vi.IsSearchSubtask {
			vi.ScanStatus = append(vi.ScanStatus, TaskStatusTerminate, TaskStatusFailed)
		}
	}

	for i := range vi.NotScanStatusStr {
		vi.NotScanStatus = append(vi.NotScanStatus, ScanStatusStrToInt(vi.NotScanStatusStr[i]))
		if vi.NotScanStatusStr[i] == TaskStatusInprogressStr {
			vi.NotScanStatus = append(vi.NotScanStatus, TaskStatusSendFinished, TaskStatusScanFinished, TaskStatusInprogress)
		}
		if vi.NotScanStatusStr[i] == TaskStatusPendingStr {
			if vi.IsSearchSubtask {
				vi.NotScanStatus = append(vi.NotScanStatus, TaskStatusPause, TaskStatusPending)
			}
		}

		if vi.NotScanStatusStr[i] == TaskStatusFailedStr && vi.IsSearchSubtask {
			vi.NotScanStatus = append(vi.ScanStatus, TaskStatusTerminate, TaskStatusFailed)
		}
	}

	vi.ScanStatus = util.DuplicateInt64Slice(vi.ScanStatus)
	vi.NotScanStatus = util.DuplicateInt64Slice(vi.NotScanStatus)
	vi.NotScanStatusStr = nil
	vi.ScanStatusStr = nil
}

func (vi UpdateSecurityPolicyParam) Check() error {
	if vi.ID <= 0 {
		return fmt.Errorf("not get ID")
	}
	if len(vi.Updater) == 0 {
		return fmt.Errorf("not get updater")
	}
	return nil
}

type CreateDetectResultParam struct {
	ImageUniqueID uint64
	PolicyID      int64
	DetectType    string
	Data          []*ImageDetectResult
}

func (vi *CreateDetectResultParam) Check() error {
	if vi == nil {
		return fmt.Errorf("not get model")
	}
	if vi.ImageUniqueID <= 0 {
		return fmt.Errorf("not get ImageID")
	}
	return nil
}

type SearchScanVersionParam struct {
	UniqueID uint64
	ID       int64
	Enable   string
	Keyword  string
	DBType   string
	Filter   *model.Filter
}

type ApiSearchVulnParam struct {
	ImageFromType    string
	PkgKeyword       string
	LanguageKeyword  string
	TargetKeyword    string
	FrameKeyword     string
	VulnKeyword      string // 漏洞名搜索
	VulnUniqueIds    []uint64
	LanguageName     string
	LanguagePath     string
	Fields           []string
	OmitFields       []string
	PkgUniqueID      uint64 // 软件ID
	VulnUniqueID     uint64 // 漏洞ID
	ImageID          int64
	ImageUniqueID    uint64   // 镜像ID
	ImageLayerDigest string   // 镜像层级
	CanFixed         []string // 是否可修复筛选
	SeverityInt      int64    // 漏洞级别筛选
	SeverityStr      []string // 漏洞级别筛选
	AttackPath       []string
	NeedKernel       []string
	VulnIds          []int64
	VulnId           int64
	ClassType        []string
	StartID          int64
	OnlineImageVuln  string
	JustReturnCount  bool
	NotReturnCount   bool

	Filter *model.Filter
}

type SearchVulnPkgParam struct {
	VulnName         string
	VulnNameUniqueID uint64
	VulnUniqueID     uint64
}

type CreateVulnParam struct {
	OnlineVuln bool
	Data       []*Vuln
}

type SearchVulnDalParam struct {
	ImageFromType     string
	PkgKeyword        string
	LanguageKeyword   string
	LanguageName      string
	LanguagePath      string
	VulnTargetKeyword string
	TargetKeyword     string
	FrameKeyword      string
	VulnKeyword       string // 漏洞名搜索
	VulnUniqueIds     []uint64
	VulnNames         []string
	Fields            []string
	OmitFields        []string
	PkgUniqueID       uint64 // 软件ID
	VulnUniqueID      uint64 // 漏洞ID
	ImageID           int64
	ImageUniqueID     uint64  // 镜像ID
	ImageLayerDigest  string  // 镜像层级
	SeverityInt       []int64 // 漏洞级别筛选
	VulnIds           []int64
	VulnId            int64
	StartID           int64
	NeedKernelFlag    uint64
	CanFixedFlag      uint64
	OnlineVuln        bool
	ClassTypeFlag     uint64
	AttackPathFlag    uint64

	Filter          *model.Filter
	JustReturnCount bool
	NotReturnCount  bool
}

func (vi ApiSearchVulnParam) ToDaoSearchVulnParam() SearchVulnDalParam {
	param := SearchVulnDalParam{
		OnlineVuln:        vi.OnlineImageVuln == consts.TrueString,
		ImageFromType:     vi.ImageFromType,
		PkgKeyword:        vi.PkgKeyword,
		LanguageKeyword:   vi.LanguageKeyword,
		VulnTargetKeyword: vi.TargetKeyword,
		FrameKeyword:      vi.FrameKeyword,
		VulnKeyword:       vi.VulnKeyword,
		VulnUniqueIds:     vi.VulnUniqueIds,
		Fields:            vi.Fields,
		OmitFields:        vi.OmitFields,
		PkgUniqueID:       vi.PkgUniqueID,
		VulnUniqueID:      vi.VulnUniqueID,
		ImageUniqueID:     vi.ImageUniqueID,
		ImageLayerDigest:  vi.ImageLayerDigest,
		VulnIds:           vi.VulnIds,
		StartID:           vi.StartID,
		LanguageName:      vi.LanguageName,
		LanguagePath:      vi.LanguagePath,
		Filter:            vi.Filter,
		JustReturnCount:   vi.JustReturnCount,
		NotReturnCount:    vi.NotReturnCount,
	}
	for i := range vi.SeverityStr {
		param.SeverityInt = append(param.SeverityInt, GetSeverityInt(vi.SeverityStr[i]))
	}
	var classFlag uint64
	for i := range vi.ClassType {
		switch vi.ClassType[i] {
		case report.ClassLangPkg:
			classFlag = util.SetBit1(classFlag, VulnFlagClassLangPkg)
		case report.ClassOSPkg:
			classFlag = util.SetBit1(classFlag, VulnFlagClassOSPkg)
		case report.ClassConfig:
			classFlag = util.SetBit1(classFlag, VulnFlagClassConfig)
		}
	}
	param.ClassTypeFlag = classFlag

	if util.ExistInStringSlice(vi.CanFixed, TrueString) && util.ExistInStringSlice(vi.CanFixed, FalseString) {
		vi.CanFixed = make([]string, 0)
	}
	if util.ExistInStringSlice(vi.NeedKernel, TrueString) && util.ExistInStringSlice(vi.NeedKernel, FalseString) {
		vi.NeedKernel = make([]string, 0)
	}

	var kernelFlag uint64
	for i := range vi.NeedKernel {
		fi := vi.NeedKernel[i]
		switch fi {
		case TrueString:
			kernelFlag = util.SetBit1(kernelFlag, VulnFlagKernel)
		case FalseString:
			kernelFlag = util.SetBit1(kernelFlag, VulnFlagNotKernel)
		}
	}
	param.NeedKernelFlag = kernelFlag

	var attackPathFlag uint64
	for i := range vi.AttackPath {
		at := vi.AttackPath[i]
		switch strings.ToUpper(at) {
		case "L":
			attackPathFlag = util.SetBit1(attackPathFlag, CVSSFlagAVL)
		case "N":
			attackPathFlag = util.SetBit1(attackPathFlag, CVSSFlagAVN)
		case "P":
			attackPathFlag = util.SetBit1(attackPathFlag, CVSSFlagAVP)
		case "A":
			attackPathFlag = util.SetBit1(attackPathFlag, CVSSFlagAVA)
			attackPathFlag = util.SetBit1(attackPathFlag, CVSSFlagAVEmpty)
		}
	}
	param.AttackPathFlag = attackPathFlag

	var canFixFlag uint64
	for i := range vi.CanFixed {
		fi := vi.CanFixed[i]
		switch fi {
		case TrueString:
			canFixFlag = util.SetBit1(canFixFlag, VulnFlagHasFixed)
		case FalseString:
			canFixFlag = util.SetBit1(canFixFlag, VulnFlagNoFixed)
		}
	}
	param.CanFixedFlag = canFixFlag

	return param
}

type SearchNodeInfoParam struct {
	Ids       []int64
	UniqueIds []uint64
	Keyword   string
	Filter    *model.Filter
}

type SearchSensitiveRuleParam struct {
	RuleType  string
	IsDefault string
	Enable    string
	Default   string
	Filed     []string
	Filter    *model.Filter
}

type SearchDataMigrateParam struct {
	SoftVersion string
	Model       string
	Filter      *model.Filter
}

type ImageGroupParam struct {
	ImageFromType string
}

type ImageFlagGroup struct {
	Flag  uint64 `gorm:"column:flag" json:"flag"`
	Count int64  `gorm:"column:cnt" json:"count"`
}
type CreateSyncTaskParam struct {
	RegID           int64
	ScannerInstance string
	SyncType        SyncType
}

type RegSyncStatus struct {
	Status bool  `json:"status"` // true表示正在同步中
	RegID  int64 `json:"registryID"`
}

type RegSyncStatusReport struct {
	Status    bool   `json:"status"` // true表示正在同步中
	RegID     int64  `json:"registryID"`
	SyncType  string `json:"syncType"`
	TaskID    int64  `json:"taskID"`
	StatusStr string `json:"statusStr"`
	Msg       string `json:"msg"`
}

type SearchResourceParam struct {
	ImageID       int64
	ImageUniqueID uint64
	Keyword       string
	ImageUUID     uint32
	ImageUUIDs    []uint32
	VulnUniqueID  uint64
	PkgUniqueID   uint64
	WebshellMD5   string
	MalwareMD5    string
	SensitiveMD5  string
	Fields        []string
	Filter        *model.Filter
}

type SearchDeployWhiteImageParam struct {
	ImageKeyword    string `json:"imageKeyword"`
	ExpirationStart int64  `json:"expirationStart"`
	ExpirationEnd   int64  `json:"expirationEnd"`
	Filter          *model.Filter
}

type DeployDeployOverviewParam struct {
	Graph string

	// Day7   string `json:"day7"`
	// Day30  string `json:"day30"`
	// Hour24 string `json:"hour24"`
}
