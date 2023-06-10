package imagesec

import (
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type SearchSecurityPolicyParam struct {
	Keyword     string
	Ids         []int64
	NotCount    bool
	ImageDetect *ImageDetectSearchParam
	Filter      *model.Filter
	Deleted     string
	Default     string
}

type SearchDetectResultParam struct {
	ImageUniqueID uint64
	DetectType    string // 检测类别，漏洞，敏感文件等
	PolicyIds     []int64
	Ids           []int64
	StartID       int64
	Filter        *model.Filter
	Fields        []string // 只想要的字端
}

func (vi SearchDetectResultParam) Check() error {
	if vi.ImageUniqueID <= 0 && len(vi.PolicyIds) == 0 && len(vi.Ids) == 0 {
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
	RegIds                 []int64 // 仓库Id列表
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
	ImageID                int64
	Projects               []SearchProjectParam
	NotCount               bool

	OnlineImage  string // 在线离线查询
	TrustedImage string // 可信息镜像的查询

	Libraries     []string
	Digests       []string
	FullRepoName  string // 这里是精确匹配
	Tag           string
	RegistryIds   []int64 // 仓库Id列表
	Where         string
	ClusterKey    []string // 集群搜索
	LessHeartbeat int64    // 低于一个心跳值，用于镜像删除
}

// 镜像 DB 查询条件 (当前只是节点镜像使用，后期统一)
type NodeImageDalParam struct {
	ImageFromType string
	InIds         []int64
	NotInIds      []int64
	ImageKeyword  string
	Projects      []SearchProjectParam
	NodeKeyword   string   // 节点名模糊搜索
	StartID       int64    // 取大于该ID的数据
	Fields        []string // 只想要的字端
	OmitFields    []string // 不想要的字端
	UUIDs         []uint32
	AndFlag       uint64
	OrFlag        uint64
	UniqueIds     []uint64
	UniqueId      uint64
	WebshellMD5   string

	ImageID       int64
	ClusterKey    []string // 集群搜索
	LessHeartbeat int64    // 低于一个心跳值，用于镜像删除
	Digests       []string
	RegistryIds   []int64
	Filter        *model.Filter
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
type GroupProjectResponse struct {
	Projects []Project `json:"projects"` // 第二层
	Name     string    `json:"name"`     // 用于前端展示
	Key      string    `json:"key"`      // 前端向后端传数据
}

// 用于前端返回，不可更改
type Project struct {
	RegistryID   int64  `json:"-"`
	NodeUniqueID uint64 `json:"-"`
	Project      string `json:"-"`
	Name         string `json:"name"` // project name
	Key          string `json:"key"`  // post to backend
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

type SearchIssueToImageParam struct {
	TableName string
	Res       []interface{}
	ImageIds  []uint64
	UniqueIds []uint64
	Count     int64
}

func (vi *SearchIssueToImageParam) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if vi.TableName == "" {
		return fmt.Errorf("not get TableName")
	}
	if vi.Res == nil {
		return fmt.Errorf("not get Res")
	}
	if len(vi.ImageIds) == 0 && len(vi.UniqueIds) == 0 {
		return fmt.Errorf("not get ImageIds or VulnUniqueIds")
	}

	return nil
}

type UpdateImageParam struct {
	ID       int64
	UniqueID uint64
	Updater  map[string]interface{}
}

func (vi UpdateImageParam) Check() error {
	if vi.ID <= 0 && vi.UniqueID <= 0 {
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
	ID      int64
	Updater map[string]interface{}
}

type UpdateTaskParam struct {
	ID      int64
	Updater map[string]interface{}
	Where   string
}

func (vi UpdateTaskParam) Check() error {
	if vi.ID <= 0 {
		return fmt.Errorf("not get ID")
	}
	if len(vi.Updater) == 0 {
		return fmt.Errorf("not get updater")
	}
	return nil
}

type SearchTaskParam struct {
	SubtaskID        int64
	TaskID           int64
	StartID          int64
	ImageUniqueID    uint64
	JustCount        bool
	ImageFromType    string
	PolicyID         int64
	Finished         string
	Started          string
	ScanType         []int64 // 扫描类型
	ScanStatus       []int64
	ScanStatusStr    []string
	NotScanStatus    []int64
	NotScanStatusStr []string
	NodeClusterKey   string
	NodeNameKeyword  string
	NodeUniqueID     uint64
	Where            string
	Filter           *model.Filter
	Fields           []string // 只想要的字端
	SearchSubtask    bool
}

func (vi *SearchTaskParam) Serialize() {
	for i := range vi.ScanStatusStr {
		vi.ScanStatus = append(vi.ScanStatus, ScanStatusStrToInt(vi.ScanStatusStr[i]))
		if vi.ScanStatusStr[i] == TaskStatusInprogressStr {
			vi.ScanStatus = append(vi.ScanStatus, TaskStatusSendFinished, TaskStatusScanFinished)
		}
		if vi.ScanStatusStr[i] == TaskStatusPendingStr {
			if vi.SearchSubtask {
				vi.ScanStatus = append(vi.ScanStatus, TaskStatusPause)
			}
		}
		if vi.ScanStatusStr[i] == TaskStatusFailedStr && vi.SearchSubtask {
			vi.ScanStatus = append(vi.ScanStatus, TaskStatusTerminate)
		}
	}

	for i := range vi.NotScanStatusStr {
		vi.NotScanStatus = append(vi.NotScanStatus, ScanStatusStrToInt(vi.NotScanStatusStr[i]))
		if vi.NotScanStatusStr[i] == TaskStatusInprogressStr {
			vi.NotScanStatus = append(vi.NotScanStatus, TaskStatusSendFinished, TaskStatusScanFinished)
		}
		if vi.NotScanStatusStr[i] == TaskStatusPendingStr {
			if vi.SearchSubtask {
				vi.NotScanStatus = append(vi.NotScanStatus, TaskStatusPause)
			}
		}

		if vi.NotScanStatusStr[i] == TaskStatusFailedStr && vi.SearchSubtask {
			vi.NotScanStatus = append(vi.ScanStatus, TaskStatusTerminate)
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
	if vi.PolicyID <= 0 {
		return fmt.Errorf("not get PolicyID")
	}
	return nil
}

type SearchScanVersionParam struct {
	UniqueID uint64
	ID       int64
	Enable   string
	Keyword  string
	Filter   *model.Filter
}

// 以前的代码中，关于漏洞的搜索条件的struct还有其他几处，后期统一整合到这个结构体中
type ApiSearchVulnParam struct {
	ImageFromType     string
	PkgKeyword        string
	LanguageKeyword   string
	VulnTargetKeyword string
	FrameKeyword      string
	VulnKeyword       string // 漏洞名搜索
	VulnUniqueIds     []uint64
	Fields            []string
	OmitFields        []string
	PkgUniqueID       uint64 // 软件ID
	VulnUniqueID      uint64 // 漏洞ID
	ImageID           int64
	ImageUniqueID     uint64   // 镜像ID
	ImageLayerDigest  string   // 镜像层级
	PkgName           string   // 软件包来源
	PkgVersion        string   // 软件包版本
	CanFixed          string   // 是否可修复筛选
	SeverityInt       []int64  // 漏洞级别筛选
	SeverityStr       []string // 漏洞级别筛选
	AttackPath        []string
	VulnClass         []string
	NeedKernel        string
	VulnIds           []int64
	VulnId            int64
	ClassType         []string
	StartID           int64
	Filter            *model.Filter
	OnlineImageVuln   string
	JustReturnCount   bool
	NotReturnCount    bool
}

type DaoSearchVulnParam struct {
	ImageFromType     string
	PkgKeyword        string
	LanguageKeyword   string
	VulnTargetKeyword string
	FrameKeyword      string
	VulnKeyword       string // 漏洞名搜索
	VulnUniqueIds     []uint64
	Fields            []string
	OmitFields        []string
	PkgUniqueID       uint64 // 软件ID
	VulnUniqueID      uint64 // 漏洞ID
	ImageID           int64
	ImageUniqueID     uint64   // 镜像ID
	ImageLayerDigest  string   // 镜像层级
	PkgName           string   // 软件包来源
	PkgVersion        string   // 软件包版本
	CanFixed          string   // 是否可修复筛选
	SeverityInt       []int64  // 漏洞级别筛选
	SeverityStr       []string // 漏洞级别筛选
	AttackPath        []string
	VulnClass         []string
	NeedKernel        string
	VulnIds           []int64
	ClassType         []string
	StartID           int64
	Flag              uint64

	Filter          *model.Filter
	OnlineImageVuln string
	JustReturnCount bool
	NotReturnCount  bool
}

func (vi ApiSearchVulnParam) ToDaoSearchVulnParam() DaoSearchVulnParam {
	param := DaoSearchVulnParam{
		ImageFromType:     vi.ImageFromType,
		PkgKeyword:        vi.PkgKeyword,
		LanguageKeyword:   vi.LanguageKeyword,
		VulnTargetKeyword: vi.VulnTargetKeyword,
		FrameKeyword:      vi.FrameKeyword,
		VulnKeyword:       vi.VulnKeyword,
		VulnUniqueIds:     vi.VulnUniqueIds,
		Fields:            vi.Fields,
		OmitFields:        vi.OmitFields,
		PkgUniqueID:       vi.PkgUniqueID,
		VulnUniqueID:      vi.VulnUniqueID,
		ImageID:           vi.ImageID,
		ImageUniqueID:     vi.ImageUniqueID,
		ImageLayerDigest:  vi.ImageLayerDigest,
		PkgName:           vi.PkgName,
		PkgVersion:        vi.PkgVersion,
		SeverityStr:       nil,
		AttackPath:        nil,
		VulnClass:         nil,
		NeedKernel:        "",
		VulnIds:           vi.VulnIds,
		ClassType:         nil,
		StartID:           vi.StartID,
		Flag:              0,
		Filter:            vi.Filter,
		OnlineImageVuln:   vi.OnlineImageVuln,
		JustReturnCount:   vi.JustReturnCount,
		NotReturnCount:    vi.NotReturnCount,
	}
	return param
}

type SearchNodeInfoParam struct {
	Ids       []int64
	UniqueIds []uint64
	Keyword   string
	Filter    *model.Filter
}
