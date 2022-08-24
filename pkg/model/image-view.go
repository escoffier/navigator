package model

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"
	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 镜像属性
type ImageAttrParam struct {
	Trusted      string `json:"trusted"`      // 是否是可信镜像：是："true"，否："false"
	ImageType    string `json:"imageType"`    // 镜像类型,基础镜像："base",应用镜像："app"
	HasFixedVuln string `json:"hasFixedVuln"` // 是否包含可修复漏洞: 是:"true",否："false"
	Reinforced   string `json:"reinforced"`   // 镜像是否已固:是："true",否："false"
	// PrivilegedBoot string `json:"privilegedBoot"` // 是否特权启动：是："true",否："false"
}

// 生成属性的flag
func (sp *ImageListParam) GenAttrFlag() uint64 {
	var flag uint64
	if sp.ImageAttr.ImageType == BaseImageTypeString {
		flag = 1<<FlagBaseImage + flag
	}
	if sp.ImageAttr.HasFixedVuln == TrueString {
		flag = 1<<FlagHasFixedVuln + flag
	}
	if sp.ImageAttr.Reinforced == TrueString {
		flag = 1<<FlagReinforced + flag
	}

	return flag
}

// 生成属性的flag
func (sp *ImageListParam) GenAttrFlagList() []uint64 {
	flag := make([]uint64, 0)
	if sp.ImageAttr.ImageType == BaseImageTypeString {
		flag = append(flag, FlagBaseImage)
	}
	if sp.ImageAttr.HasFixedVuln == TrueString {
		flag = append(flag, FlagHasFixedVuln)
	}
	if sp.ImageAttr.Reinforced == TrueString {
		flag = append(flag, FlagReinforced)
	}

	return flag
}

// 生成安全问题的flag
func (sp *ImageListParam) GenSecurityIssueFlag() uint64 {
	var flag uint64

	kinds := util.DeDuplicationUint64Slice(sp.SecurityIssue)
	for _, kind := range kinds {
		for _, imageFlag := range GetAllFlag() {
			if kind == imageFlag {
				flag = 1<<imageFlag + flag
			}
		}
	}

	return flag
}

// 镜像属性
type ImageAttrResponse struct {
	Trusted      bool   `json:"trusted"`      // 是否是可信镜像：是：true，否：false
	ImageType    string `json:"imageType"`    // 镜像类型,基础镜像："base",应用镜像："app"
	HasFixedVuln bool   `json:"hasFixedVuln"` // 是否包含可修复漏洞: 是:true,否：false
	Reinforced   bool   `json:"reinforced"`   // 镜像是否已固:是：true,否：false
}

type ImageListParam struct {
	Online            string         `json:"online"`            // 在线 "true",离线："false"
	Keyword           string         `json:"keyword"`           // 关键字搜索
	FromType          string         `json:"fromType"`          // 节点镜像："node" 仓库镜像:"registry"
	SecurityIssue     []uint64       `json:"securityIssue"`     // 安全问题: 前端传字符串
	ImageAttr         ImageAttrParam `json:"-"`                 // 镜像属性
	ImageAttrView     []string       `json:"imageAttr"`         // 镜像属性,前端以列表的方式传递
	ImageIds          []int64        `json:"imageIds"`          // 镜像ID列表
	ScanStatus        []string       `json:"scanStatus"`        // 扫描状态
	ScanStatusFlag    uint64         `json:"-"`                 // 扫描状态(对应数据库中的数据)
	JustReturnImage   bool           `json:"justReturnImage"`   // 只返回镜像信息
	ReturnMalicious   bool           `json:"returnMalicious"`   // 是否返回恶义文件
	UUIDs             []uint32       `json:"uuids"`             // 镜像uuid
	Projects          []string       `json:"projects"`          // 仓库和repo的筛选
	NodeHostname      string         `json:"nodeHostname"`      // 节点名精确匹配
	AttrIntersection  string         `json:"attrIntersection"`  // 属性交集还是并集 and or
	IssueIntersection string         `json:"issueIntersection"` // 安全问题交集还是并集 and or

	//  以下是镜像扫描时的参数
	ImageScanTaskInfo ImageScanTaskInfo `json:"imageScanTaskInfo"`
	StartID           int64             `json:"startID"`

	// 后端处理数据的中间结构
	RegistryIds []int64  `json:"-"`
	Repos       []Repo   `json:"-"`
	Fields      []string `json:"fields"`
}

type ImageScanTaskInfo struct {
	Scope        int    `json:"scope"`
	TriggerType  int    `json:"triggerType"`  // 扫描类型
	StrategyID   int64  `json:"strategyId"`   // 扫描策略ID
	StrategyName string `json:"strategyName"` // 扫描策略名字 用于openapi
	Operator     string `json:"operator"`     // 操作人
}

type Repo struct {
	RegistryID int64  `json:"registryID"`
	RepoName   string `json:"repoName"`
}

func (sp *ImageListParam) GetFromType() int64 {
	switch sp.FromType {
	case ImageFromRegistry:
		return UserRegistry
	case ImageFromNode:
		return NodeBuffRegistry
	default:
		return 0
	}
}

func (sp *ImageListParam) Deserialize() {
	// 如果是id筛选
	if len(sp.ImageIds) > 0 {
		sp.Online = ""
		sp.Keyword = ""
		sp.SecurityIssue = nil
		sp.ImageAttrView = nil
		sp.ScanStatus = nil
		sp.ScanStatusFlag = 0
		sp.UUIDs = nil
		sp.Projects = nil
		sp.NodeHostname = ""
		return
	}

	if sp.AttrIntersection == "" {
		sp.AttrIntersection = AndString
	}
	if sp.IssueIntersection == "" {
		sp.IssueIntersection = AndString
	}

	repos := make([]Repo, 0)
	for _, v := range sp.Projects {
		split := strings.Split(v, ",")
		// 说明只是registryID的筛选
		if len(split) == 1 && split[0] != "" {
			regID, err := strconv.ParseInt(split[0], 10, 64)
			if err != nil {
				logging.Get().Error().Str("project", v).Msg("project parameter incorrect")
				continue
			}
			repos = append(repos, Repo{RegistryID: regID})
		}
		if len(split) == 2 && split[0] != "" && split[1] != "" {
			regID, err := strconv.ParseInt(split[0], 10, 64)
			if err != nil {
				logging.Get().Error().Str("project", v).Msg("project parameter incorrect")
				continue
			}
			repos = append(repos, Repo{RegistryID: regID, RepoName: split[1]})
		}
	}
	sp.Repos = repos

	// 如果可信和非可信都在选项中，就移出
	if util.ContainsString(sp.ImageAttrView, TrustedString) && util.ContainsString(sp.ImageAttrView, UnTrustedString) {
		attrView := make([]string, 0)
		for i := range sp.ImageAttrView {
			if !util.ContainsString([]string{TrustedString, UnTrustedString}, sp.ImageAttrView[i]) {
				attrView = append(attrView, sp.ImageAttrView[i])
			}
		}
		sp.ImageAttrView = attrView
	}

	for i := range sp.ImageAttrView {
		switch sp.ImageAttrView[i] {
		case AppImageTypeString:
			sp.ImageAttr.ImageType = AppImageTypeString
		case BaseImageTypeString:
			sp.ImageAttr.ImageType = BaseImageTypeString
		case TrustedString:
			sp.ImageAttr.Trusted = TrueString
		case UnTrustedString:
			sp.ImageAttr.Trusted = FalseString
		case HasFixedVulnString:
			sp.ImageAttr.HasFixedVuln = TrueString
		case ReinforcedString:
			sp.ImageAttr.Reinforced = TrueString
		}
	}

	// 如果只有一个条件，取交集或者并集是一样的，统一设置成交集，便于处理
	if len(sp.ImageAttrView) == 1 {
		sp.AttrIntersection = AndString
	}

	var scanStatusFlag uint64
	for i := range sp.ScanStatus {
		scanStatusFlag = util.SetBit1(scanStatusFlag, GetSubTaskScanStatusFlag(sp.ScanStatus[i]))
	}
	sp.ScanStatusFlag = scanStatusFlag
}

// image(subtask) scan status
const (
	ImageScanUnknown    = "unknown"
	ImageScanPending    = "pending"
	ImageScanInProgress = "inprogress"
	ImageScanSuccess    = "success"
	ImageScanFailed     = "failed"
	ImageNotScan        = "notscan"
)

func GetSubTaskScanStatusFlag(status string) uint64 {
	switch status {
	case ImageScanPending:
		return FlagImageScanPending
	case ImageScanInProgress:
		return FlagImageScanInProgress
	case ImageScanSuccess:
		return FlagImageScanSuccess
	case ImageScanFailed:
		return FlagImageScanFailed
	case ImageNotScan:
		return FlagImageNotScan
	case ImageScanUnknown:
		return FlagImageScanUnknown
	default:
		return 0
	}
}

func GetSubTaskStatusFlagString(flag uint64) string {
	for _, v := range GetScanStatusFlag() {
		if !ExistFlag(flag, v) {
			continue
		}
		switch v {
		case FlagImageScanUnknown:
			return ImageScanUnknown
		case FlagImageScanPending:
			return ImageScanPending
		case FlagImageScanInProgress:
			return ImageScanInProgress
		case FlagImageScanSuccess:
			return ImageScanSuccess
		case FlagImageScanFailed:
			return ImageScanFailed
		case FlagImageNotScan:
			return ImageNotScan
		default:
			return ""
		}
	}
	return ""
}

func GetSubTaskScanStatusString(status uint8) string {
	switch status {
	case FlagImageScanUnknown:
		return ImageScanUnknown
	case FlagImageScanPending:
		return ImageScanPending
	case FlagImageScanInProgress:
		return ImageScanInProgress
	case FlagImageScanSuccess:
		return ImageScanSuccess
	case FlagImageScanFailed:
		return ImageScanFailed
	case FlagImageNotScan:
		return ImageNotScan
	default:
		return ""
	}
}

type SecurityIssue struct {
	Value int64  `json:"value"` // 安全问题的ID
	Label string `json:"label"` // 安全问题
	Info  string `json:"info"`  // 详细信息
}

type ImageListResponse struct {
	ID                int64             `json:"id"`
	Digest            string            `json:"digest"`
	NodeIP            string            `json:"nodeIP"`
	ScanStatus        string            `json:"scanStatus"`
	Online            bool              `json:"online"`        // 在线 "true",离线："false"
	FromType          string            `json:"fromType"`      // 节点镜像："node" 仓库镜像:"registry"
	SecurityIssue     []SecurityIssue   `json:"securityIssue"` // 安全问题
	ImageAttr         ImageAttrResponse `json:"imageAttr"`     // 镜像属性
	UUID              uint32            `json:"uuid"`          // 镜像uuid
	LastScanAt        int64             `json:"lastScanAt"`    // 扫描完成时间戳(单位毫秒)
	FullRepoName      string            `json:"fullRepoName"`
	Tag               string            `json:"tag"`
	RiskScore         float64           `json:"riskScore"` // 镜像评分
	RegistryID        int64             `json:"registryId"`
	RegistryName      string            `json:"registryName"`
	RegistryUrl       string            `json:"registryUrl"`
	RegistryDeletedAt int64             `json:"registryDeletedAt"`
	Os                string            `json:"os"`
	NodeHostname      string            `json:"nodeHostname"`
	Flag              uint64            `json:"flag"`
	Project           string            `json:"project"`
	LastSyncAt        int64             `json:"lastSyncAt"` // 上次同步时间(单位：毫秒)
	Malicious         []VirusInfo       `json:"malicious"`  // 恶义文件

	Registry    *Registry  `json:"-"`
	Subtasks    *SubTask   `json:"-"`
	ScanInfo    *ScanImage `json:"-"`
	UniqueImage uint64     `json:"uniqueImage;string"`
}

func (ir *ImageListResponse) GetImageName() string {
	// 把仓库信息加上
	if ir.Registry != nil {
		ir.RegistryName = ir.Registry.Name
		ir.RegistryUrl = ir.Registry.Url
		ir.RegistryDeletedAt = ir.Registry.DeletedAt
		ir.LastSyncAt = ir.Registry.LastSyncAt
	}
	return fmt.Sprintf("(%s)%s/%s:%s", ir.RegistryName, ir.RegistryUrl, ir.FullRepoName, ir.Tag)
}

func (ir *ImageListResponse) Deserialize() {
	// 扫描状态
	ir.ScanStatus = GetSubTaskStatusFlagString(ir.Flag)
	if ir.Subtasks != nil {
		if ir.Subtasks.FinishedAt != nil && !ir.Subtasks.FinishedAt.IsZero() {
			ir.LastScanAt = ir.Subtasks.FinishedAt.UnixMilli()
		}
	} else {
		ir.ScanStatus = ImageNotScan
	}

	if ir.SecurityIssue == nil {
		ir.SecurityIssue = make([]SecurityIssue, 0)
	}
	if ir.ScanInfo != nil {
		if ExistFlag(ir.Flag, FlagHasVuln) {
			ir.SecurityIssue = append(ir.SecurityIssue, SecurityIssue{
				Value: FlagHasVuln, Label: GetSecurityIssueLabel(FlagHasVuln)})
		}

		if ExistFlag(ir.Flag, FlagHasSensitive) {
			ir.SecurityIssue = append(ir.SecurityIssue, SecurityIssue{
				Value: FlagHasSensitive, Label: GetSecurityIssueLabel(FlagHasSensitive)})
		}
		if ExistFlag(ir.Flag, FlagHasMalicious) {
			ir.SecurityIssue = append(ir.SecurityIssue, SecurityIssue{
				Value: FlagHasMalicious, Label: GetSecurityIssueLabel(FlagHasMalicious)})
		}
		if ExistFlag(ir.Flag, FlagHasWebshell) {
			ir.SecurityIssue = append(ir.SecurityIssue, SecurityIssue{
				Value: FlagHasWebshell, Label: GetSecurityIssueLabel(FlagHasWebshell)})
		}

		if ExistFlag(ir.Flag, FlagHasExceptEnv) {
			ir.SecurityIssue = append(ir.SecurityIssue, SecurityIssue{
				Value: FlagHasExceptEnv,
				Label: GetSecurityIssueLabel(FlagHasExceptEnv),
				Info:  ParseConfigEnv(ir.ScanInfo.EnvKeyValue),
			})
		}

		if ExistFlag(ir.Flag, FlagHasExceptLicense) {
			ir.SecurityIssue = append(ir.SecurityIssue, SecurityIssue{
				Value: FlagHasExceptLicense,
				Label: GetSecurityIssueLabel(FlagHasExceptLicense),
				Info:  ParseLicense(ir.ScanInfo.LicenseInfo)})
		}

		if ExistFlag(ir.Flag, FlagHasSoftware) {
			ir.SecurityIssue = append(ir.SecurityIssue, SecurityIssue{
				Value: FlagHasSoftware,
				Label: GetSecurityIssueLabel(FlagHasSoftware),
				Info:  ParseSoftWare(ir.ScanInfo.Software)})
		}

		if ExistFlag(ir.Flag, FlagHasFixedVuln) {
			ir.ImageAttr.HasFixedVuln = true
		}

		ir.RiskScore = 100 - (ir.ScanInfo.VulnScore + ir.ScanInfo.SensitiveScore + math.Min(ir.ScanInfo.WebshellScore+ir.ScanInfo.VirusScore, MaxWebshellAndVirusScore))

		// 把恶义文件加上
		ir.Malicious = make([]VirusInfo, 0)
		for i := range ir.ScanInfo.MaliciousInfo {
			ir.Malicious = append(ir.Malicious, ir.ScanInfo.MaliciousInfo[i].VirusInfo)
		}
	}

	if ExistFlag(ir.Flag, FlagBaseImage) {
		ir.ImageAttr.ImageType = BaseImageTypeString
	} else {
		ir.ImageAttr.ImageType = AppImageTypeString
	}
	if ExistFlag(ir.Flag, FlagReinforced) {
		ir.ImageAttr.Reinforced = true
	}

	if ExistFlag(ir.Flag, FlagPrivilegedBoot) {
		ir.SecurityIssue = append(ir.SecurityIssue,
			SecurityIssue{Value: FlagPrivilegedBoot, Label: GetSecurityIssueLabel(FlagPrivilegedBoot)})
	}
	// 把仓库信息加上
	if ir.Registry != nil {
		ir.RegistryName = ir.Registry.Name
		ir.RegistryUrl = ir.Registry.Url
		ir.RegistryDeletedAt = ir.Registry.DeletedAt
		ir.LastSyncAt = ir.Registry.LastSyncAt * 1000 // 前端要求毫秒
	}
	// 处理os版本
	imageOs := ftypes.OS{}
	if ir.Os != "" {
		if err := json.Unmarshal([]byte(ir.Os), &imageOs); err == nil {
			ir.Os = fmt.Sprintf("%s:%s", imageOs.Family, imageOs.Name)
		} else {
			logging.Get().Err(err).Str("os", ir.Os).Msg("ImageListResponse.Deserialize")
		}
	}
	ir.LastSyncAt = ir.Registry.LastSyncAt
	// 如果没有扫描过，就统一改成0分
	if ir.ScanInfo == nil {
		ir.RiskScore = 0
	}
}

func ParseConfigEnv(env []EnvKeyValue) string {
	res := make([]string, 0)
	for i := range env {
		if env[i].IsAbnormal > 0 {
			res = append(res, env[i].Key)
		}
	}
	return strings.Join(res, ",")
}

func ParseSoftWare(softs []Software) string {
	if len(softs) == 0 {
		return ""
	}
	lit := make([]string, 0)
	for i := range softs {
		lit = append(lit, fmt.Sprintf("%s(%s)", softs[i].Name, softs[i].Version))
	}

	return strings.Join(lit, ",")
}

func ParseLicense(softs []LicenseInfo) string {
	if len(softs) == 0 {
		return ""
	}
	lit := make([]string, 0)
	for i := range softs {
		lit = append(lit, softs[i].Name)
	}

	return strings.Join(lit, ",")
}
