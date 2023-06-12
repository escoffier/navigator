package imagesec

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 镜像属性
type ImageAttrParam struct {
	Trusted              string `json:"trusted"`              // 是否是可信镜像：是："true"，否："false"
	ImageType            string `json:"imageType"`            // 镜像类型,基础镜像："base",应用镜像："app"
	HasFixedVuln         string `json:"hasFixedVuln"`         // 是否包含可修复漏洞: 是:"true",否："false"
	ImageHasSuggestion   string `json:"imageHasSuggestion"`   // 可修复镜像:是："true",否："false"
	NodeImageNotLibImage string `json:"nodeImageNotLibImage"` // 节点镜像不是仓库镜像
}

type ImageListParam struct {
	ImageFromType          string            `json:"imageFromType"`
	Online                 string            `json:"online"`    // 在线 "true",离线："false" 仓库镜像在用，后期修正
	OnlineStr              []string          `json:"onlineStr"` // 在线 "true",离线："false" // 节点镜像使用
	OnlineFlag             uint64            `json:"onlineFlag"`
	NodeKeyword            string            `json:"nodeKeyword"`
	ImageKeyword           string            `json:"imageKeyword"`
	SecurityIssue          []uint64          `json:"securityIssue"` // 安全问题
	SecurityIssueFlag      uint64            `json:"-"`             // 安全问题: 前端传字符串
	ImageAttr              ImageAttrParam    `json:"-"`             // 镜像属性
	ImageAttrFlag          uint64            `json:"-"`
	ImageAttrView          []string          `json:"imageAttr"` // 镜像属性,前端以列表的方式传递
	SafeAttr               []string          `json:"safeAttr"`  // safe，unsafe,unknown
	SafeAttrFlag           uint64            `json:"-"`
	VulnStatic             []string          `json:"vulnStatic"`      // 镜像漏洞统计
	VulnStaticFlag         uint64            `json:"-"`               // 镜像漏洞统计
	ImageIds               []int64           `json:"imageIds"`        // 镜像ID列表
	ScanStatus             []string          `json:"scanStatus"`      // 扫描状态
	ScanStatusFlag         uint64            `json:"-"`               // 扫描状态(对应数据库中的数据)
	JustReturnImage        bool              `json:"justReturnImage"` // 只需要镜像信息，不需要镜像关联信息
	ReturnMalicious        bool              `json:"returnMalicious"` // 是否返回恶义文件
	UUIDs                  []uint32          `json:"uuids"`           // 镜像uuid
	UniqueIds              []uint64          `json:"uniqueIds"`
	Projects               []string          `json:"projects"`               // 仓库和repo的筛选
	AttrIntersection       string            `json:"attrIntersection"`       // 属性交集还是并集 and or
	IssueIntersection      string            `json:"issueIntersection"`      // 安全问题交集还是并集 and or
	VulnStaticIntersection string            `json:"vulnStaticIntersection"` // 漏洞统计交集还是并集 and or
	NotIdentifyOnline      bool              `json:"notIdentifyOnline"`      // 是否识别是在线还是离线 默认需要识别
	NotIdentifyTrusted     bool              `json:"notIdentifyTrusted"`     // 是否识别是可信镜像 默认需要识别
	StartID                int64             `json:"startID"`                // 分页请求时，上一页最后一条数据的ID
	ImageScanTaskInfo      ImageScanTaskInfo `json:"imageScanTaskInfo"`
	ClusterKey             []string          `json:"clusterKey"`
	WebshellMD5            string            `json:"webshellMd5"`
	// 后端处理数据的中间结构
	RegistryIds []int64              `json:"-"`
	Repos       []SearchProjectParam `json:"-"`
	Fields      []string             `json:"fields"`

	Filter *model.Filter
}

func (sp *ImageListParam) Check() *i18.ErrI18 {
	if sp == nil {
		return i18.CreateI18BadReqErr("程序出错", "not get model")
	}
	if err := ImageFromType(sp.ImageFromType).Check(); err != nil {
		return i18.CreateI18BadReqErr("未获取到镜像类型", "not get image from type")
	}
	return nil
}

// 生成属性的flag
func (sp *ImageListParam) GenAttrFlag() uint64 {
	var flag uint64
	if sp.ImageAttr.ImageType == model.BaseImageTypeString {
		flag = util.SetBit1(flag, model.FlagBaseImage)
	}
	if sp.ImageAttr.HasFixedVuln == model.TrueString {
		flag = util.SetBit1(flag, model.FlagHasFixedVuln)
	}
	if sp.ImageAttr.Trusted == model.TrueString {
		flag = util.SetBit1(flag, model.FlagImageTrusted)
	}
	if sp.ImageAttr.NodeImageNotLibImage == model.TrueString {
		flag = util.SetBit1(flag, model.FlagNodeImageNotInLib)
	}
	if sp.ImageAttr.ImageHasSuggestion == model.TrueString {
		flag = util.SetBit1(flag, model.FlagImageHasFixSuggest)
	}
	return flag
}

// 生成属性的flag
func (sp *ImageListParam) GenAttrFlagList() []uint64 {
	flag := make([]uint64, 0)
	if sp.ImageAttr.ImageType == model.BaseImageTypeString {
		flag = append(flag, model.FlagBaseImage)
	}
	if sp.ImageAttr.HasFixedVuln == model.TrueString {
		flag = append(flag, model.FlagHasFixedVuln)
	}

	return flag
}

// 生成安全问题的flag
func (sp *ImageListParam) GenSecurityIssueFlag() uint64 {
	var flag uint64

	kinds := util.DuplicateUint64Slice(sp.SecurityIssue)
	for _, kind := range kinds {
		for _, imageFlag := range model.GetAllFlag() {
			if kind == imageFlag {
				flag = 1<<imageFlag + flag
			}
		}
	}

	return flag
}

func (sp *ImageListParam) GenSafeAttrFlag() uint64 {
	// 镜像是否安全
	var safeAttrFlag uint64
	for i := range sp.SafeAttr {
		switch sp.SafeAttr[i] {
		case model.ImageSafeString:
			safeAttrFlag = util.SetBit1(safeAttrFlag, model.FlagImageSafe)
		case model.ImageUnsafeString:
			safeAttrFlag = util.SetBit1(safeAttrFlag, model.FlagImageUnsafe)
		case model.ImageSafeUnknown:
			safeAttrFlag = util.SetBit1(safeAttrFlag, model.FlagImageSafeUnknown)
		}
	}
	return safeAttrFlag
}

func (sp *ImageListParam) GenOnlineFlag() uint64 {
	// 镜像是否安全
	var safeAttrFlag uint64
	for i := range sp.OnlineStr {
		switch sp.OnlineStr[i] {
		case model.TrueString:
			safeAttrFlag = util.SetBit1(safeAttrFlag, model.FlagImageOnline)
		case model.FalseString:
			safeAttrFlag = util.SetBit1(safeAttrFlag, model.FlagImageNotOnline)
		}
	}
	return safeAttrFlag
}

func (sp *ImageListParam) GenVulnStaticFlag() uint64 {
	// 镜像漏洞筛选
	var imageVulnStaticFlag uint64
	for i := range sp.VulnStatic {
		switch strings.ToUpper(sp.VulnStatic[i]) {
		case SeverityCritical:
			imageVulnStaticFlag = util.SetBit1(imageVulnStaticFlag, model.FlagImageHasCriticalVuln)
		case SeverityHigh:
			imageVulnStaticFlag = util.SetBit1(imageVulnStaticFlag, model.FlagImageHasHighVuln)
		case SeverityMedium:
			imageVulnStaticFlag = util.SetBit1(imageVulnStaticFlag, model.FlagImageHasMediumVuln)
		case SeverityLow:
			imageVulnStaticFlag = util.SetBit1(imageVulnStaticFlag, model.FlagImageHasLowVuln)
		case SeverityUnknown:
			imageVulnStaticFlag = util.SetBit1(imageVulnStaticFlag, model.FlagImageHasUnknownVun)
		}
	}
	return imageVulnStaticFlag
}

func (sp *ImageListParam) GenImageAttrFlag() uint64 {
	// 镜像属性flag
	var imageAttrFlag uint64
	for i := range sp.ImageAttrView {
		switch sp.ImageAttrView[i] {
		case model.AppImageTypeString:
			imageAttrFlag = util.SetBit1(imageAttrFlag, model.FlagAppImage)
		case model.BaseImageTypeString:
			imageAttrFlag = util.SetBit1(imageAttrFlag, model.FlagBaseImage)
		case model.TrustedString:
			imageAttrFlag = util.SetBit1(imageAttrFlag, model.FlagImageTrusted)
		case model.UnTrustedString:
			imageAttrFlag = util.SetBit1(imageAttrFlag, model.FlagImageUnTrusted)
		case model.HasFixedVulnString:
			imageAttrFlag = util.SetBit1(imageAttrFlag, model.FlagHasFixedVuln)
		case model.ImageHasSuggestionString:
			imageAttrFlag = util.SetBit1(imageAttrFlag, model.FlagImageHasFixSuggest)
		case model.NodeImageNotLibImageString:
			imageAttrFlag = util.SetBit1(imageAttrFlag, model.FlagNodeImageNotInLib)
		}
	}
	return imageAttrFlag
}

// 中间过度阶段，两种不同的解析方式，后期统一成Deserialize2
// 查询条件实在太多了，后期得空需要整理得更明了
// 更好的做法是 提供一个方法 把 ImageListParam 转为 NodeImageDalParam 后期修改
func (sp *ImageListParam) Deserialize() {
	if sp.ImageFromType == "" {
		sp.ImageFromType = ImageFromRegistry
	}
	if sp.ImageFromType == ImageFromNode {
		sp.deserialize2()
	}
	if sp.ImageFromType == ImageFromRegistry {
		sp.deserialize1()
	}
}

func (sp *ImageListParam) deserialize1() {
	if sp.AttrIntersection == "" {
		sp.AttrIntersection = model.AndString
	}
	if sp.IssueIntersection == "" {
		sp.IssueIntersection = model.AndString
	}
	if sp.VulnStaticIntersection == "" {
		sp.VulnStaticIntersection = model.AndString
	}

	if sp.NotIdentifyOnline {
		sp.Online = ""
	}
	if sp.NotIdentifyTrusted {
		sp.ImageAttr.Trusted = ""
	}

	repos := make([]SearchProjectParam, 0)
	for _, v := range sp.Projects {
		split := strings.Split(v, ",")
		// 说明只是registryID的筛选
		if len(split) == 1 && split[0] != "" {
			regID, err := strconv.ParseInt(split[0], 10, 64)
			if err != nil {
				logging.Get().Error().Str("project", v).Msg("project parameter incorrect")
				continue
			}
			repos = append(repos, SearchProjectParam{RegID: regID})
		}
		if len(split) == 2 && split[0] != "" && split[1] != "" {
			regID, err := strconv.ParseInt(split[0], 10, 64)
			if err != nil {
				logging.Get().Error().Str("project", v).Msg("project parameter incorrect")
				continue
			}
			repos = append(repos, SearchProjectParam{RegID: regID, ProjectName: split[1]})
		}
	}
	sp.Repos = repos

	// // 如果可信和非可信都在选项中，就移出
	// if util.ContainsString(sp.ImageAttrView, model.TrustedString) && util.ContainsString(sp.ImageAttrView, model.UnTrustedString) {
	// 	attrView := make([]string, 0)
	// 	for i := range sp.ImageAttrView {
	// 		if !util.ContainsString([]string{model.TrustedString, model.UnTrustedString}, sp.ImageAttrView[i]) {
	// 			attrView = append(attrView, sp.ImageAttrView[i])
	// 		}
	// 	}
	// 	sp.ImageAttrView = attrView
	// }

	for i := range sp.ImageAttrView {
		switch sp.ImageAttrView[i] {
		case model.AppImageTypeString:
			sp.ImageAttr.ImageType = model.AppImageTypeString
		case model.BaseImageTypeString:
			sp.ImageAttr.ImageType = model.BaseImageTypeString
		case model.TrustedString:
			sp.ImageAttr.Trusted = model.TrueString
		case model.UnTrustedString:
			sp.ImageAttr.Trusted = model.FalseString
		case model.HasFixedVulnString:
			sp.ImageAttr.HasFixedVuln = model.TrueString
		}
	}

	// 如果只有一个条件，取交集或者并集是一样的，统一设置成交集，便于处理
	if len(sp.ImageAttrView) == 1 {
		sp.AttrIntersection = model.AndString
	}

	var scanStatusFlag uint64
	for i := range sp.ScanStatus {
		scanStatusFlag = util.SetBit1(scanStatusFlag, GetSubTaskScanStatusFlag(sp.ScanStatus[i]))
	}
	sp.ScanStatusFlag = scanStatusFlag
	sp.SecurityIssueFlag = sp.GenSecurityIssueFlag()
	if sp.NotIdentifyOnline {
		sp.Online = ""
	}
	if sp.NotIdentifyTrusted {
		sp.ImageAttr.Trusted = ""
	}
	sp.ImageKeyword = strings.TrimSpace(sp.ImageKeyword)
}

func (sp *ImageListParam) deserialize2() {
	if sp.AttrIntersection == "" || len(sp.ImageAttrView) == 1 {
		sp.AttrIntersection = model.AndString
	}
	if sp.IssueIntersection == "" || len(sp.SecurityIssue) == 1 {
		sp.IssueIntersection = model.AndString
	}
	if sp.VulnStaticIntersection == "" {
		sp.VulnStaticIntersection = model.OrString
	}

	repos := make([]SearchProjectParam, 0)
	for _, v := range sp.Projects {
		split := strings.Split(v, ",")
		// 说明只是registryID的筛选
		if len(split) == 1 && split[0] != "" {
			regID, err := strconv.ParseInt(split[0], 10, 64)
			if err != nil {
				logging.Get().Error().Str("project", v).Msg("project parameter incorrect")
				continue
			}
			repos = append(repos, SearchProjectParam{RegID: regID})
		}
		if len(split) == 2 && split[0] != "" && split[1] != "" {
			regID, err := strconv.ParseInt(split[0], 10, 64)
			if err != nil {
				logging.Get().Error().Str("project", v).Msg("project parameter incorrect")
				continue
			}
			repos = append(repos, SearchProjectParam{RegID: regID, ProjectName: split[1]})
		}
	}
	sp.Repos = repos

	sp.ImageAttrFlag = sp.GenImageAttrFlag()
	sp.VulnStaticFlag = sp.GenVulnStaticFlag()

	sp.SafeAttrFlag = sp.GenSafeAttrFlag()
	// 安全问题
	sp.SecurityIssueFlag = sp.GenSecurityIssueFlag()
	sp.OnlineFlag = sp.GenOnlineFlag()
	sp.ImageKeyword = strings.TrimSpace(sp.ImageKeyword)
	sp.NodeKeyword = strings.TrimSpace(sp.NodeKeyword)
}

// 镜像属性
type ImageAttrResponse struct {
	Trusted              bool   `json:"trusted"`              // 是否是可信镜像：是：true，否：false
	ImageType            string `json:"imageType"`            // 镜像类型,基础镜像："base",应用镜像："app"
	HasFixedVuln         bool   `json:"hasFixedVuln"`         // 是否包含可修复漏洞: 是:true,否：false
	ImageHasSuggestion   bool   `json:"imageHasSuggestion"`   // 可修复镜像:是："true",否："false"
	NodeImageNotLibImage bool   `json:"nodeImageNotLibImage"` // 节点镜像不是仓库镜像
}

type GetImageAssociateDataParam struct {
	ImageFromType         string
	ImageId               int64  // 对于仓库镜像这个参数是必须的
	ImageUniqueID         uint64 // 对于节点镜像这个对数是必须的，后续仓库镜像也要整合到这里
	VulnEnable            bool
	MalwareEnable         bool
	EnvEnable             bool
	PkgEnable             bool
	LicenseEnable         bool
	SensitiveEnable       bool
	WebshellEnable        bool
	ContainerEnable       bool
	SubtaskEnable         bool
	RegistryEnable        bool
	BaseImageEnable       bool
	AppImageEnable        bool
	NodeInfoEnable        bool                  // 查询节点镜像的节点信息
	RiskPolicyEnable      bool                  // 查风险来源
	DetectResultEnable    bool                  // 查看检测结果
	ScanResultSearchParam ScanResultSearchParam // 除了漏洞之外其他扫描结果的查询
	SearchVulnParam       ApiSearchVulnParam    // 漏洞查询

	Filter *model.Filter
}

func (vi *GetImageAssociateDataParam) GetDetectTypes() []string {
	ans := make([]string, 0)
	if !vi.DetectResultEnable {
		return ans
	}
	if vi.EnvEnable {
		ans = append(ans, DetectTypeEnvRule)
	}
	if vi.WebshellEnable {
		ans = append(ans, DetectTypeWebshellRule)
	}
	if vi.VulnEnable {
		ans = append(ans, DetectTypeVulnRule)
	}
	if vi.LicenseEnable {
		ans = append(ans, DetectTypePkgLicenseRule)
	}
	if vi.MalwareEnable {
		ans = append(ans, DetectTypeMalwareRule)
	}
	if vi.SensitiveEnable {
		ans = append(ans, DetectTypeSensRule)
	}
	if vi.PkgEnable {
		ans = append(ans, DetectTypePkgVersionRule)
	}
	ans = append(ans, DetectTypeRootRule)
	return ans
}

type ScanResultSearchParam struct {
	ImageFromType      string   `json:"imageFromType"`
	ImageID            int64    `json:"imageID"`
	ImageUniqueID      uint64   `json:"imageUniqueID,string"`
	LayerDigest        string   `json:"layerDigest"`
	Keyword            string   `json:"keyword"`
	ExceptionPkg       string   `json:"exceptionPkg"`
	ExceptionLicense   string   `json:"exceptionLicense"`
	ExceptionEnv       string   `json:"exceptionEnv"`
	PasswdEnv          string   `json:"passwdEnv"`
	ExceptionVuln      string   `json:"exceptionVuln"`
	ExceptionMalware   string   `json:"exceptionMalware"`
	ExceptionSensitive string   `json:"exceptionSensitive"`
	ExceptionWebshell  string   `json:"exceptWebshell"`
	VulnSeverity       []string `json:"vulnSeverity"`
	LicenseSearch      []string `json:"licenseSearch"`     // 开源协议筛选
	UniqueIds          []uint64 `json:"uniqueIds"`         //
	WebshellRiskLevel  []string `json:"webshellRiskLevel"` //
	OmitFields         []string // 数据库中不查询的字段
	Fields             []string // 数据库中查询的字段
	SecurityPolicyIds  []int64  `json:"securityPolicyIds"` // 检测策略ID

	Filter *model.Filter
}

func (vi *ScanResultSearchParam) Check() error {
	if err := ImageFromType(vi.ImageFromType).Check(); err != nil {
		return err
	}
	if vi.ImageID <= 0 && vi.ImageUniqueID <= 0 {
		return fmt.Errorf("not get imageID or ImageUniqueID")
	}

	return nil
}

func (vi *GetImageAssociateDataParam) Check() error {
	if vi.ImageId <= 0 && vi.ImageUniqueID <= 0 {
		return fmt.Errorf("no image id")
	}
	// if vi.DetectResultEnable {
	// 	if len(vi.ScanResultSearchParam.SecurityPolicyIds) == 0 {
	// 		return fmt.Errorf("not get SecurityPolicyIds")
	// 	}
	// }

	return nil
}

func (vi *GetImageAssociateDataParam) Deserialize() {
	if vi.ImageId > 0 {
		vi.ImageUniqueID = 0
	}

	vi.ScanResultSearchParam.ImageID = vi.ImageId
	vi.ScanResultSearchParam.ImageUniqueID = vi.ImageUniqueID
	vi.ScanResultSearchParam.Keyword = strings.ToLower(vi.ScanResultSearchParam.Keyword)
	vi.ScanResultSearchParam.ImageFromType = vi.ImageFromType
	vi.SearchVulnParam.ImageFromType = vi.ImageFromType
}

type ImageScanTaskInfo struct {
	Scope        int    `json:"scope"`
	TriggerType  int    `json:"triggerType"`  // 扫描类型
	StrategyID   int64  `json:"strategyId"`   // 扫描策略ID
	StrategyName string `json:"strategyName"` // 扫描策略名字 用于openapi
	Operator     string `json:"operator"`     // 操作人
}

// image(subtask) scan status
// 以前老的调度常量，后期需要统一
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
		return model.FlagImageScanPending
	case ImageScanInProgress:
		return model.FlagImageScanInProgress
	case ImageScanSuccess:
		return model.FlagImageScanSuccess
	case ImageScanFailed:
		return model.FlagImageScanFailed
	case ImageNotScan:
		return model.FlagImageNotScan
	case ImageScanUnknown:
		return model.FlagImageScanUnknown
	default:
		return 0
	}
}

func GetSubTaskStatusFlagString(flag uint64) string {
	for _, v := range model.GetScanStatusFlag() {
		if !util.ExistBit1(flag, v) {
			continue
		}
		switch v {
		case model.FlagImageScanUnknown:
			return ImageScanUnknown
		case model.FlagImageScanPending:
			return ImageScanPending
		case model.FlagImageScanInProgress:
			return ImageScanInProgress
		case model.FlagImageScanSuccess:
			return ImageScanSuccess
		case model.FlagImageScanFailed:
			return ImageScanFailed
		case model.FlagImageNotScan:
			return ImageNotScan
		default:
			return ""
		}
	}
	return ""
}

func GetSubTaskScanStatusString(status uint8) string {
	switch status {
	case model.FlagImageScanUnknown:
		return ImageScanUnknown
	case model.FlagImageScanPending:
		return ImageScanPending
	case model.FlagImageScanInProgress:
		return ImageScanInProgress
	case model.FlagImageScanSuccess:
		return ImageScanSuccess
	case model.FlagImageScanFailed:
		return ImageScanFailed
	case model.FlagImageNotScan:
		return ImageNotScan
	default:
		return ""
	}
}

type SecurityIssueLabel struct {
	Value int64  `json:"value"` // 安全问题的ID
	Label string `json:"label"` // 安全问题
	Info  string `json:"info"`  // 详细信息
}

type ImageWithCorrelateData2 struct {
	Image             Image
	Flag              uint64
	ImageBaseResponse ImageBaseResponse
	Sensitive         []*SensitiveFile
	SensitiveCnt      int64
	Webshell          []*WebshellView
	WebshellCnt       int64
	Env               []*ImageEnv
	EnvCnt            int64
	Vuln              []*VulnView
	VulnCnt           int64
	Pkg               []*Pkg
	PkgCnt            int64
	License           []string // 异常的license
	Malware           []*Malware
	MalwareCnt        int64
	BaseImages        []*ImageBaseResponse // 基础镜像列表
	BaseImageCnt      int64
	AppImages         []*ImageBaseResponse // 应用镜像列表
	AppImageCnt       int64
	Container         []*ImageContainerResources
	ScanSubTask       []*ImageScanSubTask
	SubTaskCnt        int64
	Registry          *model.Registry
	NodeInfo          *NodeInfo
	RiskPolicy        []*SecurityPolicy               // 镜像的风险来源
	TotalPolicy       []*SecurityPolicy               // 已使用的安全策略
	DetectResult      map[string][]*ImageDetectResult // 检测结果
}

func GetDetectBriefFlag(detectResult map[string][]*ImageDetectResult) uint64 {
	var flag uint64
	for i := range detectResult {
		rr := detectResult[i]
		for j := range rr {
			flag = flag | rr[j].Flag
		}
	}
	return flag
}

type ImageLicence struct {
	Licence      string
	PolicyDetect PolicyDetect `gorm:"-" json:"policyDetect"` // 对各个策略的检测结果
}

func (iws *ImageWithCorrelateData2) GenImageFlag() uint64 {
	return 0
}

func (iws *ImageWithCorrelateData2) ExceptionFilter(param ScanResultSearchParam) *ImageWithCorrelateData2 {

	if param.ExceptionLicense == model.TrueString || param.ExceptionPkg == model.TrueString {

		pkg := make([]*Pkg, 0)
		for i := range iws.Pkg {
			add := false
			if (iws.Pkg[i].PolicyDetect.ExceptionLicense && param.ExceptionLicense == model.TrueString) ||
				(iws.Pkg[i].PolicyDetect.Exception && param.ExceptionPkg == model.TrueString) {
				add = true
			}
			if add {
				pkg = append(pkg, iws.Pkg[i])
			}
		}
		iws.Pkg = pkg
		iws.PkgCnt = int64(len(pkg))
	}

	if param.ExceptionPkg == model.TrueString {

		pkg := make([]*Pkg, 0)
		for i := range iws.Pkg {
			add := false
			if iws.Pkg[i].PolicyDetect.ExceptionLicense || param.ExceptionLicense == model.TrueString {
				add = true
			}
			if iws.Pkg[i].PolicyDetect.Exception || param.ExceptionPkg == model.TrueString {
				add = true
			}
			if add {
				pkg = append(pkg, iws.Pkg[i])
			}
		}
		iws.Pkg = pkg
		iws.PkgCnt = int64(len(pkg))
	}

	if param.ExceptionEnv == model.TrueString || param.PasswdEnv == model.TrueString {
		data := make([]*ImageEnv, 0)
		for i := range iws.Env {
			if (iws.Env[i].PolicyDetect.Exception && param.ExceptionEnv == model.TrueString) ||
				(iws.Env[i].PolicyDetect.PasswdEnv && param.PasswdEnv == model.TrueString) {
				data = append(data, iws.Env[i])
			}
		}
		iws.Env = data
		iws.EnvCnt = int64(len(data))
	}

	if param.ExceptionVuln == model.TrueString {
		data := make([]*VulnView, 0)
		for i := range iws.Vuln {
			if iws.Vuln[i].PolicyDetect.Exception {
				data = append(data, iws.Vuln[i])
			}
		}
		iws.Vuln = data
		iws.VulnCnt = int64(len(data))
	}

	if param.ExceptionSensitive == model.TrueString {
		data := make([]*SensitiveFile, 0)
		for i := range iws.Sensitive {
			if iws.Sensitive[i].PolicyDetect.Exception {
				data = append(data, iws.Sensitive[i])
			}
		}
		iws.Sensitive = data
		iws.SensitiveCnt = int64(len(data))
	}

	if param.ExceptionMalware == model.TrueString {
		data := make([]*Malware, 0)
		for i := range iws.Malware {
			if iws.Malware[i].PolicyDetect.Exception {
				data = append(data, iws.Malware[i])
			}
		}
		iws.Malware = data
		iws.MalwareCnt = int64(len(data))
	}

	if param.ExceptionWebshell == model.TrueString {
		data := make([]*WebshellView, 0)
		for i := range iws.Webshell {
			if iws.Webshell[i].PolicyDetect.Exception {
				data = append(data, iws.Webshell[i])
			}
		}
		iws.Webshell = data
		iws.WebshellCnt = int64(len(data))
	}
	return iws
}

// 程序中分页
func (iws *ImageWithCorrelateData2) AddFilter(filter *model.Filter) *ImageWithCorrelateData2 {
	if filter == nil {
		return iws
	}
	start := int(filter.Offset)
	end := int(filter.Offset + filter.Limit)

	if len(iws.Sensitive) <= start {
		iws.Sensitive = make([]*SensitiveFile, 0)
	} else {
		iws.Sensitive = iws.Sensitive[start:util.MinInt(end, len(iws.Sensitive))]
	}

	if len(iws.Webshell) <= start {
		iws.Webshell = make([]*WebshellView, 0)
	} else {
		iws.Webshell = iws.Webshell[start:util.MinInt(end, len(iws.Webshell))]
	}

	if len(iws.Env) <= start {
		iws.Env = make([]*ImageEnv, 0)
	} else {
		iws.Env = iws.Env[start:util.MinInt(end, len(iws.Env))]
	}

	if len(iws.Vuln) <= start {
		iws.Vuln = make([]*VulnView, 0)
	} else {
		iws.Vuln = iws.Vuln[start:util.MinInt(end, len(iws.Vuln))]
	}

	if len(iws.Pkg) <= start {
		iws.Pkg = make([]*Pkg, 0)
	} else {
		iws.Pkg = iws.Pkg[start:util.MinInt(end, len(iws.Pkg))]
	}

	if len(iws.License) <= start {
		iws.License = make([]string, 0)
	} else {
		iws.License = iws.License[start:util.MinInt(end, len(iws.License))]
	}

	if len(iws.Malware) <= start {
		iws.Malware = make([]*Malware, 0)
	} else {
		iws.Malware = iws.Malware[start:util.MinInt(end, len(iws.Malware))]
	}

	if len(iws.BaseImages) <= start {
		iws.BaseImages = make([]*ImageBaseResponse, 0)
	} else {
		iws.BaseImages = iws.BaseImages[start:util.MinInt(end, len(iws.BaseImages))]
	}

	if len(iws.AppImages) <= start {
		iws.AppImages = make([]*ImageBaseResponse, 0)
	} else {
		iws.AppImages = iws.AppImages[start:util.MinInt(end, len(iws.AppImages))]
	}

	return iws
}

func (iws *ImageWithCorrelateData2) GenSuggest() []ImageSuggest {
	res := make([]ImageSuggest, 0)

	vu := iws.GenVulnSuggest()
	if len(vu.Data) > 0 {
		res = append(res, vu)
	}

	ma := iws.GenMalwareSuggest()
	if len(ma.Data) > 0 {
		res = append(res, ma)
	}

	we := iws.GenWebshellSuggest()
	if len(we.Data) > 0 {
		res = append(res, we)
	}

	se := iws.GenSensitiveFileSuggest()
	if len(se.Data) > 0 {
		res = append(res, se)
	}

	return res
}

func (iws *ImageWithCorrelateData2) GenVulnSuggest() ImageSuggest {
	pkg := make([]string, 0)
	for i := range iws.Vuln {
		vu := iws.Vuln[i]
		if vu.FixedVersion != "" && vu.Class == report.ClassOSPkg {
			pkg = append(pkg, vu.PkgName)
		}
	}
	pkg = util.DuplicateStringSlice(pkg)

	install := util.InstallType(iws.Image.OS.Family)

	suggest := make([]string, 0)

	if len(pkg) > 0 && install != "" {
		cmd := fmt.Sprintf("%s %s %s", "RUN", install, strings.Join(pkg, " "))
		suggest = append(suggest, cmd)
	}

	return ImageSuggest{Data: suggest, Title: VulnSuggestTitle}
}

const (
	VulnSuggestTitle     = "建议在Dockerfile里面使用以下命令升级软件包:"
	MalwareSuggestTitle  = "建议删除木马病毒文件并排查文件来源："
	WebshellSuggestTitle = "建议删除相关后门并排查文件来源："
	SensSuggestTitle     = "建议在镜像中移除以下敏感文件，然后重新打包镜像："
)

func SuggestTile() map[string]string {
	en := map[string]string{
		VulnSuggestTitle:     "it is recommended to use following command in  Dockerfile to upgrade the package:",
		MalwareSuggestTitle:  "it is recommended to delete the Trojan virus files and investigate the source of the files:",
		WebshellSuggestTitle: "it is recommended to delete related backdoors and investigate the source of the files:",
		SensSuggestTitle:     "it is recommended to remove the following sensitive files from the image, and then repackage the image",
	}
	return en
}

func (iws *ImageWithCorrelateData2) GenSensitiveFileSuggest() ImageSuggest {

	files := make([]string, 0)

	for i := range iws.Sensitive {
		file := iws.Sensitive[i]
		if file.Name == "" {
			continue
		}
		if !strings.HasPrefix(file.Name, "/") {
			file.Name = "/" + file.Name
		}

		files = append(files, file.Name)
	}
	files = util.DuplicateStringSlice(files)
	return ImageSuggest{Data: files, Title: SensSuggestTitle}
}

func (iws *ImageWithCorrelateData2) GenWebshellSuggest() ImageSuggest {
	files := make([]string, 0)

	for i := range iws.Webshell {
		files = append(files, iws.Webshell[i].Filepath+iws.Webshell[i].Filename)
	}
	files = util.DuplicateStringSlice(files)
	return ImageSuggest{Data: files, Title: WebshellSuggestTitle}
}

func (iws *ImageWithCorrelateData2) GenMalwareSuggest() ImageSuggest {
	files := make([]string, 0)

	for i := range iws.Malware {
		files = append(files, iws.Malware[i].Filepath+iws.Malware[i].Filename)
	}
	files = util.DuplicateStringSlice(files)
	return ImageSuggest{Data: files, Title: MalwareSuggestTitle}
}

func (iws *ImageWithCorrelateData2) GetImageAttr() ImageAttrResponse {
	attr := ImageAttrResponse{}

	imageFlag := iws.Image.Flag

	if util.ExistBit1(imageFlag, model.FlagBaseImage) {
		attr.ImageType = model.BaseImageTypeString
	} else {
		attr.ImageType = model.AppImageTypeString
	}
	if util.ExistBit1(imageFlag, model.FlagHasFixedVuln) {
		attr.HasFixedVuln = true
	}
	if util.ExistBit1(imageFlag, model.FlagImageTrusted) {
		attr.Trusted = true
	}
	if util.ExistBit1(imageFlag, model.FlagImageHasFixSuggest) {
		attr.ImageHasSuggestion = true
	}
	if util.ExistBit1(imageFlag, model.FlagNodeImageNotInLib) {
		attr.NodeImageNotLibImage = true
	}

	return attr
}

func (iws *ImageWithCorrelateData2) GetSecurityIssue() []SecurityIssueLabel {
	securityIssue := make([]SecurityIssueLabel, 0)
	if iws.Flag <= 0 {
		iws.Flag = iws.Image.Flag
	}
	imageFlag := iws.Flag

	if util.ExistBit1(imageFlag, model.FlagHasVuln) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value: model.FlagHasVuln, Label: model.GetSecurityIssueLabel(model.FlagHasVuln)})
	}
	if util.ExistBit1(imageFlag, model.FlagHasSensitive) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value: model.FlagHasSensitive, Label: model.GetSecurityIssueLabel(model.FlagHasSensitive)})
	}
	if util.ExistBit1(imageFlag, model.FlagHasMalicious) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value: model.FlagHasMalicious, Label: model.GetSecurityIssueLabel(model.FlagHasMalicious)})
	}
	if util.ExistBit1(imageFlag, model.FlagHasWebshell) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value: model.FlagHasWebshell, Label: model.GetSecurityIssueLabel(model.FlagHasWebshell)})
	}
	if util.ExistBit1(imageFlag, model.FlagHasExceptEnv) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value: model.FlagHasExceptEnv,
			Label: model.GetSecurityIssueLabel(model.FlagHasExceptEnv),
			Info:  ParseConfigEnv(iws.Env),
		})
	}
	if util.ExistBit1(imageFlag, model.FlagHasExceptLicense) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value: model.FlagHasExceptLicense,
			Label: model.GetSecurityIssueLabel(model.FlagHasExceptLicense),
			Info:  ParseLicense(iws.Pkg)})
	}
	if util.ExistBit1(imageFlag, model.FlagHasExceptPKG) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value: model.FlagHasExceptPKG,
			Label: model.GetSecurityIssueLabel(model.FlagHasExceptPKG),
			Info:  ParseSoftWare(iws.Pkg)})
	}
	if util.ExistBit1(imageFlag, model.FlagPrivilegedBoot) {
		securityIssue = append(securityIssue,
			SecurityIssueLabel{Value: model.FlagPrivilegedBoot, Label: model.GetSecurityIssueLabel(model.FlagPrivilegedBoot)})
	}

	return securityIssue
}

func (iws *ImageWithCorrelateData2) GetRiskScore() int64 {
	riskScore := 100 - (CalculateVulnScore(iws.Vuln) +
		CalculateSensitiveScore(iws.SensitiveCnt) +
		util.MinInt64(CalculateWebshellScore(iws.WebshellCnt)+CalculateMalwareScore(iws.MalwareCnt), model.MaxWebshellAndVirusScore))

	if util.ExistBit1(iws.Flag, model.FlagImageNotScan) && riskScore == 100 {
		riskScore = 0
	}
	return riskScore
}

func (iws *ImageWithCorrelateData2) GetImageOs() ImageOS {
	return ImageOS{
		Family:     iws.Image.OS.Family,
		Name:       iws.Image.OS.Name,
		Maintained: !iws.Image.OS.Eosl,
	}
}

// 兼容以前的逻辑，后期去除
func (iws *ImageWithCorrelateData2) ToSecurityIssueOverview() model.SecurityIssueOverview {
	issueStatic := model.SecurityIssueOverview{
		VULN:      iws.VulnCnt,
		VIRUS:     iws.MalwareCnt,
		SENSITIVE: iws.SensitiveCnt,
		Webshell:  iws.WebshellCnt,
	}
	if iws.Image.BootRoot() {
		issueStatic.PrivilegedBoot += 1
	}
	for i := range iws.Pkg {
		if iws.Pkg[i].PolicyDetect.Exception {
			issueStatic.Software++
		}
		if iws.Pkg[i].PolicyDetect.ExceptionLicense {
			issueStatic.License++
		}
	}
	for i := range iws.Env {
		if iws.Env[i].PolicyDetect.Exception {
			issueStatic.Envs++
		}
	}

	return issueStatic
}

func (iws *ImageWithCorrelateData2) ToSecurityIssueOverview2() SecurityOverView {
	sv := SecurityOverView{
		Total: SecurityIssueStatic{
			Vuln:      iws.VulnCnt,
			Malware:   iws.MalwareCnt,
			Sensitive: iws.SensitiveCnt,
			Webshell:  iws.WebshellCnt,
			Env:       iws.EnvCnt,
			Pkg:       iws.PkgCnt,
			License:   int64(len(iws.License)),
		},
	}
	if iws.Image.BootRoot() {
		sv.Total.PrivilegedBoot += 1
	}
	risk := SecurityIssueStatic{}
	for i := range iws.Pkg {
		if iws.Pkg[i].PolicyDetect.Exception {
			risk.Pkg++
		}
		if iws.Pkg[i].PolicyDetect.ExceptionLicense {
			risk.License++
		}
	}
	for i := range iws.Env {
		if iws.Env[i].PolicyDetect.Exception {
			risk.Env++
		}
	}
	for i := range iws.Sensitive {
		if iws.Sensitive[i].PolicyDetect.Exception {
			risk.Sensitive++
		}
	}

	for i := range iws.Malware {
		if iws.Malware[i].PolicyDetect.Exception {
			risk.Malware++
		}
	}

	for i := range iws.Vuln {
		if iws.Vuln[i].PolicyDetect.Exception {
			risk.Vuln++
		}
	}
	for i := range iws.Webshell {
		if iws.Webshell[i].PolicyDetect.Exception {
			risk.Webshell++
		}
	}
	for i := range iws.RiskPolicy {
		if iws.RiskPolicy[i].RootBootEnable && iws.Image.BootRoot() {
			risk.PrivilegedBoot = 1
			break
		}
	}

	sv.Risk = risk

	return sv
}

func (iws *ImageWithCorrelateData2) GenVulnSeverityOverview() []SeverityGroup {
	ans := make([]SeverityGroup, 0)
	for i := range iws.Vuln {
		ans = AddSeverityGroup(ans, iws.Vuln[i].SeverityInt)
	}
	sort.Sort(SeverityGroups(ans))
	return ans
}

func (iws *ImageWithCorrelateData2) ToImageBaseResponse() ImageBaseResponse {
	image := iws.Image

	baseResponse := ImageBaseResponse{
		ID:                   image.ID,
		UniqueID:             image.UniqueID,
		ImageFromType:        image.ImageFromType,
		Digest:               image.Digest,
		SecurityIssue:        iws.GetSecurityIssue(),
		ImageAttr:            iws.GetImageAttr(),
		UUID:                 image.ImageUUID,
		FullRepoName:         image.Repo,
		Tag:                  image.Tag,
		Size:                 util.ParseByteSize(image.Size),
		Os:                   iws.GetImageOs(),
		Flag:                 image.Flag,
		BootUser:             image.User,
		RiskScore:            iws.GetRiskScore(),
		Suggests:             iws.GenSuggest(),
		VulnSeverityOverview: iws.GenVulnSeverityOverview(),
		RegistryID:           image.RegID,
		RegistryUrl:          image.Host,
		Project:              image.Project,
		RiskPolicy:           iws.RiskPolicy,
		LastSyncAt:           image.Heartbeat,
		TotalPolicy:          iws.TotalPolicy,
		VulnStatic:           iws.StaticVuln(),
		RiskPolicyName:       make([]string, 0),
	}
	if baseResponse.BootUser == "" {
		baseResponse.BootUser = BootRootUser
	}

	// 把仓库信息加上
	if iws.Registry != nil {
		baseResponse.RegistryName = iws.Registry.Name
		baseResponse.RegistryUrl = iws.Registry.Url
		baseResponse.RegistryID = iws.Registry.ID
	}
	if baseResponse.LastSyncAt < time.Now().UnixMilli()/100 && baseResponse.LastSyncAt > 0 {
		baseResponse.LastSyncAt = baseResponse.LastSyncAt * 1000 // 2.11.1之前用的是秒，2.11.1之后统一用的毫秒，中移部分集群还没有升级2.11.2
	}
	if baseResponse.LastSyncAt <= 0 && iws.Registry != nil {
		baseResponse.LastSyncAt = iws.Registry.LastSyncAt
	}
	// 扫描状态
	baseResponse.ScanStatus = GetSubTaskStatusFlagString(image.Flag)
	if len(iws.ScanSubTask) > 0 {
		if iws.ScanSubTask[0].FinishedAt > 0 {
			baseResponse.LastScanAt = iws.ScanSubTask[0].FinishedAt
		}
	} else {
		baseResponse.ScanStatus = ImageNotScan
	}

	if len(iws.Container) > 0 || util.ExistBit1(baseResponse.Flag, model.FlagImageOnline) {
		baseResponse.Online = true
	}

	if iws.NodeInfo != nil {
		baseResponse.NodeHostname = iws.NodeInfo.Hostname
		baseResponse.NodeClusterName = iws.NodeInfo.ClusterName
		baseResponse.NodeClusterKey = iws.NodeInfo.ClusterKey
		baseResponse.NodeUniqueID = iws.NodeInfo.UniqueID
	}
	if util.ExistBit1(image.Flag, model.FlagImageSafe) {
		baseResponse.Safe = model.ImageSafeString
	} else if util.ExistBit1(image.Flag, model.FlagImageUnsafe) {
		baseResponse.Safe = model.ImageUnsafeString
	} else {
		baseResponse.Safe = model.ImageSafeUnknown
	}

	for i := range iws.RiskPolicy {
		baseResponse.RiskPolicyName = append(baseResponse.RiskPolicyName, iws.RiskPolicy[i].Name)
	}
	return baseResponse
}

func (iws *ImageWithCorrelateData2) StaticVuln() ImageVulnSeverityStatic {
	im := ImageVulnSeverityStatic{}
	vulns := iws.Vuln
	for i := range vulns {
		switch vulns[i].SeverityInt {
		case model.SeverityCriticalInt:
			im.Critical++
		case model.SeverityHighInt:
			im.High++
		case model.SeverityMediumInt:
			im.Medium++
		case model.SeverityLowInt:
			im.Low++
		case model.SeverityUnknownInt:
			im.Unknown++
		}
	}
	return im
}

func (iws *ImageWithCorrelateData2) AddDetectResult() {
	if len(iws.DetectResult) == 0 {
		return
	}

	exit := make(map[string]map[uint64]*ImageDetectResult)

	for detectType, detectResult := range iws.DetectResult {
		if exit[detectType] == nil {
			exit[detectType] = make(map[uint64]*ImageDetectResult)
		}
		for i := range detectResult {
			exit[detectType][detectResult[i].UniqueTarget] = detectResult[i]
		}
	}

	for i := range iws.Env {
		ev := iws.Env[i]
		if d, ok := exit[DetectTypeEnvRule][ev.UniqueID]; ok && d != nil {
			ev.PolicyDetect.AddPolicyDetect(d)
		}
	}

	for i := range iws.Pkg {
		ev := iws.Pkg[i]
		if d, ok := exit[DetectTypePkgVersionRule][ev.UniqueID]; ok && d != nil {
			ev.PolicyDetect.AddPolicyDetect(d)
		}
	}

	// license
	for i := range iws.Pkg {
		ev := iws.Pkg[i]
		if d, ok := exit[DetectTypePkgLicenseRule][ev.UniqueID]; ok && d != nil {
			ev.PolicyDetect.AddExceptLicence(d)
		}
	}
	for i := range iws.Vuln {
		ev := iws.Vuln[i]
		if d, ok := exit[DetectTypeVulnRule][ev.UniqueID]; ok && d != nil {
			ev.PolicyDetect.AddPolicyDetect(d)
		}
	}
	for i := range iws.Sensitive {
		ev := iws.Sensitive[i]
		if d, ok := exit[DetectTypeSensRule][ev.UniqueID]; ok && d != nil {
			ev.PolicyDetect.AddPolicyDetect(d)
		}
	}
	for i := range iws.Webshell {
		ev := iws.Webshell[i]
		if d, ok := exit[DetectTypeWebshellRule][ev.UniqueID]; ok && d != nil {
			ev.PolicyDetect.AddPolicyDetect(d)
		}
	}
	for i := range iws.Malware {
		ev := iws.Malware[i]
		if d, ok := exit[DetectTypeMalwareRule][ev.UniqueID]; ok && d != nil {
			ev.PolicyDetect.AddPolicyDetect(d)
		}
	}
}

type ImageOS struct {
	Family     string `json:"family"`
	Name       string `json:"name"`
	Maintained bool   `json:"maintained"`
}

type ImageBaseResponse struct {
	ID                   int64                `json:"id"`
	ImageFromType        string               `json:"imageFromType"`
	UniqueID             uint64               `json:"uniqueID,string"`
	Digest               string               `json:"digest"`
	Online               bool                 `json:"online"`        // 在线 "true",离线："false"
	SecurityIssue        []SecurityIssueLabel `json:"securityIssue"` // 安全问题
	ImageAttr            ImageAttrResponse    `json:"imageAttr"`     // 镜像属性
	UUID                 uint32               `json:"uuid"`          // 镜像uuid
	FullRepoName         string               `json:"fullRepoName"`
	Tag                  string               `json:"tag"`
	Size                 string               `json:"size"`
	Os                   ImageOS              `json:"os"`
	Flag                 uint64               `json:"flag,string"`
	LastSyncAt           int64                `json:"lastSyncAt"` // 上次同步时间(单位：毫秒)
	BootUser             string               `json:"bootUser"`   // 启动用户
	RiskScore            int64                `json:"riskScore"`
	Suggests             []ImageSuggest       `json:"suggests"`
	ScanStatus           string               `json:"scanStatus"`
	LastScanAt           int64                `json:"lastScanAt"` // 扫描完成时间戳(单位毫秒)
	RegistryID           int64                `json:"registryId"`
	RegistryName         string               `json:"registryName"`
	RegistryUrl          string               `json:"registryUrl"`
	Project              string               `json:"project"`
	VulnSeverityOverview []SeverityGroup      `json:"vulnSeverityOverview"` // 漏洞统计

	// 节点镜像新增
	NodeHostname    string                  `json:"nodeHostname"`
	NodeClusterName string                  `json:"nodeClusterName"`
	NodeClusterKey  string                  `json:"nodeClusterKey"`
	NodeUniqueID    uint64                  `json:"nodeUniqueID,string"`
	VulnStatic      ImageVulnSeverityStatic `json:"vulnStatic"`
	RiskPolicyName  []string                `json:"riskPolicyName"` // 镜像的风险来源
	RiskPolicy      []*SecurityPolicy       `json:"riskPolicy"`     // 镜像的风险来源
	TotalPolicy     []*SecurityPolicy       `json:"totalPolicy"`    // 已使用的安全策略
	Safe            string                  `json:"safe"`           // 镜像安全状态
}

func (vi *ImageBaseResponse) AdaptI18(ctx context.Context) {
	lang, ok := ctx.Value(AcceptLanguage).(string)
	if ok && lang == model.LangEn {
		for i := range vi.Suggests {
			vi.Suggests[i].Title = SuggestTile()[vi.Suggests[i].Title]
		}
	}
}

func (vi *ImageBaseResponse) SuggestsString() string {
	res := make([]string, 0)
	for i := range vi.Suggests {
		if len(vi.Suggests[i].Data) == 0 {
			continue
		}
		res = append(res, vi.Suggests[i].Title)
		res = append(res, vi.Suggests[i].Data...)
	}

	return strings.Join(res, "\n")
}

func (vi *ImageBaseResponse) GetOSView() string {
	if vi.Os.Family == "" || vi.Os.Name == "" {
		return ""
	}
	return vi.Os.Family + ":" + vi.Os.Name
}

type ImageVulnSeverityStatic struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Unknown  int64 `json:"unknown"`
}

func (vi *ImageBaseResponse) GetImageName() string {

	imageName := vi.FullRepoName

	if vi.RegistryUrl != "" {
		imageName = fmt.Sprintf("%s/%s", vi.RegistryUrl, imageName)
	}
	if vi.Tag != "" {
		imageName = fmt.Sprintf("%s:%s", imageName, vi.Tag)
	}
	if vi.RegistryName != "" {
		imageName = fmt.Sprintf("(%s)%s", vi.RegistryName, imageName)
	}

	return imageName
}

func ParseConfigEnv(env []*ImageEnv) string {
	res := make([]string, 0)
	for i := range env {
		if env[i].PolicyDetect.Exception {
			res = append(res, env[i].Key)
		}
	}
	return strings.Join(res, ",")
}

func ParseSoftWare(soft []*Pkg) string {
	if len(soft) == 0 {
		return ""
	}
	lit := make([]string, 0)
	for i := range soft {
		if soft[i].Name != "" && soft[i].Version != "" && util.ExistBit1(soft[i].Flag, model.FlagHasExceptPKG) {
			lit = append(lit, fmt.Sprintf("%s(%s)", soft[i].Name, soft[i].Version))
		}
	}

	return strings.Join(lit, ",")
}

func ParseLicense(soft []*Pkg) string {
	if len(soft) == 0 {
		return ""
	}
	lit := make([]string, 0)
	for i := range soft {
		if len(soft[i].License) > 0 && util.ExistBit1(soft[i].Flag, model.FlagHasExceptLicense) {
			lit = append(lit, soft[i].License...)
		}
	}

	return strings.Join(lit, ",")
}

func CalculateWebshellScore(sesCnt int64) int64 {
	if sesCnt > 0 {
		return model.MaxWebshellScore
	}
	return 0
}

func CalculateMalwareScore(sesCnt int64) int64 {
	if sesCnt > 0 {
		return model.MaxVirusScore
	}
	return 0
}

func CalculateSensitiveScore(sesCnt int64) int64 {
	score := model.SingleSensitiveScore * sesCnt
	if score > model.MaxSensitiveScore {
		return model.MaxSensitiveScore
	}
	return int64(score)
}

func CalculateVulnScore(vulns []*VulnView) int64 {
	constMapScore := map[string]int64{
		model.SeverityCRITICALString: 25,
		model.SeverityHIGHString:     20,
		model.SeverityMEDIUMString:   15,
		model.SeverityLOWString:      10,
		model.SeverityUNKNOWNString:  5,
	}
	var score int64
	exit := make(map[string]int64)
	for _, vuln := range vulns {
		sv := strings.ToUpper(vuln.Severity)
		exit[sv] = constMapScore[sv]
	}
	for _, v := range exit {
		score += v
	}

	if score > model.MaxVulnScore {
		return model.MaxVulnScore
	}

	return score
}

type ImageContainerResources struct {
	ImageUUID    uint32 `json:"imageUUID"`
	Name         string `json:"name"`
	ResourceName string `json:"resourceName"`
	Namespace    string `json:"namespace"`
	ClusterKey   string `json:"clusterKey"`
	ClusterName  string `json:"clusterName"`
}
