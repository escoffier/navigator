package imagesec

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageSearchApiParam struct {
	ImageFromType          string   `json:"imageFromType"`
	OnlineStr              []string `json:"onlineStr"` // 在线 "true",离线："false" // 节点镜像使用
	NodeKeyword            string   `json:"nodeKeyword"`
	ImageKeyword           string   `json:"imageKeyword"`
	RegistryKeyword        string   `json:"registryKeyword"`
	PolicyUniqueID         []string `json:"policyUniqueID"`
	PolicyIntersection     string   `json:"policyIntersection"`
	SecurityIssue          []string `json:"securityIssue"`   // 安全问题,镜像属性也放在这里
	RegIds                 []int64  `json:"regIds"`          // 仓库ID
	ImageAttrView          []string `json:"imageAttr"`       // 镜像属性,前端以列表的方式传递
	SafeAttr               []string `json:"safeAttr"`        // safe，unsafe,unknown
	VulnStatic             []string `json:"vulnStatic"`      // 镜像漏洞统计
	ImageIds               []int64  `json:"imageIds"`        // 镜像ID列表
	ImageID                int64    `json:"imageID"`         // 镜像ID
	ScanStatus             []string `json:"scanStatus"`      // 扫描状态
	JustReturnImage        bool     `json:"justReturnImage"` // 只需要镜像信息，不需要镜像关联信息
	ReturnMalicious        bool     `json:"returnMalicious"` // 是否返回恶义文件
	UUIDs                  []uint32 `json:"uuids"`           // 镜像uuid
	UniqueIds              []uint64 `json:"uniqueIds"`
	UniqueId               uint64   `json:"uniqueId,string"`
	Projects               []string `json:"projects"`               // 仓库和repo的筛选
	AttrIntersection       string   `json:"attrIntersection"`       // 属性交集还是并集 and or
	IssueIntersection      string   `json:"issueIntersection"`      // 安全问题交集还是并集 and or
	VulnStaticIntersection string   `json:"vulnStaticIntersection"` // 漏洞统计交集还是并集 and or
	StartID                int64    `json:"startID"`                // 分页请求时，上一页最后一条数据的ID
	Creator                string   `json:"creator"`                // 扫描任务的操作
	ClusterKey             []string `json:"clusterKey"`
	Digests                []string `json:"digests"`
	// 部署上线特有
	DeployAction    []string        `json:"deployAction"`
	StartTime       int64           `json:"startTime"`
	EndTime         int64           `json:"endTime"`
	CheckRegDeleted string          `json:"checkRegDeleted"` // 检查镜像所属仓库是否删除
	AssetImage      []ImageWithUuid `json:"assetImage"`      // 资产查镜像
	// 以下几个查询关联镜像，单独的接口
	WebshellMD5  string `json:"webshellMd5"`
	MalwareMD5   string `json:"malwareMD5"`
	SensitiveMD5 string `json:"sensitiveMD5"`
	VulnUniqueID uint64 `json:"vulnUniqueID"`
	PkgUniqueID  uint64 `json:"pkgUniqueID"`

	AssociateParam ImageAssociateParam `json:"associateParam"`
	Fields         []string            `json:"fields"`
	Filter         *model.Filter
}

func (sp *ImageSearchApiParam) ToImageDalParam() ImageDalParam {

	if sp.IssueIntersection == "" {
		sp.IssueIntersection = OrString
	}
	if sp.AttrIntersection == "" {
		sp.AttrIntersection = OrString
	}
	if sp.PolicyIntersection == "" {
		sp.PolicyIntersection = OrString
	}
	if sp.VulnStaticIntersection == "" {
		sp.VulnStaticIntersection = OrString
	}
	daoParam := ImageDalParam{
		ImageFromType:          sp.ImageFromType,
		ImageIds:               sp.ImageIds,
		ImageKeyword:           strings.TrimSpace(sp.ImageKeyword),
		NodeKeyword:            strings.TrimSpace(sp.NodeKeyword),
		RegKeyword:             strings.TrimSpace(sp.RegistryKeyword),
		StartID:                sp.StartID,
		Fields:                 sp.Fields,
		UUIDs:                  sp.UUIDs,
		UniqueIds:              sp.UniqueIds,
		UniqueId:               sp.UniqueId,
		WebshellMD5:            sp.WebshellMD5,
		MalwareMD5:             sp.MalwareMD5,
		SensitiveMD5:           sp.SensitiveMD5,
		AttrIntersection:       sp.AttrIntersection,
		IssueIntersection:      sp.IssueIntersection,
		VulnStaticIntersection: sp.VulnStaticIntersection,
		Digests:                sp.Digests,
		NotNeedCount:           false,
		ClusterKey:             sp.ClusterKey,
		RegIds:                 sp.RegIds,
		VulnUniqueID:           sp.VulnUniqueID,
		PolicyIntersection:     sp.PolicyIntersection,
		PolicyUniqueID:         sp.PolicyUniqueID,
		Filter:                 sp.Filter,
		StartTime:              sp.StartTime,
		EndTime:                sp.EndTime,
		VulnStaticFlag:         sp.GenVulnStaticFlag(),
		SafeAttrFlag:           sp.GenSafeAttrFlag(),
		SecurityIssueFlag:      sp.GenSecurityIssueFlag(),
		OnlineFlag:             sp.GenOnlineFlag(),
		DeployActionFlag:       sp.GenDeployActionFlag(),
		ImageAttrFlag:          sp.GenImageAttrFlag(),
		CheckRegDeleted:        sp.CheckRegDeleted,
	}

	repos := make([]SearchProjectParam, 0)
	for _, v := range sp.Projects {
		split := strings.Split(v, ",")
		// 说明只是registryID的筛选
		if len(split) == 1 && split[0] != "" {
			regID, err := strconv.ParseInt(split[0], 10, 64)
			if err != nil {
				logging.Get().Error().Str("project", v).Msg("project param incorrect")
				continue
			}
			repos = append(repos, SearchProjectParam{RegID: regID})
		}
		if len(split) == 2 && split[0] != "" && split[1] != "" {
			regID, err := strconv.ParseInt(split[0], 10, 64)
			if err != nil {
				logging.Get().Error().Str("project", v).Msg("project param incorrect")
				continue
			}
			repos = append(repos, SearchProjectParam{RegID: regID, ProjectName: split[1]})
		}
	}
	daoParam.Projects = repos

	return daoParam
}

func (sp *ImageSearchApiParam) Check() error {
	return nil
}

func (sp *ImageSearchApiParam) GenSafeAttrFlag() uint64 {
	// 镜像是否安全
	var safeAttrFlag uint64
	for i := range sp.SafeAttr {
		switch sp.SafeAttr[i] {
		case ImageSafeString:
			safeAttrFlag = util.SetBit1(safeAttrFlag, FlagImageSafe)
		case ImageUnsafeString:
			safeAttrFlag = util.SetBit1(safeAttrFlag, FlagImageUnsafe)
		case ImageSafeUnknown:
			safeAttrFlag = util.SetBit1(safeAttrFlag, FlagImageSafeUnknown)
		}
	}
	return safeAttrFlag
}

// 生成属性的flag
func (sp *ImageSearchApiParam) GenImageAttrFlag() uint64 {
	var flag uint64
	for i := range sp.ImageAttrView {
		switch sp.ImageAttrView[i] {
		case BaseImageTypeString:
			flag = util.SetBit1(flag, FlagBaseImage)
		case AppImageTypeString:
			flag = util.SetBit1(flag, FlagAppImage)
		case HasFixedVulnString:
			flag = util.SetBit1(flag, FlagHasFixedVuln)
		}
	}
	return flag
}

func (sp *ImageSearchApiParam) GenDeployActionFlag() uint64 {
	var flag uint64
	for i := range sp.DeployAction {
		switch sp.DeployAction[i] {
		case DeployActionBlock:
			flag = util.SetBit1(flag, FlagImageDeployBlock)
		case DeployActionPass:
			flag = util.SetBit1(flag, FlagImageDeployPassed)
		case DeployActionAlarm:
			flag = util.SetBit1(flag, FlagImageDeployPassed)
		}
	}
	return flag
}

func (sp *ImageSearchApiParam) GenOnlineFlag() uint64 {
	// 镜像是否安全
	var safeAttrFlag uint64
	for i := range sp.OnlineStr {
		switch sp.OnlineStr[i] {
		case TrueString:
			safeAttrFlag = util.SetBit1(safeAttrFlag, FlagImageOnline)
		case FalseString:
			safeAttrFlag = util.SetBit1(safeAttrFlag, FlagImageNotOnline)
		}
	}
	return safeAttrFlag
}

func (sp *ImageSearchApiParam) GenVulnStaticFlag() uint64 {
	// 镜像漏洞筛选
	var imageVulnStaticFlag uint64
	for i := range sp.VulnStatic {
		switch strings.ToUpper(sp.VulnStatic[i]) {
		case SeverityCritical:
			imageVulnStaticFlag = util.SetBit1(imageVulnStaticFlag, FlagImageHasCriticalVuln)
		case SeverityHigh:
			imageVulnStaticFlag = util.SetBit1(imageVulnStaticFlag, FlagImageHasHighVuln)
		case SeverityMedium:
			imageVulnStaticFlag = util.SetBit1(imageVulnStaticFlag, FlagImageHasMediumVuln)
		case SeverityLow:
			imageVulnStaticFlag = util.SetBit1(imageVulnStaticFlag, FlagImageHasLowVuln)
		case SeverityUnknown:
			imageVulnStaticFlag = util.SetBit1(imageVulnStaticFlag, FlagImageHasUnknownVun)
		}
	}
	return imageVulnStaticFlag
}

func (sp *ImageSearchApiParam) GenSecurityIssueFlag() uint64 {
	// 镜像问题
	var flag uint64
	for i := range sp.SecurityIssue {
		switch sp.SecurityIssue[i] {
		case TrustedString:
			flag = util.SetBit1(flag, FlagImageTrusted)
		case UnTrustedString:
			flag = util.SetBit1(flag, FlagImageDetectUnTrusted)
		case HasFixedVulnString:
			flag = util.SetBit1(flag, FlagHasFixedVuln)
		case ImageHasSuggestionString:
			flag = util.SetBit1(flag, FlagImageHasFixSuggest)
		case ImageNotInReg:
			flag = util.SetBit1(flag, FlagImageDetectNotExitINReg)
		case ExceptionVuln:
			flag = util.SetBit1(flag, FlagHasExceptionVuln)
		case ExceptionMalware:
			flag = util.SetBit1(flag, FlagHasExceptionMalware)
		case ExceptionSensitive:
			flag = util.SetBit1(flag, FlagHasExceptionSensitive)
		case ExceptionWebshell:
			flag = util.SetBit1(flag, FlagHasExceptionWebshell)
		case ExceptionPKG:
			flag = util.SetBit1(flag, FlagHasExceptionPKG)
		case ExceptionEnv:
			flag = util.SetBit1(flag, FlagHasExceptionEnv)
		case ExceptionBoot:
			flag = util.SetBit1(flag, FlagDetectExceptionBoot)
		case ExceptionPkgLicense:
			flag = util.SetBit1(flag, FlagHasExceptionPkgLicense)
		case ExceptionLicense:
			flag = util.SetBit1(flag, FlagHasExceptionLicense)
		case ImageNotScanned:
			flag = util.SetBit1(flag, FlagImageNotScanned)
		case ImageNotExitBaseImage:
			flag = util.SetBit1(flag, FlagNotExitBaseImage)
		}
	}
	return flag
}

// 镜像属性
type ImageWithUuid struct {
	Name string `json:"name"`
	UUID uint32 `json:"uuid"`
}

type ImageAttrResponse struct {
	ImageType     string `json:"imageType"`    // 镜像类型,基础镜像："base",应用镜像："app"
	HasFixedVuln  bool   `json:"hasFixedVuln"` // 是否包含可修复漏洞: 是:true,否：false
	HasFixSuggest bool   `json:"hasFixSuggest"`
}

type ImageAssociateParam struct {
	ImageFromType         string
	ImageId               int64  // 对于仓库镜像这个参数是必须的
	ImageUniqueID         uint64 // 对于节点镜像这个对数是必须的，后续仓库镜像也要整合到这里
	DeployRecordID        int64  // 部署上线的记录 ID
	VulnEnable            bool
	MalwareEnable         bool
	EnvEnable             bool
	PkgEnable             bool
	LicenseEnable         bool
	ImageLicenseEnable    bool
	SensitiveEnable       bool
	WebshellEnable        bool
	ContainerEnable       bool
	SubtaskEnable         bool
	RegistryEnable        bool
	ScanInstanceEnable    bool
	BaseImageEnable       bool
	AppImageEnable        bool
	CheckDownloadable     bool
	AllPkgVuln            bool                  // 获取软件包对应的所有漏洞
	TrustedEnable         bool                  // 查可digest 是否是可信
	ImageInReg            bool                  // 查看节点镜像及部署上线的镜像是否在仓库中
	NodeInfoEnable        bool                  // 查询节点镜像的节点信息
	RiskPolicyEnable      bool                  // 查风险来源
	SimplePolicyEnable    bool                  // 查看命中的策略
	DetectResultEnable    bool                  // 查看检测结果
	ScanResultSearchParam ScanResultSearchParam // 除了漏洞之外其他扫描结果的查询
	SearchVulnParam       ApiSearchVulnParam    // 漏洞查询
	DetectParam           DetectResultParam
}

func (vi *ImageAssociateParam) GetDetectTypes() []string {
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
		ans = append(ans, DetectTypeLicenseRule)
	}
	if vi.MalwareEnable {
		ans = append(ans, DetectTypeMalwareRule)
	}
	if vi.SensitiveEnable {
		ans = append(ans, DetectTypeSensRule)
	}
	if vi.PkgEnable {
		ans = append(ans, DetectTypePkgRule)
	}
	ans = append(ans, DetectTypeRootRule)
	ans = append(ans, DetectTypeTrustedImageRule)
	ans = append(ans, DetectTypeExistInRegRule)
	return ans
}

type DetectResultParam struct {
	SecurityPolicyIds []int64 `json:"securityPolicyIds"` // 检测策略ID
	AllPolicy         bool    `json:"allPolicy"`
}

type RelatedSearchParam struct {
	VulnUniqueID uint64 `json:"vulnUniqueID,string"`
	PkgUniqueID  uint64 `json:"pkgUniqueID,string"`
	WebshellMD5  string `json:"webshellMd5"`
	SensitiveMd5 string `json:"sensitiveMd5"`
	MalwareMd5   string `json:"malwareMd5"`
	ImageKeyword string `json:"imageKeyword"`
	Filter       *model.Filter
}

func (vi *RelatedSearchParam) Check() error {
	if vi.WebshellMD5+vi.SensitiveMd5+vi.MalwareMd5 == "" && vi.VulnUniqueID+vi.PkgUniqueID == 0 {
		return fmt.Errorf("not get condition")
	}
	return nil
}

type ScanResultSearchParam struct {
	ImageFromType       string   `json:"imageFromType"`
	ImageID             int64    `json:"imageID"`
	ImageUniqueID       uint64   `json:"imageUniqueID,string"`
	VulnUniqueID        uint64   `json:"vulnUniqueID,string"`
	VulnName            string   `json:"vulnName"`
	LayerDigest         string   `json:"layerDigest"`
	Keyword             string   `json:"keyword"`
	ExceptionPkg        string   `json:"exceptionPkg"`
	ExceptionPkgLicense string   `json:"exceptionPkgLicense"`
	ExceptionEnv        string   `json:"exceptionEnv"`
	PasswdEnv           string   `json:"passwdEnv"`
	ExceptionVuln       string   `json:"exceptionVuln"`
	ExceptionLicense    string   `json:"exceptionLicense"`
	ExceptionMalware    string   `json:"exceptionMalware"`
	ExceptionSensitive  string   `json:"exceptionSensitive"`
	ExceptionWebshell   string   `json:"exceptWebshell"`
	VulnSeverity        []string `json:"vulnSeverity"`
	LicenseSearch       []string `json:"licenseSearch"`     // 开源协议筛选
	UniqueIds           []uint64 `json:"uniqueIds"`         //
	WebshellRiskLevel   []string `json:"webshellRiskLevel"` //
	DeployRecordID      int64    `json:"deployRecordID"`
	DeployAction        string   `json:"deployAction"`
	OmitFields          []string // 数据库中不查询的字段
	Fields              []string // 数据库中查询的字段
	SecurityPolicyIds   []int64  `json:"securityPolicyIds"` // 检测策略ID

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

func (vi *ImageAssociateParam) Check() error {
	if vi.ImageId <= 0 && vi.ImageUniqueID <= 0 && vi.DeployRecordID <= 0 {
		return fmt.Errorf("no image id or deploy record id")
	}
	return nil
}

func (vi *ImageAssociateParam) Deserialize() {
	vi.ScanResultSearchParam.ImageID = vi.ImageId
	vi.ScanResultSearchParam.ImageUniqueID = vi.ImageUniqueID
	vi.SearchVulnParam.ImageID = vi.ImageId
	vi.SearchVulnParam.ImageUniqueID = vi.ImageUniqueID
	vi.ScanResultSearchParam.Keyword = strings.ToLower(vi.ScanResultSearchParam.Keyword)
	vi.ScanResultSearchParam.ImageFromType = vi.ImageFromType
	vi.SearchVulnParam.ImageFromType = vi.ImageFromType

	if vi.DeployRecordID > 0 && vi.ImageFromType == ImageFromDeploy {
		vi.NodeInfoEnable = false
		vi.RegistryEnable = false
		vi.ScanInstanceEnable = false
		vi.SubtaskEnable = false
		vi.DetectResultEnable = false
		vi.ContainerEnable = false
		vi.AllPkgVuln = true // 查的是软件下的所有漏洞

		vi.ScanResultSearchParam.ImageUniqueID = 0
		vi.ScanResultSearchParam.ImageID = 0
		vi.SearchVulnParam.ImageID = 0
		vi.SearchVulnParam.ImageUniqueID = 0
		vi.ImageUniqueID = 0
		vi.ImageId = 0
	}
}

type CreateScanTaskInfo struct {
	Scope        int    `json:"scope"`
	TriggerType  int    `json:"triggerType"`  // 扫描类型
	StrategyID   int64  `json:"strategyId"`   // 扫描策略ID
	StrategyName string `json:"strategyName"` // 扫描策略名字 用于openapi
	Operator     string `json:"operator"`     // 操作人
}

// 资产也在用，// imageProblems 这个接口
type SecurityIssueLabel struct {
	Value   string `json:"value"`   // 安全问题的ID
	LabelZH string `json:"labelZH"` // 安全问题
	LabelEN string `json:"labelEN"` // 安全问题:英文
	Info    string `json:"info"`    // 详细信息
}

type ImageWithCorrelateData2 struct {
	Image             Image
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
	License           []*License // 异常的license
	LicenseCnt        int64
	Malware           []*Malware
	MalwareCnt        int64
	BaseImages        []*ImageBaseResponse // 基础镜像列表
	BaseImageCnt      int64
	AppImages         []*ImageBaseResponse // 应用镜像列表
	AppImageCnt       int64
	Container         []*RawContainer
	ScanSubTask       []*ImageScanSubTask
	SubTaskCnt        int64
	RootBoot          []RootBoot
	TrustedImage      []TrustedImage
	ImageInReg        []ImageInReg
	Registry          *Registry
	NodeInfo          *NodeInfo
	// TrustedDigest     []string
	ScanInstance *ScannerInstanceInfo
	// RegIds            []int64
	RiskPolicy    []SecurityPolicy                // 镜像的风险来源
	TotalPolicy   []SecurityPolicy                // 已使用的安全策略
	DetectResult  map[string][]*ImageDetectResult // 检测结果
	DeployRecord  *DeployRecord                   // 阻断结果
	DeployInWhite bool                            // 是否在白名单中
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

func (iws *ImageWithCorrelateData2) ExceptionFilter(param ScanResultSearchParam) *ImageWithCorrelateData2 {

	if param.ExceptionPkgLicense == TrueString || param.DeployAction != "" || param.ExceptionPkg == TrueString {
		pkg := make([]*Pkg, 0)
		for i := range iws.Pkg {
			add := false

			// 1:不做筛选
			if param.ExceptionPkgLicense != TrueString && param.ExceptionPkg != TrueString && param.DeployAction == "" {
				add = true
			}

			// 又变了，取并集了 https://project.feishu.cn/tensorsecurity/issue/detail/16674613
			if iws.Pkg[i].PolicyDetect.ExceptionPkgLicense && param.ExceptionPkgLicense == TrueString {
				add = true
			}
			if iws.Pkg[i].PolicyDetect.Exception && param.ExceptionPkg == TrueString {
				add = true
			}

			if param.DeployAction != "" && iws.Pkg[i].PolicyDetect.DeployAction == param.DeployAction {
				add = true
			}

			if add {
				pkg = append(pkg, iws.Pkg[i])
			}
		}
		iws.Pkg = pkg
		iws.PkgCnt = int64(len(pkg))
	}

	if param.ExceptionLicense == TrueString || param.DeployAction != "" {
		license := make([]*License, 0)
		for i := range iws.License {
			add := true
			if !iws.License[i].PolicyDetect.Exception && param.ExceptionLicense == TrueString {
				add = false
			}
			if param.DeployAction != "" && iws.License[i].PolicyDetect.DeployAction != param.DeployAction {
				add = false
			}
			if add {
				license = append(license, iws.License[i])
			}
		}
		iws.License = license
		iws.LicenseCnt = int64(len(license))
	}

	if param.ExceptionEnv == TrueString || param.DeployAction != "" || param.PasswdEnv == TrueString {
		data := make([]*ImageEnv, 0)
		for i := range iws.Env {
			add := false

			// 1:不做筛选
			if param.ExceptionEnv != TrueString && param.PasswdEnv != TrueString && param.DeployAction == "" {
				add = true
			}

			// 又变了，取并集了 https://project.feishu.cn/tensorsecurity/issue/detail/16674613
			if iws.Env[i].PolicyDetect.Exception && param.ExceptionEnv == TrueString {
				add = true
			}
			if iws.Env[i].PolicyDetect.PasswdEnv && param.PasswdEnv == TrueString {
				add = true
			}

			if param.DeployAction != "" && iws.Env[i].PolicyDetect.DeployAction == param.DeployAction {
				add = true
			}

			if add {
				data = append(data, iws.Env[i])
			}
		}
		iws.Env = data
		iws.EnvCnt = int64(len(data))
	}

	if param.ExceptionVuln == TrueString || param.DeployAction != "" {
		data := make([]*VulnView, 0)
		for i := range iws.Vuln {
			add := true

			if !iws.Vuln[i].PolicyDetect.Exception && param.ExceptionVuln == TrueString {
				add = false
			}
			if param.DeployAction != "" && iws.Vuln[i].PolicyDetect.DeployAction != param.DeployAction {
				add = false
			}

			if add {
				data = append(data, iws.Vuln[i])
			}
		}
		iws.Vuln = data
		iws.VulnCnt = int64(len(data))
	}

	if param.ExceptionSensitive == TrueString || param.DeployAction != "" {
		data := make([]*SensitiveFile, 0)
		for i := range iws.Sensitive {
			add := true
			if !iws.Sensitive[i].PolicyDetect.Exception && param.ExceptionSensitive == TrueString {
				add = false
			}
			if param.DeployAction != "" && iws.Sensitive[i].PolicyDetect.DeployAction != param.DeployAction {
				add = false
			}

			if add {
				data = append(data, iws.Sensitive[i])
			}
		}
		iws.Sensitive = data
		iws.SensitiveCnt = int64(len(data))
	}

	if param.ExceptionMalware == TrueString || param.DeployAction != "" {
		data := make([]*Malware, 0)
		for i := range iws.Malware {
			add := true
			if !iws.Malware[i].PolicyDetect.Exception && param.ExceptionMalware == TrueString {
				add = false
			}
			if param.DeployAction != "" && iws.Malware[i].PolicyDetect.DeployAction != param.DeployAction {
				add = false
			}
			if add {
				data = append(data, iws.Malware[i])
			}
		}
		iws.Malware = data
		iws.MalwareCnt = int64(len(data))
	}

	if param.ExceptionWebshell == TrueString || param.DeployAction != "" {
		data := make([]*WebshellView, 0)
		for i := range iws.Webshell {
			add := true
			if !iws.Webshell[i].PolicyDetect.Exception && param.ExceptionWebshell == TrueString {
				add = false
			}
			if param.DeployAction != "" && iws.Webshell[i].PolicyDetect.DeployAction != param.DeployAction {
				add = false
			}
			if add {
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
	if filter == nil || filter.Limit <= 0 {
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
		iws.License = make([]*License, 0)
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

func SuggestEnTile() map[string]string {
	en := map[string]string{
		VulnSuggestTitle:     "it is recommended to use following command in  Dockerfile to upgrade the package:",
		MalwareSuggestTitle:  "it is recommended to delete the Trojan virus files and investigate the source of the files:",
		WebshellSuggestTitle: "it is recommended to delete related backdoors and investigate the source of the files:",
		SensSuggestTitle:     "it is recommended to remove the following sensitive files from the image, and then repackage the image:",
	}
	return en
}

func (iws *ImageWithCorrelateData2) GenSensitiveFileSuggest() ImageSuggest {

	files := make([]string, 0)

	for i := range iws.Sensitive {
		file := iws.Sensitive[i]
		files = append(files, file.GenFullFilename())
	}
	files = util.DuplicateStringSlice(files)
	return ImageSuggest{Data: files, Title: SensSuggestTitle}
}

func (iws *ImageWithCorrelateData2) GenWebshellSuggest() ImageSuggest {
	files := make([]string, 0)

	for i := range iws.Webshell {
		wb := iws.Webshell[i]
		files = append(files, wb.GenFullFilename())
	}
	files = util.DuplicateStringSlice(files)
	return ImageSuggest{Data: files, Title: WebshellSuggestTitle}
}

func (iws *ImageWithCorrelateData2) GenMalwareSuggest() ImageSuggest {
	files := make([]string, 0)

	for i := range iws.Malware {
		files = append(files, iws.Malware[i].GenFullFilename())
	}
	files = util.DuplicateStringSlice(files)
	return ImageSuggest{Data: files, Title: MalwareSuggestTitle}
}

func (iws *ImageWithCorrelateData2) GenSafe() string {
	imageFlag := iws.Image.Flag
	if util.ExistBit1(imageFlag, FlagImageSafe) {
		return DeployModSafe
	}
	if util.ExistBit1(imageFlag, FlagImageUnsafe) {
		return ImageUnsafeString
	}
	return ImageSafeUnknown
}

func (iws *ImageWithCorrelateData2) GenAction() string {
	imageFlag := iws.Image.Flag
	if util.ExistBit1(imageFlag, FlagImageDeployWhite) {
		return DeployActionPass
	}
	if util.ExistBit1(imageFlag, FlagImageDeployBlock) {
		return DeployActionBlock
	}
	if util.ExistBit1(imageFlag, FlagImageDeployPassed) {
		return DeployActionPass
	}
	if util.ExistBit1(imageFlag, FlagImageDeployAlarm) {
		return DeployActionAlarm
	}
	return DeployActionPass
}

func (iws *ImageWithCorrelateData2) GetImageAttr() ImageAttrResponse {
	attr := ImageAttrResponse{}

	imageFlag := iws.Image.Flag

	if util.ExistBit1(imageFlag, FlagBaseImage) {
		attr.ImageType = BaseImageTypeString
	} else if util.ExistBit1(imageFlag, FlagAppImage) {
		attr.ImageType = AppImageTypeString
	}
	if util.ExistBit1(imageFlag, FlagHasFixedVuln) {
		attr.HasFixedVuln = true
	}
	if util.ExistBit1(imageFlag, FlagImageHasFixSuggest) {
		attr.HasFixSuggest = true
	}

	return attr
}

func (iws *ImageWithCorrelateData2) GetSecurityIssue() []SecurityIssueLabel {
	securityIssue := make([]SecurityIssueLabel, 0)
	imageFlag := iws.Image.Flag

	if util.ExistBit1(imageFlag, FlagHasExceptionVuln) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value:   ExceptionVuln,
			LabelZH: GetSecurityIssueLabelZH(FlagHasExceptionVuln),
			LabelEN: GetSecurityIssueLabelEN(FlagHasExceptionVuln),
		})
	}
	if util.ExistBit1(imageFlag, FlagHasExceptionSensitive) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value:   ExceptionSensitive,
			LabelZH: GetSecurityIssueLabelZH(FlagHasExceptionSensitive),
			LabelEN: GetSecurityIssueLabelEN(FlagHasExceptionSensitive),
		})
	}
	if util.ExistBit1(imageFlag, FlagNotExitBaseImage) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value:   ImageNotExitBaseImage,
			LabelZH: GetSecurityIssueLabelZH(FlagNotExitBaseImage),
			LabelEN: GetSecurityIssueLabelEN(FlagNotExitBaseImage),
		})
	}
	if util.ExistBit1(imageFlag, FlagHasExceptionMalware) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value:   ExceptionMalware,
			LabelZH: GetSecurityIssueLabelZH(FlagHasExceptionMalware),
			LabelEN: GetSecurityIssueLabelEN(FlagHasExceptionMalware),
		})
	}
	if util.ExistBit1(imageFlag, FlagHasExceptionWebshell) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value:   ExceptionWebshell,
			LabelZH: GetSecurityIssueLabelZH(FlagHasExceptionWebshell),
			LabelEN: GetSecurityIssueLabelEN(FlagHasExceptionWebshell),
		})
	}
	if util.ExistBit1(imageFlag, FlagHasExceptionEnv) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value:   ExceptionEnv,
			LabelZH: GetSecurityIssueLabelZH(FlagHasExceptionEnv),
			LabelEN: GetSecurityIssueLabelEN(FlagHasExceptionEnv),
			Info:    ParseConfigEnv(iws.Env),
		})
	}
	if util.ExistBit1(imageFlag, FlagHasExceptionPkgLicense) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value:   ExceptionPkgLicense,
			LabelZH: GetSecurityIssueLabelZH(FlagHasExceptionPkgLicense),
			LabelEN: GetSecurityIssueLabelEN(FlagHasExceptionPkgLicense),
			Info:    ParseLicense(iws.Pkg)})
	}

	if util.ExistBit1(imageFlag, FlagHasExceptionPKG) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value:   ExceptionPKG,
			LabelZH: GetSecurityIssueLabelZH(FlagHasExceptionPKG),
			LabelEN: GetSecurityIssueLabelEN(FlagHasExceptionPKG),
			Info:    ParseLicense(iws.Pkg)})
	}
	if util.ExistBit1(imageFlag, FlagHasExceptionLicense) {
		securityIssue = append(securityIssue, SecurityIssueLabel{
			Value:   ExceptionLicense,
			LabelZH: GetSecurityIssueLabelZH(FlagHasExceptionLicense),
			LabelEN: GetSecurityIssueLabelEN(FlagHasExceptionLicense),
			Info:    ParseSoftWare(iws.Pkg)})
	}
	if util.ExistBit1(imageFlag, FlagDetectExceptionBoot) {
		securityIssue = append(securityIssue,
			SecurityIssueLabel{
				Value:   ExceptionBoot,
				LabelZH: GetSecurityIssueLabelZH(FlagDetectExceptionBoot),
				LabelEN: GetSecurityIssueLabelEN(FlagDetectExceptionBoot)})
	}
	// 节点镜像没有可信、非可信的问题，但是有仓库镜像和非仓库镜像
	if iws.Image.ImageFromType != ImageFromNode {
		if util.ExistBit1(imageFlag, FlagImageDetectUnTrusted) {
			securityIssue = append(securityIssue,
				SecurityIssueLabel{
					Value:   UnTrustedString,
					LabelZH: GetSecurityIssueLabelZH(FlagImageDetectUnTrusted),
					LabelEN: GetSecurityIssueLabelEN(FlagImageDetectUnTrusted)})
		}
	}
	// 现在归类到属性中的
	// if util.ExistBit1(imageFlag, FlagHasFixedVuln) {
	// 	securityIssue = append(securityIssue,
	// 		SecurityIssueLabel{
	// 			Value:   HasFixedVulnString,
	// 			LabelZH: GetSecurityIssueLabelZH(FlagHasFixedVuln),
	// 			LabelEN: GetSecurityIssueLabelEN(FlagHasFixedVuln)})
	// }

	if util.ExistBit1(imageFlag, FlagImageNotScanned) {
		securityIssue = append(securityIssue,
			SecurityIssueLabel{
				Value:   ImageNotScanned,
				LabelZH: GetSecurityIssueLabelZH(FlagImageNotScanned),
				LabelEN: GetSecurityIssueLabelEN(FlagImageNotScanned)})
	}

	// if util.ExistBit1(imageFlag, FlagImageHasFixSuggest) {
	// 	securityIssue = append(securityIssue,
	// 		SecurityIssueLabel{
	// 			Value:   ImageHasSuggestionString,
	// 			LabelZH: GetSecurityIssueLabelZH(FlagImageHasFixSuggest),
	// 			LabelEN: GetSecurityIssueLabelEN(FlagImageHasFixSuggest)})
	// }
	if iws.Image.ImageFromType != ImageFromRegistry {
		if util.ExistBit1(imageFlag, FlagImageDetectNotExitINReg) {
			securityIssue = append(securityIssue,
				SecurityIssueLabel{
					Value:   ImageNotInReg,
					LabelZH: GetSecurityIssueLabelZH(FlagImageDetectNotExitINReg),
					LabelEN: GetSecurityIssueLabelEN(FlagImageDetectNotExitINReg)})
		}
	}

	return securityIssue
}

func (iws *ImageWithCorrelateData2) GetRiskScore() int64 {
	riskScore := 100 - (CalculateVulnScore(iws.Vuln) +
		CalculateSensitiveScore(iws.SensitiveCnt) +
		util.MinInt64(CalculateWebshellScore(iws.WebshellCnt)+CalculateMalwareScore(iws.MalwareCnt),
			model.MaxWebshellAndVirusScore))

	// 又改啦，没有扫描过的100分
	// if len(iws.ScanSubTask) == 0 && riskScore == 100 {
	// 	riskScore = 0
	// }
	return riskScore
}

func (iws *ImageWithCorrelateData2) GetMaxVulnLevel() int64 {
	var ans int64
	for i := range iws.Vuln {
		if iws.Vuln[i].SeverityInt > ans {
			ans = iws.Vuln[i].SeverityInt
		}
	}
	return ans
}

func (iws *ImageWithCorrelateData2) GetImageOs() ImageOS {
	return ImageOS{
		Family:     iws.Image.OS.Family,
		Name:       iws.Image.OS.Name,
		Maintained: !iws.Image.OS.Eosl,
	}
}

// 镜像是否安全 仓库镜像和节点镜像使用
func (iws *ImageWithCorrelateData2) ToSecurityIssueOverview1() SecurityOverview {
	ans := SecurityOverview{
		Vuln:       ImageSafeString,
		Malware:    ImageSafeString,
		Sensitive:  ImageSafeString,
		Webshell:   ImageSafeString,
		Env:        ImageSafeString,
		Pkg:        ImageSafeString,
		License:    ImageSafeString,
		PkgLicense: ImageSafeString,
	}

	for i := range iws.Pkg {
		if iws.Pkg[i].PolicyDetect.Exception {
			ans.Pkg = ImageUnsafeString
			break
		}
		if iws.Pkg[i].PolicyDetect.ExceptionPkgLicense {
			ans.PkgLicense = ImageUnsafeString
			break
		}
	}
	for i := range iws.License {
		if iws.License[i].PolicyDetect.Exception {
			ans.License = ImageUnsafeString
			break
		}
	}
	for i := range iws.Env {
		if iws.Env[i].PolicyDetect.Exception {
			ans.Env = ImageUnsafeString
			break
		}
	}
	for i := range iws.Sensitive {
		if iws.Sensitive[i].PolicyDetect.Exception {
			ans.Sensitive = ImageUnsafeString
			break
		}
	}
	for i := range iws.Malware {
		if iws.Malware[i].PolicyDetect.Exception {
			ans.Malware = ImageUnsafeString
			break
		}
	}
	for i := range iws.Vuln {
		if iws.Vuln[i].PolicyDetect.Exception {
			ans.Vuln = ImageUnsafeString
			break
		}
	}
	for i := range iws.Webshell {
		if iws.Webshell[i].PolicyDetect.Exception {
			ans.Webshell = ImageUnsafeString
			break
		}
	}
	return ans
}

// 只能是告警或阻断
func getAction(pre string, n string) string {
	if pre == DeployActionBlock {
		return pre
	}
	if n == DeployActionBlock {
		return DeployActionBlock
	}
	return DeployActionAlarm
}

// 部署上线使用
// 最新的要求，这里就展示策略的动作，和数据无关 (也就是策略设置的病毒阻断，即使没有病毒，也返回阻断)
// 又增加了需求,未在仓库中的镜像，不展示策略动作
func (iws *ImageWithCorrelateData2) ToSecurityIssueOverview2() SecurityOverview {
	ans := SecurityOverview{}
	if iws.DeployRecord == nil || util.ExistBit1(iws.DeployRecord.Flag, FlagImageDetectNotExitINReg) {
		return ans
	}
	// 未扫描就只有环境变量
	if util.ExistBit1(iws.DeployRecord.Flag, FlagImageNotScanned) {
		for i := range iws.RiskPolicy {
			po := iws.RiskPolicy[i]
			if po.Enable && po.Env.Enable {
				if ans.Env == DeployActionBlock {
					continue
				}
				ans.Env = po.Env.Action
			}
		}
		return ans
	}

	for i := range iws.RiskPolicy {
		po := iws.RiskPolicy[i]
		if !po.Enable {
			continue
		}

		if po.Env.Enable {
			ans.Env = getAction(ans.Env, po.Env.Action)
		}
		if po.Webshell.Enable {
			ans.Webshell = getAction(ans.Webshell, po.Webshell.Action)
		}
		if po.Vuln.Enable {
			ans.Vuln = getAction(ans.Vuln, po.Vuln.Action)
		}
		if po.Sensitive.Enable {
			ans.Sensitive = getAction(ans.Sensitive, po.Sensitive.Action)
		}
		if po.Malware.Enable {
			ans.Malware = getAction(ans.Malware, po.Malware.Action)
		}
		if po.Pkg.Enable {
			ans.Pkg = getAction(ans.Env, po.Pkg.Action)
		}
		if po.PkgLicense.Enable {
			ans.Pkg = getAction(ans.Pkg, po.PkgLicense.Action)
		}
		if po.License.Enable {
			ans.License = getAction(ans.License, po.License.Action)
		}
	}
	return ans
}

// 单个镜像统计，要区分镜像本身属性和检测问题
// 节点镜像和仓库镜像
func (iws *ImageWithCorrelateData2) ToSecurityIssueStatistic() SecurityStatistic {
	sv := SecurityStatistic{
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
		sv.Total.ExceptionBoot = 1
	}
	if len(iws.TrustedImage) == 0 || (len(iws.TrustedImage) > 0 && !iws.TrustedImage[0].Trusted) {
		sv.Total.Untrusted = 1
	}
	if iws.Image.ImageFromType != ImageFromRegistry {
		if len(iws.ImageInReg) == 0 || (len(iws.ImageInReg) > 0 && len(iws.ImageInReg[0].RegIds) == 0) {
			sv.Total.NotInRegistry = 1
		}
	}

	risk := SecurityIssueStatic{}
	for i := range iws.Pkg {
		if iws.Pkg[i].PolicyDetect.Exception {
			risk.Pkg++
		}
		if iws.Pkg[i].PolicyDetect.ExceptionPkgLicense {
			risk.PkgLicense++
		}
	}
	for i := range iws.License {
		if iws.License[i].PolicyDetect.Exception {
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
	for i := range iws.RootBoot {
		if iws.RootBoot[i].IsRoot && iws.RootBoot[i].PolicyDetect.Exception {
			risk.ExceptionBoot = 1
		}
	}
	for i := range iws.ImageInReg {
		if iws.Image.ImageFromType == ImageFromRegistry {
			continue
		}
		if len(iws.ImageInReg[i].RegIds) == 0 && iws.ImageInReg[i].PolicyDetect.Exception {
			risk.NotInRegistry = 1
		}
	}
	for i := range iws.TrustedImage {
		if !iws.TrustedImage[i].Trusted && iws.TrustedImage[i].PolicyDetect.Exception {
			risk.Untrusted = 1
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
		ID:            image.ID,
		UniqueID:      image.UniqueID,
		ImageID:       image.ID,
		ImageUniqueID: image.UniqueID,
		ImageFromType: image.ImageFromType,
		Digest:        image.Digest,
		SecurityIssue: iws.GetSecurityIssue(),
		ImageAttr:     iws.GetImageAttr(),
		UUID:          image.ImageUUID,
		FullRepoName:  image.Repo,
		Tag:           image.Tag,
		Size:          util.ParseByteSize(image.Size),
		Os:            iws.GetImageOs(),
		Flag:          image.Flag,
		BootUser:      image.User,
		RiskScore:     iws.GetRiskScore(),
		Suggests:      iws.GenSuggest(),
		RegistryID:    image.RegID,
		RegistryUrl:   image.Host,
		Project:       image.Project,
		RiskPolicy:    make([]SimplePolicy, 0),
		TotalPolicy:   make([]SimplePolicy, 0),
		LastSyncAt:    image.Heartbeat,
		Safe:          iws.GenSafe(),
		Action:        iws.GenAction(),
		Online:        util.ExistBit1(image.Flag, FlagImageOnline),
		VulnStatic:    iws.StaticVuln(),
		PullCount:     image.PullCount,
		InWhite:       iws.DeployInWhite,
		BuildAt:       image.BuildAt,
		White:         util.ExistBit1(image.Flag, FlagImageDeployWhite),
		CreatedAt:     image.CreatedAt,
	}

	if baseResponse.BootUser == "" {
		baseResponse.BootUser = BootRootUser
	}
	for i := range iws.RiskPolicy {
		po := iws.RiskPolicy[i].ToSimplePolicy()
		baseResponse.RiskPolicy = append(baseResponse.RiskPolicy, po)
	}
	for i := range iws.TotalPolicy {
		po := iws.TotalPolicy[i].ToSimplePolicy()
		baseResponse.TotalPolicy = append(baseResponse.TotalPolicy, po)
	}

	// 把仓库信息加上
	if iws.Registry != nil {
		baseResponse.RegistryName = iws.Registry.Name
		baseResponse.RegistryUrl = iws.Registry.Url
		baseResponse.RegistryID = iws.Registry.ID
	}

	if util.ExistBit1(baseResponse.Flag, FlagImageOnline) {
		baseResponse.Online = true
	}
	baseResponse.NodeUniqueID = iws.Image.NodeID
	if iws.NodeInfo != nil {
		baseResponse.NodeHostname = iws.NodeInfo.Hostname
		baseResponse.ClusterName = iws.NodeInfo.ClusterName
		baseResponse.ClusterKey = iws.NodeInfo.ClusterKey
	}
	if iws.ScanInstance != nil {
		baseResponse.ScanInstanceID = iws.ScanInstance.ID
		baseResponse.ScanInsVer = iws.ScanInstance.ScannerVersion
		baseResponse.ScanInstance = iws.ScanInstance.ScannerInstance
		baseResponse.ClusterKey = iws.ScanInstance.ClusterKey
		baseResponse.ClusterName = iws.ScanInstance.ClusterName
	}
	if len(iws.ScanSubTask) > 0 {
		baseResponse.LastScanAt = iws.ScanSubTask[0].FinishedAt
	}
	baseResponse.SecurityIssueView = baseResponse.GetSecurityIssueViewView(model.LangZh)
	baseResponse.ImageAttrView = baseResponse.GetImageAttrView(model.LangZh)

	// 把容器名加上
	for i := range iws.Container {
		baseResponse.ContainerName = append(baseResponse.ContainerName, iws.Container[i].TensorRawContainer.Name)
	}

	if strings.HasPrefix(baseResponse.FullRepoName, "/") {
		baseResponse.FullRepoName = strings.Replace(baseResponse.FullRepoName, "/", "", 1)
	}

	baseResponse.FullNull()

	return baseResponse
}

func (iws *ImageWithCorrelateData2) CheckSafeByPolicy() string {

	if len(iws.DetectResult) == 0 {
		return ImageSafeString
	}
	for _, res := range iws.DetectResult {
		for i := range res {
			if util.ExistBit1(res[i].Flag, FlagDetectException) {
				return ImageUnsafeString
			}
		}
	}

	return ImageSafeString
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
	for i := range iws.Env {
		iws.Env[i].PolicyDetect.AddPolicyDetect(iws.Env[i].UniqueID, iws.DetectResult[DetectTypeEnvRule])
	}
	for i := range iws.Pkg {
		iws.Pkg[i].PolicyDetect.AddPolicyDetect(iws.Pkg[i].UniqueID, iws.DetectResult[DetectTypePkgRule])
	}
	for i := range iws.Vuln {
		iws.Vuln[i].PolicyDetect.AddPolicyDetect(iws.Vuln[i].UniqueID, iws.DetectResult[DetectTypeVulnRule])
	}
	for i := range iws.Sensitive {
		iws.Sensitive[i].PolicyDetect.AddPolicyDetect(iws.Sensitive[i].UniqueID, iws.DetectResult[DetectTypeSensRule])
	}
	for i := range iws.Webshell {
		iws.Webshell[i].PolicyDetect.AddPolicyDetect(iws.Webshell[i].UniqueID, iws.DetectResult[DetectTypeWebshellRule])
	}
	for i := range iws.Malware {
		iws.Malware[i].PolicyDetect.AddPolicyDetect(iws.Malware[i].UniqueID, iws.DetectResult[DetectTypeMalwareRule])
	}
	for i := range iws.License {
		iws.License[i].PolicyDetect.AddPolicyDetect(iws.License[i].UniqueID, iws.DetectResult[DetectTypeLicenseRule])
	}
	for i := range iws.RootBoot {
		iws.RootBoot[i].PolicyDetect.AddPolicyDetect(iws.RootBoot[i].UniqueID, iws.DetectResult[DetectTypeRootRule])
	}
	for i := range iws.TrustedImage {
		iws.TrustedImage[i].PolicyDetect.AddPolicyDetect(iws.TrustedImage[i].UniqueID, iws.DetectResult[DetectTypeTrustedImageRule])
	}
}

// 部署上线检测
func (iws *ImageWithCorrelateData2) AddDeployDetect() {
	if iws.DeployRecord == nil {
		return
	}
	for i := range iws.Pkg {
		iws.Pkg[i].PolicyDetect.AddDeployDetect(iws.Pkg[i].UniqueID, iws.DeployRecord.EnvIssue)
	}

	for i := range iws.Pkg {
		iws.Pkg[i].PolicyDetect.AddDeployDetect(iws.Pkg[i].UniqueID, iws.DeployRecord.PkgIssue)
	}

	for i := range iws.Vuln {
		iws.Vuln[i].PolicyDetect.AddDeployDetect(iws.Vuln[i].UniqueID, iws.DeployRecord.VulnIssue)
	}
	for i := range iws.Sensitive {
		iws.Sensitive[i].PolicyDetect.AddDeployDetect(iws.Sensitive[i].UniqueID, iws.DeployRecord.SensitiveIssue)
	}
	for i := range iws.Webshell {
		iws.Webshell[i].PolicyDetect.AddDeployDetect(iws.Webshell[i].UniqueID, iws.DeployRecord.WebshellIssue)
	}
	for i := range iws.Malware {
		iws.Malware[i].PolicyDetect.AddDeployDetect(iws.Malware[i].UniqueID, iws.DeployRecord.MalwareIssue)
	}
	for i := range iws.License {
		iws.License[i].PolicyDetect.AddDeployDetect(iws.License[i].UniqueID, iws.DeployRecord.LicenseIssue)
	}

	for i := range iws.Env {
		iws.Env[i].PolicyDetect.AddDeployDetect(iws.Env[i].UniqueID, iws.DeployRecord.EnvIssue)
	}
	for i := range iws.RootBoot {
		iws.RootBoot[i].PolicyDetect.AddDeployDetect(iws.RootBoot[i].UniqueID, iws.DeployRecord.RootBootIssue)
	}
	for i := range iws.TrustedImage {
		iws.TrustedImage[i].PolicyDetect.AddDeployDetect(iws.TrustedImage[i].UniqueID, iws.DeployRecord.TrustedImageIssue)
	}
}

type ImageOS struct {
	Family     string `json:"family"`
	Name       string `json:"name"`
	Maintained bool   `json:"maintained"`
}

type ImageBaseResponse struct {
	ID                int64                   `json:"id"`
	ImageFromType     string                  `json:"imageFromType"`
	UniqueID          uint64                  `json:"uniqueID,string"`
	ImageUniqueID     uint64                  `json:"imageUniqueID,string"`
	ImageID           int64                   `json:"imageID"`
	Digest            string                  `json:"digest"`
	Online            bool                    `json:"online"`            // 在线 "true",离线："false"
	SecurityIssue     []SecurityIssueLabel    `json:"securityIssue"`     // 安全问题
	SecurityIssueView []string                `json:"securityIssueView"` // 安全问题
	ImageAttr         ImageAttrResponse       `json:"imageAttr"`         // 镜像属性
	ImageAttrView     []string                `json:"imageAttrView"`     // 镜像属性
	UUID              uint32                  `json:"uuid"`              // 镜像uuid
	FullRepoName      string                  `json:"fullRepoName"`
	Tag               string                  `json:"tag"`
	Size              string                  `json:"size"`
	Os                ImageOS                 `json:"os"`
	Flag              uint64                  `json:"flag,string"`
	LastSyncAt        int64                   `json:"lastSyncAt"` // 上次同步时间(单位：毫秒)
	BootUser          string                  `json:"bootUser"`   // 启动用户
	RiskScore         int64                   `json:"riskScore"`
	Suggests          []ImageSuggest          `json:"suggests"`
	ScanStatus        string                  `json:"scanStatus"`
	LastScanAt        int64                   `json:"lastScanAt"` // 扫描完成时间戳(单位毫秒)
	RegistryID        int64                   `json:"registryId"`
	RegistryName      string                  `json:"registryName"`
	RegistryUrl       string                  `json:"registryUrl"`
	Project           string                  `json:"project"`
	NodeHostname      string                  `json:"nodeHostname"`
	ClusterName       string                  `json:"nodeClusterName"` // json tag 不一致，是因为前端要使用数据
	ClusterKey        string                  `json:"nodeClusterKey"`
	NodeUniqueID      uint64                  `json:"nodeUniqueID,string"`
	ScanInstanceID    int64                   `json:"scanInstanceID"`
	ScanInstance      string                  `json:"scanInstance"`
	ScanInsVer        string                  `json:"scanInsVer"`
	VulnStatic        ImageVulnSeverityStatic `json:"vulnStatic"`
	RiskPolicy        []SimplePolicy          `json:"riskPolicy"`    // 镜像的风险来源
	TotalPolicy       []SimplePolicy          `json:"totalPolicy"`   // 已使用的安全策略
	Safe              string                  `json:"safe"`          // 镜像安全状态
	Action            string                  `json:"action"`        // 部署上线的状态
	PullCount         int64                   `json:"pullCount"`     // 镜像下载次数
	BuildAt           int64                   `json:"buildAt"`       // 镜像的创建时间
	ContainerName     []string                `json:"containerName"` // 容器列表
	White             bool                    `json:"white"`         // 部署上线是否是白名单通过
	InWhite           bool                    `json:"inWhite"`       // 部署上线是否已在白名单中
	CreatedAt         int64                   `json:"createdAt"`
}

func (vi *ImageBaseResponse) RegNameView() string {
	r := vi.RegistryUrl
	if vi.RegistryName != "" {
		r = fmt.Sprintf("(%s)%s", vi.RegistryName, r)
	}
	return r
}

func (vi *ImageBaseResponse) FullNull() {
	if len(vi.SecurityIssue) == 0 {
		vi.SecurityIssue = make([]SecurityIssueLabel, 0)
	}

	if len(vi.Suggests) == 0 {
		vi.Suggests = make([]ImageSuggest, 0)
	}
}

func (vi *ImageBaseResponse) AdaptI18(ctx context.Context) {
	lang := model.LangZh

	if la, ok := ctx.Value(AcceptLanguage).(string); ok && la == model.LangEn {
		lang = model.LangEn
	}

	if lang == model.LangEn {
		for i := range vi.Suggests {
			vi.Suggests[i].Title = SuggestEnTile()[vi.Suggests[i].Title]
		}
	}
	if lang == model.LangZh {
		for i := range vi.TotalPolicy {
			if vi.TotalPolicy[i].Name == DefaultPolicyNameEN {
				vi.TotalPolicy[i].Name = DefaultPolicyNameZH
			}
		}
		for i := range vi.RiskPolicy {
			if vi.RiskPolicy[i].Name == DefaultPolicyNameEN {
				vi.RiskPolicy[i].Name = DefaultPolicyNameZH
			}
		}
	}

	vi.SecurityIssueView = vi.GetSecurityIssueViewView(lang)
	vi.ImageAttrView = vi.GetImageAttrView(lang)

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

func (vi *ImageBaseResponse) GetImageAttrView(lang string) []string {
	if lang == "" {
		lang = model.LangZh
	}
	ans := make([]string, 0)

	if vi.ImageAttr.ImageType == BaseImageTypeString {
		if lang == model.LangZh {
			ans = append(ans, "基础镜像")
		} else {
			ans = append(ans, "Base Image")
		}
	}

	if vi.ImageAttr.ImageType == AppImageTypeString {
		if lang == model.LangZh {
			ans = append(ans, "应用镜像")
		} else {
			ans = append(ans, "App Image")
		}
	}

	// if vi.ImageAttr.Trusted {
	// 	if lang == model.LangZh {
	// 		ans = append(ans, "可信镜像")
	// 	} else {
	// 		ans = append(ans, "Trusted Image")
	// 	}
	// }
	//
	// if !vi.ImageAttr.Trusted {
	// 	if lang == model.LangZh {
	// 		ans = append(ans, "非可信镜像")
	// 	} else {
	// 		ans = append(ans, "Untrusted Image")
	// 	}
	// }
	//
	// if vi.ImageAttr.ImageHasSuggestion {
	// 	if lang == model.LangZh {
	// 		ans = append(ans, "存在修复建议")
	// 	} else {
	// 		ans = append(ans, "Has Suggestion")
	// 	}
	// }
	//
	// if vi.ImageAttr.HasFixedVuln {
	// 	if lang == model.LangZh {
	// 		ans = append(ans, "存在可修复漏洞")
	// 	} else {
	// 		ans = append(ans, "Has Fixed Vulnerability")
	// 	}
	// }

	return ans
}

func (vi *ImageBaseResponse) GetSecurityIssueViewView(lang string) []string {
	ans := make([]string, 0)

	for i := range vi.SecurityIssue {
		si := vi.SecurityIssue[i]
		if lang == model.LangEn {
			ans = append(ans, si.LabelEN)
		} else {
			ans = append(ans, si.LabelZH)
		}
	}

	return ans
}

type ImageVulnSeverityStatic struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Unknown  int64 `json:"unknown"`
}

func (vi *ImageBaseResponse) GetImageName() string {

	imageName := vi.FullRepoName + ":" + vi.Tag

	if vi.RegistryUrl != "" {
		imageName = fmt.Sprintf("%s/%s", vi.RegistryUrl, imageName)
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
		if soft[i].Name != "" && soft[i].Version != "" && util.ExistBit1(soft[i].Flag, FlagHasExceptionPKG) {
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
		if soft[i].License != "" && util.ExistBit1(soft[i].Flag, FlagHasExceptionPkgLicense) {
			lit = append(lit, soft[i].License)
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

type ContainerResources struct {
	ImageUUID    uint32 `json:"imageUUID"`
	Name         string `json:"name"`
	ResourceName string `json:"resourceName"`
	Namespace    string `json:"namespace"`
	ClusterKey   string `json:"clusterKey"`
	ClusterName  string `json:"clusterName"`
}
