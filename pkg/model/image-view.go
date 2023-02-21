package model

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/security-rd/go-pkg/logging"
	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 镜像属性
type ImageAttrParam struct {
	Trusted      string `json:"trusted"`      // 是否是可信镜像：是："true"，否："false"
	ImageType    string `json:"imageType"`    // 镜像类型,基础镜像："base",应用镜像："app"
	HasFixedVuln string `json:"hasFixedVuln"` // 是否包含可修复漏洞: 是:"true",否："false"
	Reinforced   string `json:"reinforced"`   // 镜像是否已固:是："true",否："false"
}

// 生成属性的flag
func (sp *ImageListParam) GenAttrFlag() uint64 {
	var flag uint64
	if sp.ImageAttr.ImageType == BaseImageTypeString {
		flag = util.SetBit1(flag, FlagBaseImage)
	}
	if sp.ImageAttr.HasFixedVuln == TrueString {
		flag = util.SetBit1(flag, FlagHasFixedVuln)
	}
	if sp.ImageAttr.Reinforced == TrueString {
		flag = util.SetBit1(flag, FlagReinforced)
	}
	if sp.ImageAttr.Trusted == TrueString {
		flag = util.SetBit1(flag, FlagImageTrusted)
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

type GetImageAssociateDataParam struct {
	ImageId               int64 // 这个参数是必须的
	VulnEnable            bool
	VirusEnable           bool
	EnvEnable             bool
	SoftwareEnable        bool
	LicenseEnable         bool
	SensitiveEnable       bool
	WebshellEnable        bool
	ContainerEnable       bool
	SubtaskEnable         bool
	RegistryEnable        bool
	BaseImageEnable       bool
	AppImageEnable        bool
	ScanResultSearchParam ScanResultSearchParam
	Filter                *Filter
}

type ScanResultSearchParam struct {
	ImageID         int64    `json:"imageID"`
	LayerDigest     string   `json:"layerDigest"`
	Keyword         string   `json:"keyword"`
	AbnormalSoft    string   `json:"abnormalSoft"`
	AbnormalLicense string   `json:"abnormalLicense"`
	AbnormalEnv     string   `json:"abnormalEnv"`
	VulnSeverity    []string `json:"vulnSeverity"`
	LicenseSearch   []string `json:"licenseSearch"` // 开源协议筛选
	UniqueVuln      []uint64 `json:"uniqueVuln"`    // 漏洞筛选
	OmitFields      []string // 数据库中不查询的字段
}

func (s *GetImageAssociateDataParam) Valid() error {
	if s.ImageId <= 0 {
		return fmt.Errorf("no image id")
	}
	return nil
}

func (s *GetImageAssociateDataParam) Deserialize() {
	s.ScanResultSearchParam.ImageID = s.ImageId
	s.ScanResultSearchParam.Keyword = strings.ToLower(s.ScanResultSearchParam.Keyword)
}

type ImageListParam struct {
	Online             string            `json:"online"`             // 在线 "true",离线："false"
	Keyword            string            `json:"keyword"`            // 关键字搜索
	SecurityIssue      []uint64          `json:"securityIssue"`      // 安全问题: 前端传字符串
	ImageAttr          ImageAttrParam    `json:"-"`                  // 镜像属性
	ImageAttrView      []string          `json:"imageAttr"`          // 镜像属性,前端以列表的方式传递
	ImageIds           []int64           `json:"imageIds"`           // 镜像ID列表
	ScanStatus         []string          `json:"scanStatus"`         // 扫描状态
	ScanStatusFlag     uint64            `json:"-"`                  // 扫描状态(对应数据库中的数据)
	JustReturnImage    bool              `json:"justReturnImage"`    // 只需要镜像信息，不需要镜像关联信息
	ReturnMalicious    bool              `json:"returnMalicious"`    // 是否返回恶义文件
	UUIDs              []uint32          `json:"uuids"`              // 镜像uuid
	Projects           []string          `json:"projects"`           // 仓库和repo的筛选
	NodeHostname       string            `json:"nodeHostname"`       // 节点名精确匹配
	AttrIntersection   string            `json:"attrIntersection"`   // 属性交集还是并集 and or
	IssueIntersection  string            `json:"issueIntersection"`  // 安全问题交集还是并集 and or
	NotIdentifyOnline  bool              `json:"notIdentifyOnline"`  // 是否识别是在线还是离线 默认需要识别
	NotIdentifyTrusted bool              `json:"notIdentifyTrusted"` // 是否识别是可信镜像 默认需要识别
	StartID            int64             `json:"startID"`            // 分页请求时，上一页最后一条数据的ID
	ImageScanTaskInfo  ImageScanTaskInfo `json:"imageScanTaskInfo"`

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

func (sp *ImageListParam) Deserialize() {
	if sp.AttrIntersection == "" {
		sp.AttrIntersection = AndString
	}
	if sp.IssueIntersection == "" {
		sp.IssueIntersection = AndString
	}

	if sp.NotIdentifyOnline {
		sp.Online = ""
	}
	if sp.NotIdentifyTrusted {
		sp.ImageAttr.Trusted = ""
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

	if sp.NotIdentifyOnline {
		sp.Online = ""
	}
	if sp.NotIdentifyTrusted {
		sp.ImageAttr.Trusted = ""
	}
	sp.Keyword = strings.TrimSpace(sp.Keyword)
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

type ImageWithCorrelateData struct {
	ImageList         ImageList
	ImageBaseResponse ImageBaseResponse
	Sensitive         []*ImageSensitiveFile
	SensitiveCnt      int64
	Webshell          []*scannermodel.Webshell
	WebshellCnt       int64
	Env               []*ImageEnv
	EnvCnt            int64
	Vuln              []*Vuln
	VulnCnt           int64
	Software          []*ImageSoftware
	SoftwareCnt       int64
	License           []string // 异常的license
	Virus             []*ImageVirus
	VirusCnt          int64
	BaseImages        []*ImageBaseResponse // 基础镜像列表
	BaseImageCnt      int64
	AppImages         []*ImageBaseResponse // 应用镜像列表
	AppImageCnt       int64
	Container         []*ImageContainerResources
	SubTask           []SubTask
	SubTaskCnt        int64
	Registry          *Registry
}

// 程序中分页
func (iws *ImageWithCorrelateData) AddFilter(filter *Filter) *ImageWithCorrelateData {
	if filter == nil {
		return iws
	}
	start := int(filter.Offset)
	end := int(filter.Offset + filter.Limit)

	if len(iws.Sensitive) <= start {
		iws.Sensitive = make([]*ImageSensitiveFile, 0)
	} else {
		iws.Sensitive = iws.Sensitive[start:util.MinInt(end, len(iws.Sensitive))]
	}

	if len(iws.Webshell) <= start {
		iws.Webshell = make([]*scannermodel.Webshell, 0)
	} else {
		iws.Webshell = iws.Webshell[start:util.MinInt(end, len(iws.Webshell))]
	}

	if len(iws.Env) <= start {
		iws.Env = make([]*ImageEnv, 0)
	} else {
		iws.Env = iws.Env[start:util.MinInt(end, len(iws.Env))]
	}

	if len(iws.Vuln) <= start {
		iws.Vuln = make([]*Vuln, 0)
	} else {
		iws.Vuln = iws.Vuln[start:util.MinInt(end, len(iws.Env))]
	}

	if len(iws.Software) <= start {
		iws.Software = make([]*ImageSoftware, 0)
	} else {
		iws.Software = iws.Software[start:util.MinInt(end, len(iws.Software))]
	}

	if len(iws.License) <= start {
		iws.License = make([]string, 0)
	} else {
		iws.License = iws.License[start:util.MinInt(end, len(iws.License))]
	}

	if len(iws.Virus) <= start {
		iws.Virus = make([]*ImageVirus, 0)
	} else {
		iws.Virus = iws.Virus[start:util.MinInt(end, len(iws.Virus))]
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

func (iws *ImageWithCorrelateData) GenVulnSuggest() []string {
	ans := make([]string, 0)
	if len(iws.Vuln) == 0 {
		return ans
	}

	split := strings.Split(iws.GetImageOs(), ":")
	if len(split) == 0 || split[0] == "" {
		return ans
	}

	for i := range iws.Vuln {
		vu := iws.Vuln[i]
		if vu.FixedBy != "" && (util.ExistBit1(vu.Flag, VulnFlagClassOSPkg) || vu.Class == report.ClassOSPkg) {
			ans = append(ans, vu.PkgName)
		}
	}
	// 去重
	ans = util.DeDuplicationStringSlice(ans)
	install := util.InstallType(split[0])

	pre := "建议在Dockerfile里面使用以下命令升级软件包:"

	if len(ans) > 0 && install != "" {
		cmd := fmt.Sprintf("%s %s %s", "RUN", install, strings.Join(ans, " "))
		return []string{pre, cmd}
	}
	return ans
}

func (iws *ImageWithCorrelateData) GenSensitiveFileSuggest() []string {

	pre := []string{"建议在镜像中移除以下敏感文件，然后重新打包镜像："}
	res := make([]string, 0)
	if len(iws.Sensitive) == 0 {
		return res
	}

	for i := range iws.Sensitive {
		file := iws.Sensitive[i]
		if file.Name == "" {
			continue
		}
		if !strings.HasPrefix(file.Name, "/") {
			file.Name = "/" + file.Name
		}

		res = append(res, file.Name)
	}
	res = util.DeDuplicationStringSlice(res)
	if len(res) > 0 {
		pre = append(pre, res...)
		return pre
	}
	return []string{}
}

func (iws *ImageWithCorrelateData) GetImageAttr() ImageAttrResponse {
	attr := ImageAttrResponse{}

	image := iws.ImageList

	if ExistFlag(image.Flag, FlagBaseImage) {
		attr.ImageType = BaseImageTypeString
	} else {
		attr.ImageType = AppImageTypeString
	}
	if ExistFlag(image.Flag, FlagReinforced) {
		attr.Reinforced = true
	}
	if ExistFlag(image.Flag, FlagHasFixedVuln) {
		attr.HasFixedVuln = true
	}
	if ExistFlag(image.Flag, FlagImageTrusted) {
		attr.Trusted = true
	}
	return attr
}

func (iws *ImageWithCorrelateData) GetSecurityIssue() []SecurityIssue {
	// 问题
	securityIssue := make([]SecurityIssue, 0)
	image := iws.ImageList
	if ExistFlag(image.Flag, FlagHasVuln) {
		securityIssue = append(securityIssue, SecurityIssue{
			Value: FlagHasVuln, Label: GetSecurityIssueLabel(FlagHasVuln)})
	}

	if ExistFlag(image.Flag, FlagHasSensitive) {
		securityIssue = append(securityIssue, SecurityIssue{
			Value: FlagHasSensitive, Label: GetSecurityIssueLabel(FlagHasSensitive)})
	}
	if ExistFlag(image.Flag, FlagHasMalicious) {
		securityIssue = append(securityIssue, SecurityIssue{
			Value: FlagHasMalicious, Label: GetSecurityIssueLabel(FlagHasMalicious)})
	}
	if ExistFlag(image.Flag, FlagHasWebshell) {
		securityIssue = append(securityIssue, SecurityIssue{
			Value: FlagHasWebshell, Label: GetSecurityIssueLabel(FlagHasWebshell)})
	}

	if ExistFlag(image.Flag, FlagHasExceptEnv) {
		securityIssue = append(securityIssue, SecurityIssue{
			Value: FlagHasExceptEnv,
			Label: GetSecurityIssueLabel(FlagHasExceptEnv),
			Info:  ParseConfigEnv(iws.Env),
		})
	}

	if ExistFlag(image.Flag, FlagHasExceptLicense) {
		securityIssue = append(securityIssue, SecurityIssue{
			Value: FlagHasExceptLicense,
			Label: GetSecurityIssueLabel(FlagHasExceptLicense),
			Info:  ParseLicense(iws.Software)})
	}

	if ExistFlag(image.Flag, FlagHasSoftware) {
		securityIssue = append(securityIssue, SecurityIssue{
			Value: FlagHasSoftware,
			Label: GetSecurityIssueLabel(FlagHasSoftware),
			Info:  ParseSoftWare(iws.Software)})
	}

	if ExistFlag(image.Flag, FlagPrivilegedBoot) {
		securityIssue = append(securityIssue,
			SecurityIssue{Value: FlagPrivilegedBoot, Label: GetSecurityIssueLabel(FlagPrivilegedBoot)})
	}

	return securityIssue
}

func (iws *ImageWithCorrelateData) GetRiskScore() int64 {
	riskScore := 100 - (CalculateVulnScore(iws.Vuln) +
		CalculateSensitiveScore(iws.Sensitive) +
		util.MinInt64(CalculateWebshellScore(iws.Webshell)+CalculateVirusScore(iws.Virus), MaxWebshellAndVirusScore))

	if ExistFlag(iws.ImageList.Flag, FlagImageNotScan) && riskScore == 100 {
		riskScore = 0
	}
	return riskScore
}

func (iws *ImageWithCorrelateData) GetImageOs() string {
	if iws.ImageBaseResponse.Os != "" {
		return iws.ImageBaseResponse.Os
	}
	image := iws.ImageList
	imageOs := ftypes.OS{}
	if image.OS != "" {
		if err := json.Unmarshal([]byte(image.OS), &imageOs); err == nil {
			return fmt.Sprintf("%s:%s", imageOs.Family, imageOs.Name)
		} else {
			logging.Get().Err(err).Str("os", image.OS).Msg("ImageListResponse.Deserialize")
		}
	}
	return ""
}

func (iws *ImageWithCorrelateData) ToSecurityIssueOverview() SecurityIssueOverview {
	issueStatic := SecurityIssueOverview{
		VULN:      iws.VulnCnt,
		VIRUS:     iws.VirusCnt,
		SENSITIVE: iws.SensitiveCnt,
		Webshell:  iws.WebshellCnt,
		Envs:      iws.EnvCnt,
		Software:  iws.SoftwareCnt,
		License:   int64(len(iws.License)),
	}
	if iws.ImageList.ConfigFile != nil && (iws.ImageList.ConfigFile.Config.User == consts.BootRootUser ||
		iws.ImageList.ConfigFile.Config.User == "") {
		issueStatic.PrivilegedBoot += 1
	}
	return issueStatic
}

func (iws *ImageWithCorrelateData) ToImageBaseResponse() ImageBaseResponse {
	image := iws.ImageList

	baseResponse := ImageBaseResponse{
		ID:                     image.ID,
		Digest:                 image.Digest,
		Online:                 image.Online,
		SecurityIssue:          iws.GetSecurityIssue(),
		ImageAttr:              iws.GetImageAttr(),
		UUID:                   image.ImageUUID,
		FullRepoName:           image.FullRepoName,
		Tag:                    image.Tags,
		Size:                   util.ByteToMB(image.Size),
		Os:                     iws.GetImageOs(),
		Flag:                   image.Flag,
		Maintained:             !util.ExistBit1(image.Flag, FlagImageNotMaintained),
		BootUser:               image.GetBootUser(),
		RiskScore:              iws.GetRiskScore(),
		VulnFixSuggestion:      iws.GenVulnSuggest(),
		SensitiveFixSuggestion: iws.GenSensitiveFileSuggest(),
		Project:                image.Project,
		RegistryID:             image.RegistryID,
		RegistryUrl:            image.Library,
	}

	// 把仓库信息加上
	if iws.Registry != nil {
		baseResponse.RegistryName = iws.Registry.Name
		baseResponse.RegistryUrl = iws.Registry.Url
		baseResponse.LastSyncAt = iws.Registry.LastSyncAt
		baseResponse.RegistryID = iws.Registry.ID
	}
	if baseResponse.LastSyncAt < time.Now().UnixMilli()/100 {
		baseResponse.LastSyncAt = baseResponse.LastSyncAt * 1000 // 2.11.1之前用的是秒，2.11.1之后统一用的毫秒，中移部分集群还没有升级2.11.2
	}
	// 扫描状态
	baseResponse.ScanStatus = GetSubTaskStatusFlagString(image.Flag)
	if len(iws.SubTask) > 0 {
		if iws.SubTask[0].FinishedAt != nil && !iws.SubTask[0].FinishedAt.IsZero() {
			baseResponse.LastScanAt = iws.SubTask[0].FinishedAt.UnixMilli()
		}
	} else {
		baseResponse.ScanStatus = ImageNotScan
	}

	if len(iws.Container) > 0 {
		baseResponse.Online = true
	}

	return baseResponse
}

type ImageBaseResponse struct {
	ID                     int64             `json:"id"`
	Digest                 string            `json:"digest"`
	Online                 bool              `json:"online"`        // 在线 "true",离线："false"
	SecurityIssue          []SecurityIssue   `json:"securityIssue"` // 安全问题
	ImageAttr              ImageAttrResponse `json:"imageAttr"`     // 镜像属性
	UUID                   uint32            `json:"uuid"`          // 镜像uuid
	FullRepoName           string            `json:"fullRepoName"`
	Tag                    string            `json:"tag"`
	Size                   string            `json:"size"`
	Os                     string            `json:"os"`
	Flag                   uint64            `json:"flag"`
	LastSyncAt             int64             `json:"lastSyncAt"` // 上次同步时间(单位：毫秒)
	Maintained             bool              `json:"maintained"` // os是否维护维护
	BootUser               string            `json:"bootUser"`   // 启动用户
	RiskScore              int64             `json:"riskScore"`
	VulnFixSuggestion      []string          `json:"vulnFixSuggestion"`
	SensitiveFixSuggestion []string          `json:"sensitiveFixSuggestion"`
	ScanStatus             string            `json:"scanStatus"`
	LastScanAt             int64             `json:"lastScanAt"` // 扫描完成时间戳(单位毫秒)
	RegistryID             int64             `json:"registryId"`
	RegistryName           string            `json:"registryName"`
	RegistryUrl            string            `json:"registryUrl"`
	Project                string            `json:"project"`
}

func (ir *ImageBaseResponse) GetImageName() string {
	imageName := ir.FullRepoName

	if ir.RegistryUrl != "" {
		imageName = fmt.Sprintf("%s/%s", ir.RegistryUrl, imageName)
	}
	if ir.Tag != "" {
		imageName = fmt.Sprintf("%s:%s", imageName, ir.Tag)
	}
	if ir.RegistryName != "" {
		imageName = fmt.Sprintf("(%s)%s", ir.RegistryName, imageName)
	}
	return imageName
}

func ParseConfigEnv(env []*ImageEnv) string {
	res := make([]string, 0)
	for i := range env {
		if !env[i].Normal {
			res = append(res, env[i].Key)
		}
	}
	return strings.Join(res, ",")
}

func ParseSoftWare(soft []*ImageSoftware) string {
	if len(soft) == 0 {
		return ""
	}
	lit := make([]string, 0)
	for i := range soft {
		if soft[i].Name != "" && soft[i].Version != "" && util.ExistBit1(soft[i].Flag, FlagHasSoftware) {
			lit = append(lit, fmt.Sprintf("%s(%s)", soft[i].Name, soft[i].Version))
		}
	}

	return strings.Join(lit, ",")
}

func ParseLicense(soft []*ImageSoftware) string {
	if len(soft) == 0 {
		return ""
	}
	lit := make([]string, 0)
	for i := range soft {
		if soft[i].License != "" && util.ExistBit1(soft[i].Flag, FlagHasExceptLicense) {
			lit = append(lit, soft[i].License)
		}
	}

	return strings.Join(lit, ",")
}

func CalculateWebshellScore(ses []*scannermodel.Webshell) int64 {
	if len(ses) > 0 {
		return MaxWebshellScore
	}
	return 0
}

func CalculateVirusScore(ses []*ImageVirus) int64 {
	if len(ses) > 0 {
		return MaxVirusScore
	}
	return 0
}

func CalculateSensitiveScore(ses []*ImageSensitiveFile) int64 {
	score := SingleSensitiveScore * len(ses)
	if score > MaxSensitiveScore {
		return MaxSensitiveScore
	}
	return int64(score)
}

func CalculateVulnScore(vulns []*Vuln) int64 {
	constMapScore := map[string]int64{
		SeverityCRITICALString: 25,
		SeverityHIGHString:     20,
		SeverityMEDIUMString:   15,
		SeverityLOWString:      10,
		SeverityUNKNOWNString:  5,
	}

	getScore := func(severity string, num int64) int64 {
		if num == 0 {
			return 0
		}
		return util.MaxInt64(constMapScore[severity]*num, constMapScore[severity])
	}
	ret := GenSeverityHistogram(vulns)
	var score int64

	score += getScore(SeverityCRITICALString, ret.NumCritical)
	score += getScore(SeverityHIGHString, ret.NumHigh)
	score += getScore(SeverityMEDIUMString, ret.NumMedium)
	score += getScore(SeverityLOWString, ret.NumLow)
	score += getScore(SeverityUNKNOWNString, ret.NumUnknown)

	if score > MaxVulnScore {
		return MaxVulnScore
	}

	return score
}

func GenSeverityHistogram(vulns []*Vuln) SeverityHistogramInfo {
	ret := SeverityHistogramInfo{}

	for _, vuln := range vulns {
		switch vuln.Severity {
		case consts.SeverityCRITICALString:
			ret.NumCritical++
		case consts.SeverityHIGHString:
			ret.NumHigh++
		case consts.SeverityMEDIUMString:
			ret.NumMedium++
		case consts.SeverityLOWString:
			ret.NumLow++
		case consts.SeverityUNKNOWNString:
			ret.NumUnknown++
		}
	}

	return ret
}

type ImageContainerResources struct {
	ImageUUID    uint32
	Name         string
	ResourceName string
	Namespace    string
	ClusterKey   string
	ClusterName  string
}
