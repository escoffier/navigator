package sourceCheck

import (
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/consts"
)

type GetTokenReq struct {
	Title          string `json:"title"`
	ExpirationTime int64  `json:"expirationTime"`
	Username       string `json:"username"`
	Password       string `json:"password"`
}

type GetTokenResp struct {
	Status int `json:"status"`
	Data   struct {
		ExpirationTime int64  `json:"expirationTime"`
		Token          string `json:"token"`
		TokenUuid      string `json:"tokenUuid"`
	} `json:"data"`
	Msg string `json:"msg"`
}

type User struct {
	Email    string `json:"email"`
	LastName string `json:"lastName"`
	Name     string `json:"name"`
	Password string `json:"password"` // 原始密码，不需要加密
}

type Project struct {
	AppUuid string `json:"appUuid,omitempty"`
	AppName string `json:"appName"`
	// ProjectUuid string `json:"projectUuid"` // 创建时不可以传这个值
	Type string `json:"type"` // 只支持 git:1
	// 以下参数非必传
	GitType string `json:"gitType"` // git类型 type是git的时候该字段必输 值为 github/gitlab/gitee
	// gitlab版本 当gitType为gitlab必填 枚举值有   V3、V4 说明：在GitLab 9.0及更高版本中，请选择 API V4版本
	GitlabApiVersion string `json:"gitlabApiVersion"` // 当gitType为gitlab必填 值有：V3， V4
	// GitLabHead  string `json:"gitLabHead"`
	Protocol    string `json:"protocol"`   // 当 Type 是git 是必传， 值是：https,ssh
	GitLabPort  string `json:"gitLabPort"` // 当 protocol 是 ssh时必传,默认22
	PullWay     int    `json:"pullWay"`    // 默认是 2,也就是用 token 拉取代码
	AccessToken string `json:"accessToken"`
	Url         string `json:"url"`
	Branch      string `json:"branch"` // 分支 必传
	GitLabHead  string `json:"gitLabHead"`
}

func (s *Project) Serializer() {
	s.Type = consts.GitTypeGit
	if s.GitlabApiVersion == "" {
		s.GitlabApiVersion = consts.GitlabApiVersionV4
	}
	if s.Protocol == "" {
		s.Protocol = "22"
	}
	s.PullWay = consts.SourceCheckPullWayToken
	s.Url = strings.TrimSpace(s.Url)
	s.Branch = strings.TrimSpace(s.Branch)
}

func (s *Project) Check() error {
	if s.Url == "" {
		return fmt.Errorf("not get url")
	}
	if s.AccessToken == "" { // 修正字段名
		return fmt.Errorf("not get accessToken")
	}
	// if s.Branch == "" { // 补充必传字段校验
	// 	return fmt.Errorf("not get branch")
	// }
	// 根据结构体注释补充其他校验
	if s.Type == consts.GitTypeGit && s.Protocol == "" {
		return fmt.Errorf("protocol is required for git type")
	}
	return nil
}

type CreateProjectResponse struct {
	Status int `json:"status"`
	Data   struct {
		AppUuid string `json:"appUuid"`
	} `json:"data"`
	Msg string `json:"msg"`
}

// HighRiskComponent 高危组件top10
type HighRiskComponent struct {
	ComponentName string `json:"componentName"`
	ComponentId   string `json:"componentId"`
	Grade         int    `json:"grade"`
	GradeName     string `json:"gradeName"`
	// AppVersionId      string `json:"appVersionId"`
	VulNum int `json:"vulNum"`
	// ControlStatus     string `json:"controlStatus"`
	// ControlStatusName string `json:"controlStatusName"`
	// CreateTime        string `json:"createTime"`
}

// MostUsedComponent 被引用最多的组件top10统计数据
type MostUsedComponent struct {
	Value       string `json:"value"`
	Count       int64  `json:"count"`
	Name        string `json:"name"`
	ComponentId string `json:"componentId"`
}

type LicenseStat struct {
	Label  string `json:"label"`
	Value  int    `json:"value"`
	Number int    `json:"number"`
}

type StatisticsRequest struct {
	ProjectTagIds []string `json:"projectTagIds,omitempty"`
	DepSources    []string `json:"depSources,omitempty"`
	StartTime     string   `json:"startTime,omitempty"`
	EndTime       string   `json:"endTime,omitempty"`
	Type          string   `json:"type,omitempty"`
	ProjectFlag   string   `json:"projectFlag"`
}

// ShareAppRequest 应用分享请求参数
type ShareAppRequest struct {
	AppUuid  string `json:"appUuid"`  // 应用UUID
	UserUuid string `json:"userUuid"` // 用户UUID
	Auth     string `json:"auth"`
}

type BaseResponse struct {
	Msg    string `json:"msg"`
	Status int64  `json:"status"`
}

// VulnerabilityListRequest 获取漏洞列表请求参数
type VulnerabilityListRequest struct {
	PageIndex int `json:"pageIndex"` // 当前页面下标
	PageSize  int `json:"pageSize"`  // 每页展示行数
	// ProjectUuid   string `json:"projectUuid"`   // 项目唯一标识，soucecheck 查结果是使用的是 appuuid
	AppUuid string `json:"appUuid"` // 应用唯一标识
	// ComponentUuid string `json:"componentUuid"` // 组件唯一标识
	// Number        string `json:"number"`        // customSzNo/customCveNo/customCnnvdNo过滤条件
}

// VulnerabilityItem 漏洞项
type VulnerabilityItem struct {
	CustomSzNo           string `json:"customSzNo"`           // sz编号
	CustomCveNo          string `json:"customCveNo"`          // Cve编号
	CustomCnnvdNo        string `json:"customCnnvdNo"`        // Cnnvd编号
	AffectComponentCount int    `json:"affectComponentCount"` // 影响组件数
	CustomCnvdNo         string `json:"customCnvdNo"`         // Cnvd编号
	Grade                string `json:"grade"`                // 风险等级字典 字典编码:CVERISK
	Cwe                  string `json:"cwe"`                  // 弱点类型编号
	VulnerabilityName    string `json:"vulnerabilityName"`    // 漏洞名称
	CweName              string `json:"cweName"`              // 弱点类型名称
	Description          string `json:"description"`          // 漏洞描述
	ReleaseDate          int64  `json:"releaseDate"`          // 发布时间
}

// VulnerabilityListResponse 获取漏洞列表响应
type VulnerabilityListResponse struct {
	Status int `json:"status"`
	Data   struct {
		Total     int                 `json:"total"`
		DataList  []VulnerabilityItem `json:"dataList"`
		PageIndex int                 `json:"pageIndex"`
		PageSize  int                 `json:"pageSize"`
	} `json:"data"`
	Msg string `json:"msg"`
}

// LicenseListRequest 获取许可列表请求参数
type LicenseListRequest struct {
	PageIndex int `json:"pageIndex"` // 当前页面下标
	PageSize  int `json:"pageSize"`  // 每页展示行数
	// ProjectUuid   string `json:"projectUuid"`   // 项目唯一标识
	AppUuid string `json:"appUuid"` // 应用唯一标识
	// ComponentUuid string `json:"componentUuid"` // 组件唯一标识
	// LicenseId     string `json:"licenseId"`     // 许可简称
}

// LicenseItem 许可项
type LicenseItem struct {
	ControlStatus int    `json:"controlStatus"` // 黑白名单状态字典值
	Grade         string `json:"grade"`         // 风险级别字典值
	LicenseId     string `json:"licenseId"`     // 许可简称
	LicenseName   string `json:"licenseName"`   // 许可全称
}

// LicenseListResponse 获取许可列表响应
type LicenseListResponse struct {
	Status int `json:"status"`
	Data   struct {
		Total     int           `json:"total"`
		DataList  []LicenseItem `json:"dataList"`
		PageIndex int           `json:"pageIndex"`
		PageSize  int           `json:"pageSize"`
	} `json:"data"`
	Msg string `json:"msg"`
}

// ComponentListRequest 获取组件列表请求参数
type ComponentListRequest struct {
	PageIndex int    `json:"pageIndex"` // 当前页面下标 不需要进行测试
	PageSize  int    `json:"pageSize"`  // 每页展示行数  不需要进行测试
	AppUuid   string `json:"appUuid"`   // 应用唯一标识
	// ProjectUuid      string `json:"projectUuid"`      // 项目唯一标识
	// ComponentUuid    string `json:"componentUuid"`    // 组件uuid
	// Language         string `json:"language"`         // 语言字典值
	// Grade            string `json:"grade"`            // 风险级别字典值
	// License          string `json:"license"`          // 许可
	// ControlStatus    int    `json:"controlStatus"`    // 黑白名单字典值
	// ComponentType    int    `json:"componentType"`    // 组件类型字典值
	// DependRank       string `json:"dependRank"`       // 依赖等级
	// IntroductionType string `json:"introductionType"` // 引用类型字典值
	// DepScopeList     string `json:"depScopeList"`     // 作用域字典值
	// ScanLevel        int    `json:"scanLevel"`        // 扫描层级
	// RemarkTypes      string `json:"remarkTypes"`      // 组件标记
}

// SourceInfo 来源信息
type SourceInfo struct {
	Depth   string `json:"depth"`   // 扫描层级
	DepRank string `json:"depRank"` // 依赖方式
	Path    string `json:"path"`    // 解析路径
	Origin  string `json:"origin"`  // 来源
}

// ComponentItem 组件项
type ComponentItem struct {
	ComponentId               int64        `json:"componentId"`               // 组件id
	GroupId                   string       `json:"groupId"`                   // 组织
	ArtifactId                string       `json:"artifactId"`                // 组件名称
	ComponentUuid             string       `json:"componentUuid"`             // 组件唯一标识
	ControlStatus             int          `json:"controlStatus"`             // 黑白名单状态字典值
	ControlStatusName         string       `json:"controlStatusName"`         // 黑白名单字典值中文名
	DepRank                   string       `json:"depRank"`                   // 依赖类型
	DepScope                  string       `json:"depScope"`                  // 作用域
	Reference                 string       `json:"reference"`                 // 引用类型字典值
	Grade                     string       `json:"grade"`                     // 风险级别字典值
	JarInfoAddFrom            string       `json:"jarInfoAddFrom"`            // 语言字典值
	Version                   string       `json:"version"`                   // 版本
	RecommendVersion          string       `json:"recommendVersion"`          // 推荐版本
	AppVersionId              int64        `json:"appVersionId"`              // 应用版本id
	FirstCheckTime            int64        `json:"firstCheckTime"`            // 第一次检测时间
	LastCheckTime             int64        `json:"lastCheckTime"`             // 最后检测时间
	SourceInfoList            []SourceInfo `json:"sourceInfoList"`            // 来源信息列表
	Origin                    string       `json:"origin"`                    // 来源
	LicenseIds                []string     `json:"licenseIds"`                // 许可名称列表
	GradeDesc                 string       `json:"gradeDesc"`                 // 风险描述
	HomePage                  string       `json:"homePage"`                  // 主页
	SourceCode                string       `json:"sourceCode"`                // 源码
	ReleaseTime               int64        `json:"releaseTime"`               // 发布时间
	LatestVersion             string       `json:"latestVersion"`             // 最新版本
	PrivatePublicStatus       int          `json:"privatePublicStatus"`       // 组件状态编码
	PrivatePublicStatusName   string       `json:"privatePublicStatusName"`   // 组件状态中文
	Classifier                string       `json:"classifier"`                // classifier字符
	ProjectWhiteControlStatus int          `json:"projectWhiteControlStatus"` // 黑名单是否豁免
	Country                   string       `json:"country"`                   // 所属国家
	CountryChineseName        string       `json:"countryChineseName"`        // 所属国家的中文名称
	VirusFlag                 int          `json:"virusFlag"`                 // 投毒组件标识
}

// ComponentListResponse 获取组件列表响应
type ComponentListResponse struct {
	Status int `json:"status"`
	Data   struct {
		Total     int             `json:"total"`
		DataList  []ComponentItem `json:"dataList"`
		PageIndex int             `json:"pageIndex"`
		PageSize  int             `json:"pageSize"`
	} `json:"data"`
	Msg string `json:"msg"`
}

// StartScanRequest 发起扫描请求参数
type StartScanRequest struct {
	AppUuid     string `json:"appUuid"`     // 应用唯一标识,对应的就是 sourceCheckUUID
	CallBackUrl string `json:"callBackUrl"` // 回调接口地址(post接口，json参数体)
}

// StartScanResponse 发起扫描响应
type StartScanResponse struct {
	Status int `json:"status"`
	Data   struct {
		CheckNo string `json:"checkNo"` // 检测编号
	} `json:"data"`
	Msg string `json:"msg"`
}

// GetScanProgressResponse 获取扫描进度响应
type GetScanProgressResponse struct {
	Status int                   `json:"status"`
	Data   *ScanProgressResponse `json:"data"`
	Msg    string                `json:"msg"`
}

type ScanProgressResponse struct {
	Progress       string `json:"progress"`       // 进度
	State          int    `json:"state"`          // 应用检测状态字典值
	CheckStartTime string `json:"checkStartTime"` // 检测开始时间
	CheckEndTime   string `json:"checkEndTime"`   // 检测结束时间
	CheckTime      int64  `json:"checkTime"`      // 检测实际时长（单位：秒）
}

func (vi *ScanProgressResponse) ScanStatus() string {
	switch vi.State {
	case consts.SourceCheckScanStateNotChecked:
		return consts.ScanStatusNotScan
	case consts.SourceCheckScanStateChecked:
		return consts.ScanStatusSuccess
	case consts.SourceCheckScanStateCheckFailed, consts.SourceCheckScanStateDownloadFailed,
		consts.SourceCheckScanStatePaused, consts.SourceCheckScanStateStopped:
		return consts.ScanStatusFailed
	default:
		return consts.ScanStatusScanning
	}
}

type ScanState struct {
	Code  int    `json:"dicCode"`
	Name  string `json:"dicName"`
	Order int    `json:"order"`
}
