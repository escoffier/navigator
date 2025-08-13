package api

import (
	"gitlab.com/piccolo_su/vegeta/cmd/portal/model"
)

type SourceCheckVuln struct {
	ID                   int64  `json:"id"`
	ProjectUuid          string `json:"projectUuid"`          // 项目UUID
	UniqueId             uint64 `json:"uniqueID,string"`      // 唯一标识ID
	SourceCheckUuid      string `json:"sourceCheckUuid"`      // SourceCheck应用UUID
	CustomCveNo          string `json:"customCveNo"`          // Cve编号(漏洞信息)
	Severity             string `json:"severity"`             // 风险等级
	CweName              string `json:"cweName"`              // 弱点类型名称
	AffectComponentCount int    `json:"affectComponentCount"` // 影响组件数
	Description          string `json:"description"`          // 漏洞描述
}

// FromModel 从model.SourceCheckVuln转换为api.SourceCheckVuln
func (v *SourceCheckVuln) FromModel(m *model.SourceCheckVuln) *SourceCheckVuln {
	if v == nil {
		v = &SourceCheckVuln{}
	}
	v.ID = m.ID
	v.ProjectUuid = m.ProjectUuid
	v.UniqueId = m.UniqueId
	v.SourceCheckUuid = m.SourceCheckUuid
	v.CustomCveNo = m.CustomCveNo
	v.AffectComponentCount = m.AffectComponentCount
	v.Description = m.Description
	v.Severity = m.Severity
	v.CweName = m.CweName
	return v
}

// SourceCheckLicense SourceCheck许可数据模型
type SourceCheckLicense struct {
	ID              int64  `json:"id"`
	ProjectUuid     string `json:"projectUuid"`     // 项目UUID
	UniqueId        uint64 `json:"uniqueID,string"` // 唯一标识ID
	SourceCheckUuid string `json:"sourceCheckUuid"` // SourceCheck应用UUID
	LicenseId       string `json:"licenseId"`       // 许可简称
	LicenseName     string `json:"licenseName"`     // 许可全称
	Severity        string `json:"severity"`        // 风险等级
}

// FromModel 从model.SourceCheckLicense转换为api.SourceCheckLicense
func (l *SourceCheckLicense) FromModel(m *model.SourceCheckLicense) *SourceCheckLicense {
	if l == nil {
		l = &SourceCheckLicense{}
	}
	l.ID = m.ID
	l.ProjectUuid = m.ProjectUuid
	l.UniqueId = m.UniqueId
	l.SourceCheckUuid = m.SourceCheckUuid
	l.LicenseId = m.LicenseId
	l.LicenseName = m.LicenseName
	l.Severity = m.Severity
	return l
}

type SourceCheckComponent struct {
	ID              int64  `json:"id"`
	ProjectUuid     string `json:"projectUuid"`     // 项目UUID
	UniqueId        uint64 `json:"uniqueID,string"` // 唯一标识ID
	SourceCheckUuid string `json:"sourceCheckUuid"` // SourceCheck应用UUID

	ArtifactId         string   `json:"artifactId"`         // 组件名称
	Severity           string   `json:"severity"`           // 风险等级
	JarInfoAddFrom     string   `json:"jarInfoAddFrom"`     // 语言字典值
	LicenseIds         []string `json:"licenseIds"`         // 许可名称列表(JSON)
	Version            string   `json:"version"`            // 当前版本
	RecommendVersion   string   `json:"recommendVersion"`   // 推荐版本
	LatestVersion      string   `json:"latestVersion"`      // 最新版本
	CountryChineseName string   `json:"countryChineseName"` // 所属国家的中文名称
}

// FromModel 从model.SourceCheckComponent转换为api.SourceCheckComponent
func (c *SourceCheckComponent) FromModel(m *model.SourceCheckComponent) *SourceCheckComponent {
	if c == nil {
		c = &SourceCheckComponent{}
	}
	c.ID = m.ID
	c.ProjectUuid = m.ProjectUuid
	c.UniqueId = m.UniqueId
	c.SourceCheckUuid = m.SourceCheckUuid
	c.ArtifactId = m.ArtifactId
	c.JarInfoAddFrom = m.JarInfoAddFrom
	c.Version = m.Version
	c.RecommendVersion = m.RecommendVersion
	c.LicenseIds = m.LicenseIds
	c.LatestVersion = m.LatestVersion
	c.CountryChineseName = m.CountryChineseName
	c.Severity = m.Severity
	return c
}

// CodeSecVuln 代码安全漏洞数据模型
// 根据需求只包含指定字段：树节点类型描述,漏洞类型名称,漏洞类型,语言,漏洞名称,漏洞库信息，语言类型,文件名,文件行数,严重等级,缺陷状态,缺陷跟踪类型
type CodeSecVuln struct {
	ID           int64  `json:"id"` //
	UniqueID     uint64 `json:"uniqueID,string"`
	ProjectUuid  string `json:"projectUuid"`
	CodesecAppId string `json:"codesecAppId"` //
	VulName      string `json:"vulName"`      // 漏洞名称
	Severity     string `json:"severity"`     // 风险等级
	Filename     string `json:"filename"`     // 文件名
	RowNum       string `json:"rowNum"`       // 文件行数
	VulFlag      string `json:"vulFlag"`      // 缺陷跟踪类型
}

// FromModel 从model.CodeSecVuln转换为api.CodeSecVuln
func (vi *CodeSecVuln) FromModel(m *model.CodeSecVuln) *CodeSecVuln {
	if vi == nil {
		vi = &CodeSecVuln{}
	}
	vi.ID = m.ID
	vi.UniqueID = m.UniqueID
	vi.ProjectUuid = m.ProjectUuid
	vi.CodesecAppId = m.CodesecAppId
	vi.VulName = m.VulName
	vi.Filename = m.Filename
	vi.RowNum = m.RowNum
	vi.VulFlag = m.VulFlag
	vi.Severity = m.Severity
	return vi
}

type SourceCheckSummary struct {
	ID              int64  `json:"id"`
	UniqueID        uint64 `json:"uniqueID,string"`
	ProjectUuid     string `json:"projectUuid"`     // 项目UUID
	SourceCheckUuid string `json:"sourceCheckUuid"` // SourceCheck应用UUID
	CheckNo         string `json:"checkNo"`         // 检测编号
	ComponentCount  int64  `json:"componentCount"`  // 组件数量
	VulnCount       int64  `json:"vulnCount"`       // 漏洞数量
	LicenseCount    int64  `json:"licenseCount"`    // 许可数量
	ScanStatus      string `json:"scanStatus"`      // 扫描状态
	ScanMsg         string `json:"scanMsg"`         // 扫描消息
}

// FromModel 从model.SourceCheckSummary转换为api.SourceCheckSummary
func (s *SourceCheckSummary) FromModel(m *model.SourceCheckSummary) *SourceCheckSummary {
	if m == nil {
		s = &SourceCheckSummary{}
		return s
	}
	if s == nil {
		s = &SourceCheckSummary{}
	}
	s.ID = m.ID
	s.UniqueID = m.UniqueID
	s.ProjectUuid = m.ProjectUuid
	s.SourceCheckUuid = m.SourceCheckUuid
	s.CheckNo = m.CheckNo
	s.ScanStatus = m.ScanStatus
	s.ScanMsg = m.ScanMsg
	s.ComponentCount = m.ComponentCount
	s.VulnCount = m.VulnCount
	s.LicenseCount = m.LicenseCount
	return s
}

type CodesecSummary struct {
	ID              int64  `json:"id"`
	ProjectUuid     string `json:"projectUuid"`     // 项目UUID
	ScanStatus      string `json:"scanStatus"`      // 扫描状态
	ScanMsg         string `json:"scanMsg"`         // 扫描消息
	CodeLineNum     int    `json:"codeLineNum"`     // 可执行代码行数
	CommentLines    int    `json:"commentLines"`    // 注释行数
	BlankLines      int    `json:"blankLines"`      // 空白行数
	RepetitiveLines int    `json:"repetitiveLines"` // 重复代码行数
	FileNum         int    `json:"fileNum"`         // 文件数
	FileSize        int    `json:"fileSize"`        // 文件总大小
	LanguageName    string `json:"languageName"`    // 语言名称
}

// FromModel 从model.CodesecSummary转换为api.CodesecSummary
func (s *CodesecSummary) FromModel(m *model.CodesecSummary) *CodesecSummary {
	if s == nil {
		s = &CodesecSummary{}
	}
	s.ID = m.ID
	s.ProjectUuid = m.ProjectUuid
	s.ScanStatus = m.ScanStatus
	s.ScanMsg = m.ScanMsg
	s.CodeLineNum = m.CodeLineNum
	s.CommentLines = m.CommentLines
	s.BlankLines = m.BlankLines
	s.RepetitiveLines = m.RepetitiveLines
	s.FileNum = m.FileNum
	s.FileSize = m.FileSize
	s.LanguageName = m.LanguageName
	return s
}

// Project API项目结构体
type Project struct {
	ID                      int64  `json:"id"`                      // 项目ID
	Uuid                    string `json:"uuid"`                    // 项目标识符
	Name                    string `json:"name"`                    // 项目名称
	Url                     string `json:"url"`                     // 仓库地址
	UserID                  int64  `json:"userId"`                  // 用户ID
	Description             string `json:"description"`             // 项目描述
	GitType                 string `json:"gitType"`                 // 仓库类型
	Token                   string `json:"token"`                   // Token
	Branch                  string `json:"branch"`                  // 分支名
	Tag                     string `json:"tag"`                     // tag名
	BranchTag               string `json:"branchTag"`               // 分支名和tag名
	CodesecScanStatus       string `json:"codesecScanStatus"`       // codesec扫描状态
	CodesecScanMsg          string `json:"codesecScanMsg"`          // codesec扫描消息
	SourceCheckScanStatus   string `json:"sourceCheckScanStatus"`   // sourcecheck扫描状态
	SourceCheckScanMsg      string `json:"sourceCheckScanMsg"`      // sourcecheck扫描消息
	RiskLevel               string `json:"riskLevel"`               // 项目风险级别：高、中、低、未知
	CodesecHighRisk         string `json:"codesecHighRisk"`         // codesec最高风险等级
	CodesecHighSeverity     int64  `json:"codesecHighSeverity"`     // codesec最高风险等级
	SourceCheckHighRisk     string `json:"sourceCheckHighRisk"`     // sourcecheck最高风险等级
	SourceCheckHighSeverity int64  `json:"sourceCheckHighSeverity"` // sourcecheck最高风险等级
	LastScanAt              int64  `json:"lastScanAt"`              // 最近扫描时间
	Updater                 string `json:"updater"`                 // 最近一次更新人
	CreatedAt               int64  `json:"createdAt"`               // 创建时间
	UpdatedAt               int64  `json:"updatedAt"`               // 更新时间
}

// FromModel 从model.Project转换为api.Project
func (p *Project) FromModel(m *model.Project) *Project {
	if p == nil {
		p = &Project{}
	}
	p.ID = m.ID
	p.Uuid = m.Uuid
	p.Name = m.Name
	p.Url = m.Url
	p.UserID = m.UserID
	p.Description = m.Description
	p.GitType = m.GitType
	p.Token = m.Token
	p.Branch = m.Branch
	p.Tag = m.Tag
	p.BranchTag = m.BranchTag
	p.CodesecScanStatus = m.CodesecScanStatus
	p.CodesecScanMsg = m.CodesecScanMsg
	p.SourceCheckScanStatus = m.SourceCheckScanStatus
	p.SourceCheckScanMsg = m.SourceCheckScanMsg
	p.CodesecHighRisk = m.CodesecHighRisk
	p.CodesecHighSeverity = m.CodesecHighSeverity
	p.SourceCheckHighRisk = m.SourceCheckHighRisk
	p.SourceCheckHighSeverity = m.SourceCheckHighSeverity
	p.LastScanAt = m.LastScanAt
	p.Updater = m.Updater
	p.RiskLevel = m.RiskLevel
	p.CreatedAt = m.CreatedAt
	p.UpdatedAt = m.UpdatedAt
	return p
}
