package model

import (
	"encoding/json"
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// SourceCheckVuln SourceCheck漏洞数据模型
type SourceCheckVuln struct {
	ID                   int64  `gorm:"column:id" json:"id"`
	ProjectUuid          string `gorm:"column:project_uuid" json:"projectUuid"`                    // 项目UUID
	UniqueId             uint64 `gorm:"column:unique_id" json:"uniqueID,string"`                   // 唯一标识ID
	SourceCheckUuid      string `gorm:"column:source_check_uuid" json:"sourceCheckUuid"`           // SourceCheck应用UUID
	CustomSzNo           string `gorm:"column:custom_sz_no" json:"customSzNo"`                     // sz编号
	CustomCveNo          string `gorm:"column:custom_cve_no" json:"customCveNo"`                   // Cve编号
	CustomCnnvdNo        string `gorm:"column:custom_cnnvd_no" json:"customCnnvdNo"`               // Cnnvd编号
	AffectComponentCount int    `gorm:"column:affect_component_count" json:"affectComponentCount"` // 影响组件数
	CustomCnvdNo         string `gorm:"column:custom_cnvd_no" json:"customCnvdNo"`                 // Cnvd编号
	Grade                string `gorm:"column:grade" json:"grade"`                                 // 风险等级字典 字典编码:超危，高危，低危，其他，无风险
	Cwe                  string `gorm:"column:cwe" json:"cwe"`                                     // 弱点类型编号
	VulnerabilityName    string `gorm:"column:vulnerability_name" json:"vulnerabilityName"`        // 漏洞名称
	CweName              string `gorm:"column:cwe_name" json:"cweName"`                            // 弱点类型名称,可能会空
	Description          string `gorm:"column:description" json:"description"`                     // 漏洞描述
	ReleaseDate          int64  `gorm:"column:release_date" json:"releaseDate"`                    // 发布时间

	SeverityInt int64  `gorm:"column:severity_int" json:"severityInt"` // 风险等级
	Severity    string `gorm:"column:severity" json:"severity"`        // 风险等级(数字)

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
	DeletedAt int64 `gorm:"column:deleted_at;default:0" json:"deletedAt"`            // milliseconds
}

// TableName 指定表名
func (vi *SourceCheckVuln) TableName() string {
	return "source_check_vuln"
}

// Check 数据校验
func (vi *SourceCheckVuln) Check() error {

	if vi.SourceCheckUuid == "" || vi.ProjectUuid == "" {
		return fmt.Errorf("source_check_uuid or project_uuid is required")
	}
	if vi.CustomSzNo == "" && vi.CustomCveNo == "" && vi.CustomCnnvdNo == "" {
		return fmt.Errorf("at least one of customSzNo, customCveNo, customCnnvdNo is required")
	}
	return nil
}

// GenUniqueID 生成唯一标识ID
func (vi *SourceCheckVuln) GenUniqueID() uint64 {
	key := fmt.Sprintf("%s-%s-%s-%s", vi.ProjectUuid, vi.SourceCheckUuid, vi.CustomCveNo, vi.CustomCnnvdNo)
	uid := util.GenerateUUID64(key)
	vi.UniqueId = uid
	return uid
}

// Serialize 序列化处理
func (vi *SourceCheckVuln) Serialize() {
	if vi.SourceCheckUuid == "" {
		vi.SourceCheckUuid = vi.ProjectUuid
	}
	if vi.UniqueId == 0 {
		vi.UniqueId = vi.GenUniqueID()
	}
	// 根据Grade确定Severity和SeverityInt
	vi.Severity, vi.SeverityInt = SetSeverityFromGrade(vi.Grade)
}

// Deserialize 反序列化处理
func (vi *SourceCheckVuln) Deserialize() {
	// SourceCheckVuln 暂无需要反序列化的复杂字段
}

// Same 比较两个对象是否相同
func (vi *SourceCheckVuln) Same(other *SourceCheckVuln) bool {
	if other == nil {
		return false
	}
	return vi.UniqueId == other.UniqueId &&
		vi.CustomCveNo == other.CustomCveNo &&
		vi.CustomCnnvdNo == other.CustomCnnvdNo &&
		vi.VulnerabilityName == other.VulnerabilityName
}

// SourceCheckLicense SourceCheck许可数据模型
type SourceCheckLicense struct {
	ID              int64  `gorm:"column:id" json:"id"`
	ProjectUuid     string `gorm:"column:project_uuid" json:"projectUuid"`                  // 项目UUID
	UniqueId        uint64 `gorm:"column:unique_id" json:"uniqueID,string"`                 // 唯一标识ID
	SourceCheckUuid string `gorm:"column:source_check_uuid" json:"sourceCheckUuid"`         // SourceCheck应用UUID
	ControlStatus   int64  `gorm:"column:control_status" json:"controlStatus"`              // 黑白名单状态字典值
	Grade           string `gorm:"column:grade" json:"grade"`                               // 风险级别字典值
	LicenseId       string `gorm:"column:license_id" json:"licenseId"`                      // 许可简称
	LicenseName     string `gorm:"column:license_name" json:"licenseName"`                  // 许可全称
	SeverityInt     int64  `gorm:"column:severity_int" json:"severityInt"`                  // 风险等级
	Severity        string `gorm:"column:severity" json:"severity"`                         // 风险等级(数字)
	CreatedAt       int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt       int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
	DeletedAt       int64  `gorm:"column:deleted_at;default:0" json:"deletedAt"`            // milliseconds
}

// TableName 指定表名
func (vi *SourceCheckLicense) TableName() string {
	return "source_check_license"
}

// Check 数据校验
func (vi *SourceCheckLicense) Check() error {
	if vi.SourceCheckUuid == "" || vi.ProjectUuid == "" {
		return fmt.Errorf("source_check_uuid or project_uuid is required")
	}
	if vi.LicenseId == "" {
		return fmt.Errorf("license_id is required")
	}
	return nil
}

// GenUniqueID 生成唯一标识ID
func (vi *SourceCheckLicense) GenUniqueID() uint64 {
	key := fmt.Sprintf("%s-%s-%s", vi.ProjectUuid, vi.SourceCheckUuid, vi.LicenseId)
	uid := util.GenerateUUID64(key)
	vi.UniqueId = uid
	return uid
}

// Serialize 序列化处理
func (vi *SourceCheckLicense) Serialize() {
	if vi.SourceCheckUuid == "" {
		vi.SourceCheckUuid = vi.ProjectUuid
	}
	if vi.UniqueId == 0 {
		vi.UniqueId = vi.GenUniqueID()
	}

	// 根据Grade确定Severity和SeverityInt
	vi.Severity, vi.SeverityInt = SetSeverityFromGrade(vi.Grade)
}

// Deserialize 反序列化处理
func (vi *SourceCheckLicense) Deserialize() {
	// SourceCheckLicense 暂无需要反序列化的复杂字段
}

// Same 比较两个对象是否相同
func (vi *SourceCheckLicense) Same(other *SourceCheckLicense) bool {
	if other == nil {
		return false
	}
	return vi.UniqueId == other.UniqueId &&
		vi.LicenseId == other.LicenseId &&
		vi.LicenseName == other.LicenseName &&
		vi.Grade == other.Grade
}

// SourceCheckComponent SourceCheck组件数据模型
type SourceCheckComponent struct {
	ID                        int64    `gorm:"column:id" json:"id"`
	ProjectUuid               string   `gorm:"column:project_uuid" json:"projectUuid"`              // 项目UUID
	UniqueId                  uint64   `gorm:"column:unique_id" json:"uniqueID,string"`             // 唯一标识ID
	SourceCheckUuid           string   `gorm:"column:source_check_uuid" json:"sourceCheckUuid"`     // SourceCheck应用UUID
	ComponentId               int64    `gorm:"column:component_id" json:"componentId"`              // 组件id
	GroupId                   string   `gorm:"column:group_id" json:"groupId"`                      // 组织
	ArtifactId                string   `gorm:"column:artifact_id" json:"artifactId"`                // 组件名称
	ComponentUuid             string   `gorm:"column:component_uuid" json:"componentUuid"`          // 组件唯一标识
	ControlStatus             int      `gorm:"column:control_status" json:"controlStatus"`          // 黑白名单状态字典值
	ControlStatusName         string   `gorm:"column:control_status_name" json:"controlStatusName"` // 黑白名单字典值中文名
	DepRank                   string   `gorm:"column:dep_rank" json:"depRank"`                      // 依赖类型
	DepScope                  string   `gorm:"column:dep_scope" json:"depScope"`                    // 作用域
	Reference                 string   `gorm:"column:reference" json:"reference"`                   // 引用类型字典值
	Grade                     string   `gorm:"column:grade" json:"grade"`                           // 风险级别字典值
	JarInfoAddFrom            string   `gorm:"column:jar_info_add_from" json:"jarInfoAddFrom"`      // 语言字典值
	Version                   string   `gorm:"column:version" json:"version"`                       // 版本
	RecommendVersion          string   `gorm:"column:recommend_version" json:"recommendVersion"`    // 推荐版本
	AppVersionId              int64    `gorm:"column:app_version_id" json:"appVersionId"`           // 应用版本id
	FirstCheckTime            int64    `gorm:"column:first_check_time" json:"firstCheckTime"`       // 第一次检测时间
	LastCheckTime             int64    `gorm:"column:last_check_time" json:"lastCheckTime"`         // 最后检测时间
	SourceInfoList            string   `gorm:"column:source_info_list" json:"sourceInfoList"`       // 来源信息列表(JSON)
	Origin                    string   `gorm:"column:origin" json:"origin"`                         // 来源
	LicenseIdsJson            string   `gorm:"column:license_ids" json:"-"`                         // 许可名称列表(JSON)
	LicenseIds                []string `gorm:"-" json:"licenseIds"`
	GradeDesc                 string   `gorm:"column:grade_desc" json:"gradeDesc"`                                   // 风险描述
	HomePage                  string   `gorm:"column:home_page" json:"homePage"`                                     // 主页
	SourceCode                string   `gorm:"column:source_code" json:"sourceCode"`                                 // 源码
	ReleaseTime               int64    `gorm:"column:release_time" json:"releaseTime"`                               // 发布时间
	LatestVersion             string   `gorm:"column:latest_version" json:"latestVersion"`                           // 最新版本
	PrivatePublicStatus       int      `gorm:"column:private_public_status" json:"privatePublicStatus"`              // 组件状态编码
	PrivatePublicStatusName   string   `gorm:"column:private_public_status_name" json:"privatePublicStatusName"`     // 组件状态中文
	Classifier                string   `gorm:"column:classifier" json:"classifier"`                                  // classifier字符
	ProjectWhiteControlStatus int      `gorm:"column:project_white_control_status" json:"projectWhiteControlStatus"` // 黑名单是否豁免
	Country                   string   `gorm:"column:country" json:"country"`                                        // 所属国家
	CountryChineseName        string   `gorm:"column:country_chinese_name" json:"countryChineseName"`                // 所属国家的中文名称
	VirusFlag                 int      `gorm:"column:virus_flag" json:"virusFlag"`                                   // 投毒组件标识

	SeverityInt int64  `gorm:"column:severity_int" json:"severityInt"`                  // 风险等级
	Severity    string `gorm:"column:severity" json:"severity"`                         // 风险等级(数字)
	CreatedAt   int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt   int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
	DeletedAt   int64  `gorm:"column:deleted_at;default:0" json:"deletedAt"`            // milliseconds
}

// TableName 指定表名
func (c *SourceCheckComponent) TableName() string {
	return "source_check_component"
}

// Check 数据校验
func (c *SourceCheckComponent) Check() error {
	if c.SourceCheckUuid == "" || c.ProjectUuid == "" {
		return fmt.Errorf("source_check_uuid or project_uuid is required")
	}
	if c.ComponentUuid == "" {
		return fmt.Errorf("component_uuid is required")
	}
	return nil
}

// GenUniqueID 生成唯一标识ID
func (c *SourceCheckComponent) GenUniqueID() uint64 {
	key := fmt.Sprintf("%s-%s-%s-%s", c.ProjectUuid, c.SourceCheckUuid, c.ComponentUuid, c.Version)
	uid := util.GenerateUUID64(key)
	c.UniqueId = uid
	return uid
}

// Serialize 序列化处理
func (vi *SourceCheckComponent) Serialize() {
	if vi.SourceCheckUuid == "" {
		vi.SourceCheckUuid = vi.ProjectUuid
	}
	if vi.UniqueId == 0 {
		vi.UniqueId = vi.GenUniqueID()
	}

	// 根据Grade确定Severity和SeverityInt
	vi.Severity, vi.SeverityInt = SetSeverityFromGrade(vi.Grade)
	if byt, err := json.Marshal(vi.LicenseIds); err == nil {
		vi.LicenseIdsJson = string(byt)
	}
}

// Deserialize 反序列化处理
func (c *SourceCheckComponent) Deserialize() {
	// 处理JSON字段反序列化
	lic := make([]string, 0)
	if err := json.Unmarshal([]byte(c.LicenseIdsJson), &lic); err != nil {
		lic = make([]string, 0)
	}
	c.LicenseIds = lic
}

// Same 比较两个对象是否相同
func (c *SourceCheckComponent) Same(other *SourceCheckComponent) bool {
	if other == nil {
		return false
	}
	return c.UniqueId == other.UniqueId &&
		c.ComponentUuid == other.ComponentUuid &&
		c.GroupId == other.GroupId &&
		c.ArtifactId == other.ArtifactId &&
		c.Version == other.Version
}

// SourceCheckSummary SourceCheck扫描结果数据模型
type SourceCheckSummary struct {
	ID              int64  `gorm:"column:id" json:"id"`
	UniqueID        uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	ProjectUuid     string `gorm:"column:project_uuid" json:"projectUuid"`
	SourceCheckUuid string `gorm:"column:source_check_uuid" json:"sourceCheckUuid"`
	CheckNo         string `gorm:"column:check_no" json:"checkNo"`
	ScanStatus      string `gorm:"column:scan_status" json:"scanStatus"`
	ScanMsg         string `gorm:"column:scan_msg" json:"scanMsg"`

	// 统计信息
	ComponentCount int64 `gorm:"column:component_count" json:"componentCount"` // 组件数量
	VulnCount      int64 `gorm:"column:vuln_count" json:"vulnCount"`           // 漏洞数量
	LicenseCount   int64 `gorm:"column:license_count" json:"licenseCount"`     // 许可数量

	// 风险等级统计
	HighRiskCount     int64 `gorm:"column:high_risk_count" json:"highRiskCount"`         // 高危数量
	MediumRiskCount   int64 `gorm:"column:medium_risk_count" json:"mediumRiskCount"`     // 中危数量
	LowRiskCount      int64 `gorm:"column:low_risk_count" json:"lowRiskCount"`           // 低危数量
	CriticalRiskCount int64 `gorm:"column:critical_risk_count" json:"criticalRiskCount"` // 超危数量

	// 扫描时间信息
	ScanStartTime int64 `gorm:"column:scan_start_time" json:"scanStartTime"` // 扫描开始时间
	ScanEndTime   int64 `gorm:"column:scan_end_time" json:"scanEndTime"`     // 扫描结束时间
	ScanDuration  int64 `gorm:"column:scan_duration" json:"scanDuration"`    // 扫描时长（秒）

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

// TableName 指定表名
func (vi *SourceCheckSummary) TableName() string {
	return "source_check_scan_summary"
}

func (vi *SourceCheckSummary) Check() error {
	if vi.ProjectUuid == "" {
		return fmt.Errorf("project_uuid is required")
	}
	if vi.SourceCheckUuid == "" {
		return fmt.Errorf("source_check_uuid is required")
	}
	return nil
}

func (vi *SourceCheckSummary) GenUniqueID() uint64 {
	key := fmt.Sprintf("%s-%s-%s", vi.ProjectUuid, vi.SourceCheckUuid, vi.CheckNo)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *SourceCheckSummary) Serialize() {
	if vi.UniqueID == 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
}

func (vi *SourceCheckSummary) Deserialize() {
}

func (vi *SourceCheckSummary) Same(af *SourceCheckSummary) bool {
	return vi.UniqueID == af.UniqueID
}
