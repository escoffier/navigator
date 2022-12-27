package scanner_ci

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/types"
)

// Policy rule action
const (
	CiActionPass  = "pass"
	CiActionAlert = "alert"
	CiActionBlock = "block"
)

// Policy final result
const (
	CiPolicyResultCodeUnknown = iota + 1
	CiPolicyResultCodePass
	CiPolicyResultCodeAlert
	CiPolicyResultCodeBlock
	CiPolicyResultCodeException
)

const (
	// CiExitCodePass will return to jenkins when pass all rules, and we still return 0 with some exception
	CiExitCodePass = 0

	// CiExitCodeBlock will return to jenkins when match any rule and policy's action is block
	CiExitCodeBlock = 1
)

type ImageNamePattern struct {
	EndTime int64  `json:"end_time"` // white list end time,eg: 2023-01-01 12:00:00
	Value   string `json:"value"`    // name regexp string,eg: dev/test*
}

type ImageNameWhiteListResult struct {
	Match   bool             `json:"match"`   // true: match whitelist
	Pattern ImageNamePattern `json:"pattern"` // matched pattern
}

type PkgVuln struct {
	VulnId              string `json:"vuln_id"`
	PkgName             string `json:"pkg_name"`
	PkgInstalledVersion string `json:"pkg_installed_version"`
}

// VulnRule vulnerability ci rule
type VulnRule struct {
	Enabled           bool      `json:"enabled"`
	Severity          string    `json:"severity"`             // critical,high,medium...
	BlackListVulns    []string  `json:"black_list_vulns"`     // cve-id blacklist
	WhiteListVulns    []string  `json:"white_list_vulns"`     // cve-id whitelist
	WhiteListPkgVulns []PkgVuln `json:"white_list_pkg_vulns"` // cve-x-y of pkg-name and version
	IgnoreUnfixed     bool      `json:"ignore_unfixed"`       // true: ignore unfixed vuln when audit by other rules
	IgnoreLangPkgVuln bool      `json:"ignore_lang_pkg_vuln"`
	Action            string    `json:"action"`      // block or alert
	ActionCode        int       `json:"action_code"` // see CiPolicyResultCodePass etc.
}

type VulnWrapper struct {
	types.DetectedVulnerability
	Target string             `json:"target"`
	Class  report.ResultClass `json:"class,omitempty"`
	Type   string             `json:"type,omitempty"`
}

type VulnResult struct {
	SeverityResults  []VulnWrapper
	BlackListResults []VulnWrapper
	Remediation      string // remediation for os pkg. eg "RUN apt update -y nurse && ..."
	Match            bool   // true: match any rule
}

// VulnWhiteListResult container vunls that match vuln whitelist rule
type VulnWhiteListResult struct {
	UnfixedVulns []PkgVuln // ignore unfixed vuln
	LangPkgVulns []PkgVuln // ignore lang pkg vuln
	VulId        []PkgVuln // ignore vuln id
	PkgVulns     []PkgVuln // ignore vuln of pkg name and version
}

// Pattern sensitive file match pattern
type Pattern struct {
	Description string `json:"description"` // rule description,like:"Environment configuration file"
	SecretType  string `json:"secret_type"` // match mod: Filename ,FileContent, FileExt
	Value       string `json:"value"`       // regexp,like: *.rsa
}

type SensitiveFileRule struct {
	Enabled            bool      `json:"enabled"`
	DefaultFilePattern []Pattern `json:"default_file_pattern"`
	Ext                []Pattern `json:"ext"`         // file ext name,eg: .sql, .password
	ExcludeExt         []Pattern `json:"exclude_ext"` // whitelist,file ext
	Action             string    `json:"action"`
	ActionCode         int       `json:"action_code"` // see CiPolicyResultCodePass etc.
}

type SensitiveFileResult struct {
	Files        []string // files found by custom sensitive file rule
	DefaultFiles []string // files found by default sensitive file pattern
	Remediation  string   // remediation for sensitive files, eg. "delete /etc/id.rsa"
	Match        bool     //
}

// PolicyResult policy result, add result here when we have new rule
type PolicyResult struct {
	// identify every local scan result
	UUID string

	// image artifact which contain layer info,package info etc
	Artifact ImageArtifact

	// image vulnerabilities
	Vulnerabilities ImageVulnerabilities

	// snapshot of policy content at the time of ci-tool fetch
	PolicySnapShot Policy

	// jenkins or other devops tools' pipeline name
	PipelineName string

	// vuln match result
	MatchVulns VulnResult

	// vulns that match vuln whitelist rule
	MatchWhiteListVulns VulnWhiteListResult

	// sensitive files
	MatchSensitiveFiles SensitiveFileResult

	// image white list
	MatchImageWhiteListResult ImageNameWhiteListResult

	// exit code which return to devops tool
	ExitCode int // exit with this code: 0-pass or alert,1-block

	// summary msg to stdout
	ExistMsg string

	// policy final result code,see CiPolicyResulCodePass,... etc
	PolicyResultCode int

	// local scan start time
	ScanStartTime time.Time

	// local scan end time
	ScanEndTime time.Time
}

type VulnWhitelist struct {
	Name   string `json:"name"`   //cveID
	Object string `json:"object"` //all 全部生效。否则 xxx@123,rrr@456
}

// Policy protocol for ci-tool and ci-controller
type Policy struct {
	Name                string             `json:"name"`
	Vuln                VulnRule           `json:"vuln"`
	SensitiveFile       SensitiveFileRule  `json:"sensitive_file"`
	ImageNameWhiteLists []ImageNamePattern `json:"white_lists"`
}

// CiPolicy policy db schema
type CiPolicy struct {
	ID                  int64  `gorm:"primaryKey" json:"id"`
	CreatedAt           int64  `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"`
	UpdatedAt           int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"`
	Name                string `gorm:"type:varchar(255);" json:"name"`               // 策略名
	Comment             string `gorm:"type:varchar(255);" json:"comment"`            // 备注
	Operator            string `gorm:"type:varchar(255);" json:"operator"`           // 操作员名字
	Updater             string `gorm:"type:varchar(255);" json:"Updater"`            // 更新者名字
	VulnLevel           string `gorm:"type:varchar(255);" json:"vuln_level"`         // 漏洞按严重级别阻断
	VulnPolicy          string `gorm:"type:varchar(255);" json:"vuln_policy"`        //
	VulnEnable          bool   `gorm:"vuln_enable" json:"vuln_enable"`               // 漏洞开关
	IgnoreIrreparable   bool   `gorm:"ignore_irreparable" json:"ignore_irreparable"` // 忽略不可修复
	IgnoreLangaue       bool   `gorm:"ignore_langaue" json:"ignore_langaue"`         //忽略应用漏洞
	VulnWhitelist       []byte `gorm:"type:blob;" json:"vuln_whitelist"`
	VulnRuleMode        string `gorm:"type:varhar(255);column:vuln_rule_mode;" json:"vuln_rule_mode"`
	SensitiveEnable     bool   `gorm:"sensitive_enable" json:"sensitive_enable"`        // 敏感文件开关
	SensitiveFilePolicy string `gorm:"type:varchar(255);" json:"sensitive_file_policy"` // 自定义敏感文件规则
	SensitiveWhitelist  string `gorm:"type:varchar(255);" json:"sensitive_whitelist"`
	SensitiveRuleMode   string `gorm:"type:varchar(255);" json:"sensitive_rule_mode"`
	DeletedAt           int    `json:"deleted_at,omitempty"`
}

func (CiPolicy) TableName() string {
	return "ivan_ci_policies"
}

type CiScan struct {
	ID                    int64                       `gorm:"primaryKey" json:"id"`
	CreatedAt             int64                       `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"`
	UpdatedAt             int64                       `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"`
	DeletedAt             int                         `gorm:"coulmn:deleted_at"`
	ImageName             string                      `gorm:"type:varchar(255);" json:"image_name"`
	UniqueImage           uint64                      `gorm:"unique_name" json:"unique_name"`
	OS                    string                      `gorm:"type:varchar(64);column:os" json:"os"`
	PipelineName          string                      `gorm:"type:varchar(255);" json:"Pipeline_name"`
	Layers                []byte                      `gorm:"type:blob" json:"layers"`
	PolicySnapshot        []byte                      `gorm:"type:MediumBlob" json:"-"`
	SeverityHistogram     model.SeverityHistogramInfo `gorm:"-" json:"severityHistogram"` // 评级集合
	SeverityHistogramJSON []byte                      `gorm:"type:MediumBlob"`
	MatchWhitelist        bool                        `gorm:"column:match_whitelist" json:"match_whitelist"`
	Mode                  int                         `gorm:"" json:"mode"`
	Flag                  uint64                      `gorm:"column:flag" json:"flag"`
	Message               string                      `gorm:"type:varchar(255)" json:"message"` // 错误信息
	Remediation           []byte                      `gorm:"type:blob" json:"remediation"`
	StartedAt             int64                       `gorm:"autoUpdateTime:milli;column:started_at" json:"started_at"` // 扫描开始时间
	FinishAt              time.Time                   `gorm:"column:finish_at" json:"finish_at"`                        // 扫描结束时间
}

func (CiScan) TableName() string {
	return `ivan_ci_scan_images`
}

type CiVulns struct {
	ID           int64               `gorm:"primaryKey" json:"id"`
	CreatedAt    int64               `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"`
	UpdatedAt    int64               `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"`
	DeletedAt    int                 `json:"deleted_at"`
	Target       string              `gorm:"column:target" json:"target"`
	Name         string              `gorm:"type:varchar(255);uniqueIndex:uniq_idx_vuln,priority:1" json:"name"` // 形如CVE-2021-28831
	Namespace    string              `gorm:"type:varchar(255)" json:"namespace"`                                 // 发行版名字：alpine，redhat等
	Description  string              `gorm:"type:text" json:"description"`                                       // 描述
	Link         []string            `gorm:"-" json:"link"`                                                      // 参考链接
	LinkJSON     []byte              `gorm:"type:Blob" json:"-"`
	Severity     string              `gorm:"type:varchar(255)" json:"severity"` // 威胁等级
	SeverityInt  int                 `gorm:"column:severity_int" json:"severity_int"`
	Metadata     *model.VulnMatedata `gorm:"-" json:"metadata"`
	MetadataJSON []byte              `gorm:"type:Blob" json:"-"`                                                        // 元数据
	PkgName      string              `gorm:"type:varchar(255);uniqueIndex:uniq_idx_vuln,priority:2" json:"pkg_name"`    // 软件包来源
	PkgVersion   string              `gorm:"type:varchar(255);uniqueIndex:uniq_idx_vuln,priority:3" json:"pkg_version"` // 软件包版本
	FixedBy      string              `gorm:"type:varchar(255)" json:"fixedby"`                                          // 修复建议
	UniqueVuln   uint64              `gorm:"column:unique_vuln" json:"unique_vuln,string"`
	ExtraInfo    []byte              `gorm:"type:Blob" json:"-"` //  预留，漏洞属性。如我们自己的漏洞评级
	CheckSum     uint64              `gorm:"column:check_sum" json:"check_sum,string"`
	Class        string              `gorm:"column:target" json:"class"`      // 代表是系统包还是语言包 os-pkgs
	Language     string              `gorm:"column:language" json:"language"` // 把编程语言入库用于搜索 统一存小写，便于搜索
	Frame        string              `gorm:"column:frame" json:"frame"`       // 开发框架筛选
	Match        int                 `gorm:"-" json:"match"`                  //黑名单类型
	White        bool                `gorm:"-" json:"white"`                  //是否在白名单内
}

func (vn *CiVulns) GenCheckSum() uint64 {
	createdAt, updatedAt, preCheck := vn.CreatedAt, vn.UpdatedAt, vn.CheckSum
	vn.CreatedAt = 0
	vn.UpdatedAt = 0
	vn.CheckSum = 0

	bys, err := json.Marshal(vn)
	vn.CreatedAt, vn.UpdatedAt, vn.CheckSum = createdAt, updatedAt, preCheck
	if err != nil {
		return 0
	}
	return util.GenerateUUID64(string(bys))
}

func (vn *CiVulns) Serialize() {
	if vn.Metadata != nil {
		sort.Sort(model.CnvdMetadatas(vn.Metadata.CNVDs))
		bys, err := json.Marshal(vn.Metadata)
		if err != nil {
			logging.GetLogger().Err(err).Msg("Vuln.Serialize")
		} else {
			vn.MetadataJSON = bys
		}
	}
	if len(vn.Link) > 0 {
		sort.Strings(vn.Link)
		bys, err := json.Marshal(vn.Link)
		if err != nil {
			logging.GetLogger().Err(err).Msg("Vuln.Serialize")
		} else {
			vn.LinkJSON = bys
		}
	}
	if vn.Language == "" {
		vn.Language = model.GetVulnLanguageMap()[vn.Namespace] // 如果没有编程语言，就存空
	}

	if vn.Language == "java" {
		if strings.Contains(vn.PkgName, "struts2") {
			vn.Frame = "struts2"
		}
		if strings.Contains(vn.PkgName, "fastjson") {
			vn.Frame = "fastjson"
		}
	}
}

func (vn *CiVulns) Deserialize() {
	if len(vn.MetadataJSON) > 0 {
		meta := model.VulnMatedata{}
		if err := json.Unmarshal(vn.MetadataJSON, &meta); err != nil {
			logging.GetLogger().Err(err).Msg("Vuln.Deserialize")
			meta = model.VulnMatedata{} // 一定改成默认值
		}
		vn.Metadata = &meta
	}

	if len(vn.LinkJSON) > 0 {
		link := make([]string, 0)
		if err := json.Unmarshal(vn.LinkJSON, &link); err != nil {
			logging.GetLogger().Err(err).Msg("Vuln.Deserialize")
			link = make([]string, 0)
		}
		vn.Link = link
	}
}

func (vn *CiVulns) GenUniqueVuln() uint64 {
	key := fmt.Sprintf(consts.UniqueVulnFamat, vn.Name, vn.PkgName, vn.PkgVersion)
	uid := util.GenerateUUID64(key)
	return uid
}

func (CiVulns) TableName() string {
	return `ivan_ci_scan_vulns`
}

type CiVulnImage struct {
	ID          int64  `gorm:"primaryKey" json:"id"`
	CreatedAt   int64  `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"`
	UpdatedAt   int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"`
	SeverityInt int    `gorm:"severity_int" json:"severity_int"`
	UniqueVuln  uint64 `gorm:"column:unique_vuln" json:"unique_vuln"` // 漏洞的唯一标识
	ImageID     int64  `gorm:"column:image_id" json:"image_id"`       // 镜像id
	MatchPolicy int    `gorm:"column:match_policy" json:"match_policy"`
	White       bool   `gorm:"white" json:"white"`
}

func (CiVulnImage) TableName() string {
	return `ivan_ci_scan_vuln_images`
}

type CiWhitelist struct {
	ID         int64  `gorm:"primaryKey" json:"id"`
	CreatedAt  int64  `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"`
	UpdatedAt  int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"`
	Name       string `gorm:"type:varchar(255);" json:"name"`
	ExpireTime int64  `gorm:"coulmn:expire_time" json:"expire_time"`
}

type CiWhitelistReq struct {
	ID         int64  `gorm:"primaryKey" json:"id"`
	CreatedAt  int64  `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"`
	UpdatedAt  int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"`
	Name       string `gorm:"type:varchar(255);" json:"name"`
	ExpireTime int64  `json:"expire_time"`
}

func (CiWhitelist) TableName() string {
	return `ivan_ci_whitelist`
}

type CiPkgs struct {
	ID        int64  `gorm:"primaryKey" json:"id"`
	CreatedAt int64  `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"`
	UpdatedAt int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"`
	UniquePkg string `gorm:"type:varchar(255);column:unique_pkg" json:"unique_pkg"` // pkg:version
	ImageID   int64  `gorm:"column:image_id" json:"image_id"`                       // 镜像id
	License   string `gorm:"type:varchar(255);column:license" json:"license"`
	Layer     string `gorm:"type:varchar(255);column:layer"`
}

func (CiPkgs) TableName() string {
	return "ivan_ci_scan_pkgs"
}

type CiSensitiveImages struct {
	ID          int64  `gorm:"primaryKey" json:"id"`
	CreatedAt   int64  `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"`
	UpdatedAt   int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"`
	File        string `gorm:"type:text;column:file" json:"file"`
	MatchPolicy bool   `gorm:"type:bool;column:match_policy" json:"match_policy"`
	ImageID     int64  `gorm:"column:image_id" json:"image_id"`
}

func (CiSensitiveImages) TableName() string {
	return `ivan_ci_scan_sensitives`
}

type CiPkgImage struct {
	ID         int64  `gorm:"primaryKey" json:"id"`
	CreatedAt  int64  `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"`
	UpdatedAt  int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"`
	UniquePkg  string `gorm:"type:varchar(255);column:unique_pkg" json:"unique_pkg"` // pkg:version
	UniqueVuln uint64 `gorm:"column:unique_vuln" json:"unique_vuln"`                 // 漏洞的唯一标识
	ImageID    int64  `gorm:"column:image_id" json:"image_id"`                       // 镜像id
}

func (CiPkgImage) TableName() string {
	return "ivan_ci_scan_pkg_images"
}

type CiPolicyAPI struct {
	ID                  int64           `gorm:"primaryKey" json:"id"`
	CreatedAt           int64           `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"`
	UpdatedAt           int64           `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"`
	Name                string          `gorm:"type:varchar(255);" json:"name"`               // 策略名
	Comment             string          `gorm:"type:varchar(255);" json:"comment"`            // 备注
	Operator            string          `gorm:"type:varchar(255);" json:"operator"`           // 操作员名字
	Updater             string          `gorm:"type:varchar(255);" json:"Updater"`            // 更新者名字
	VulnLevel           string          `gorm:"type:varchar(255);" json:"vuln_level"`         // 漏洞按严重级别阻断
	VulnPolicy          string          `gorm:"type:varchar(255);" json:"vuln_policy"`        //
	VulnEnable          bool            `gorm:"vuln_enable" json:"vuln_enable"`               // 漏洞开关
	IgnoreIrreparable   bool            `gorm:"ignore_irreparable" json:"ignore_irreparable"` // 忽略不可修复
	VulnWhitelist       []VulnWhitelist `gorm:"type:varchar(255);" json:"vuln_whitelist"`
	IgnoreLangaue       bool            `gorm:"ignore_langaue" json:"ignore_langaue"` //忽略应用漏洞
	VulnRuleMode        string          `gorm:"type:varhar(255);column:vuln_rule_mode;" json:"vuln_rule_mode"`
	SensitiveEnable     bool            `gorm:"sensitive_enable" json:"sensitive_enable"`        // 敏感文件开关
	SensitiveFilePolicy string          `gorm:"type:varchar(255);" json:"sensitive_file_policy"` // 自定义敏感文件规则
	SensitiveWhitelist  string          `gorm:"type:varchar(255);" json:"sensitive_whitelist"`
	SensitiveRuleMode   string          `gorm:"type:varchar(255);" json:"sensitive_rule_mode"`
	DeletedAt           int             `json:"deleted_at,omitempty"`
}

func (c *CiPolicyAPI) TransToPolicy() CiPolicy {
	var err error
	res := CiPolicy{}
	res.ID = c.ID
	res.CreatedAt = c.CreatedAt
	res.UpdatedAt = c.UpdatedAt
	res.Name = c.Name
	res.Comment = c.Comment
	res.Operator = c.Operator
	res.Updater = c.Updater
	res.VulnLevel = c.VulnLevel
	res.VulnPolicy = c.VulnPolicy
	res.VulnEnable = c.VulnEnable
	res.IgnoreIrreparable = c.IgnoreIrreparable
	res.IgnoreLangaue = c.IgnoreLangaue
	res.VulnRuleMode = c.VulnRuleMode
	res.SensitiveEnable = c.SensitiveEnable
	res.SensitiveFilePolicy = c.SensitiveFilePolicy
	res.SensitiveWhitelist = c.SensitiveWhitelist
	res.SensitiveRuleMode = c.SensitiveRuleMode
	res.VulnWhitelist, err = json.Marshal(c.VulnWhitelist)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("marshal vulnWhitelist error")
	}
	return res
}

func (c *CiPolicy) TransToPolicyAPI() CiPolicyAPI {
	var err error
	res := CiPolicyAPI{}
	res.ID = c.ID
	res.CreatedAt = c.CreatedAt
	res.UpdatedAt = c.UpdatedAt
	res.Name = c.Name
	res.Comment = c.Comment
	res.Operator = c.Operator
	res.Updater = c.Updater
	res.VulnLevel = c.VulnLevel
	res.VulnPolicy = c.VulnPolicy
	res.VulnEnable = c.VulnEnable
	res.IgnoreIrreparable = c.IgnoreIrreparable
	res.IgnoreLangaue = c.IgnoreLangaue
	res.VulnRuleMode = c.VulnRuleMode
	res.SensitiveEnable = c.SensitiveEnable
	res.SensitiveFilePolicy = c.SensitiveFilePolicy
	res.SensitiveWhitelist = c.SensitiveWhitelist
	res.SensitiveRuleMode = c.SensitiveRuleMode
	err = json.Unmarshal(c.VulnWhitelist, &res.VulnWhitelist)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("marshal vulnWhitelist error")
	}
	return res
}
