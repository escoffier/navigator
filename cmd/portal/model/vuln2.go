package model

import (
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// CodeSecVuln 代码安全漏洞数据模型
// 根据需求只包含指定字段：树节点类型描述,漏洞类型名称,漏洞类型,语言,漏洞名称,漏洞库信息，语言类型,文件名,文件行数,严重等级,缺陷状态,缺陷跟踪类型
type CodeSecVuln struct {
	ID           int64  `gorm:"column:id" json:"id"`
	UniqueID     uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	ProjectUuid  string `gorm:"column:project_uuid" json:"projectUuid"`
	CodesecAppId string `gorm:"column:codesec_app_id" json:"codesecAppId"`
	TaskId       string `gorm:"column:task_id" json:"taskId"`
	VulId        string `gorm:"column:vul_id" json:"vulId"`

	VulTypeName  string `gorm:"column:vul_type_name" json:"vulTypeName"`  // 漏洞类型名称
	VulTypeId    string `gorm:"column:vul_type_id" json:"vulTypeId"`      // 漏洞类型
	LanguageName string `gorm:"column:language_name" json:"languageName"` // 语言
	VulName      string `gorm:"column:vul_name" json:"vulName"`           // 漏洞名称
	VulDataId    string `gorm:"column:vul_data_id" json:"vulDataId"`      // 漏洞库信息ID
	LanguageId   int    `gorm:"column:language_id" json:"languageId"`     // 语言类型
	Filename     string `gorm:"column:filename" json:"filename"`          // 文件名
	RowNum       string `gorm:"column:row_num" json:"rowNum"`             // 文件行数
	RiskId       int    `gorm:"column:risk_id" json:"riskId"`             // 严重等级ID
	RiskName     string `gorm:"column:risk_name" json:"riskName"`         // 严重等级名称
	TagId        int    `gorm:"column:tag_id" json:"tagId"`               // 缺陷状态ID
	TagName      string `gorm:"column:tag_name" json:"tagName"`           // 缺陷状态名称
	VulFlag      string `gorm:"column:vul_flag" json:"vulFlag"`           // 缺陷跟踪类型
	Signer       string `gorm:"column:signer" json:"signer"`              // 签名者
	SeverityInt  int64  `gorm:"column:severity_int" json:"severityInt"`   //
	Severity     string `gorm:"column:severity" json:"severity"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

// TableName 指定表名
func (vi *CodeSecVuln) TableName() string {
	return "codesec_vuln"
}

func (vi *CodeSecVuln) GenUniqueID() uint64 {
	key := fmt.Sprintf("%s-%s-%s", vi.ProjectUuid, vi.VulId, vi.TaskId)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *CodeSecVuln) Serialize() {
	if vi.UniqueID == 0 {
		vi.UniqueID = vi.GenUniqueID()
	}

	// 根据RiskName确定Severity和SeverityInt
	vi.Severity, vi.SeverityInt = SetSeverityFromGrade(vi.RiskName)
}

// Deserialize 反序列化处理
func (vi *CodeSecVuln) Deserialize() {
	// CodeSecVuln 暂无需要反序列化的复杂字段
}

// Check 数据校验
func (vi *CodeSecVuln) Check() error {
	if vi.ProjectUuid == "" {
		return fmt.Errorf("project_uuid is required")
	}
	if vi.VulId == "" {
		return fmt.Errorf("vul_id is required")
	}
	return nil
}

// Same 比较两个对象是否相同
func (vi *CodeSecVuln) Same(other *CodeSecVuln) bool {
	if other == nil {
		return false
	}
	return vi.UniqueID == other.UniqueID &&
		vi.VulId == other.VulId &&
		vi.VulName == other.VulName &&
		vi.ProjectUuid == other.ProjectUuid &&
		vi.TaskId == other.TaskId
}

type CodesecSummary struct {
	ID          int64  `gorm:"column:id" json:"id"`
	UniqueID    uint64 `gorm:"column:unique_id" json:"uniqueID,string"`
	ProjectUuid string `gorm:"column:project_uuid" json:"projectUuid"`
	CodesecUuid string `gorm:"column:codesec_uuid" json:"codesecUuid"` // Codesec应用ID
	TaskId      string `gorm:"column:task_id" json:"taskId"`
	ScanStatus  string `gorm:"column:scan_status" json:"scanStatus"`
	ScanMsg     string `gorm:"column:scan_msg" json:"scanMsg"`

	SecurityVulNum          int `gorm:"column:security_vul_num" json:"securityVulNum"`                    // 漏洞总数
	CodeSecurityWeaknessNum int `gorm:"column:code_security_weakness_num" json:"codeSecurityWeaknessNum"` // 代码安全缺陷数
	CriticalNum             int `gorm:"column:critical_num" json:"criticalNum"`                           // 严重漏洞数
	HighNum                 int `gorm:"column:high_num" json:"highNum"`                                   // 高危漏洞数
	MediumNum               int `gorm:"column:medium_num" json:"mediumNum"`                               // 中危漏洞数
	LowNum                  int `gorm:"column:low_num" json:"lowNum"`                                     // 低危漏洞数
	NoteNum                 int `gorm:"column:note_num" json:"noteNum"`                                   // 建议漏洞数
	NewDiscoveryNum         int `gorm:"column:new_discovery_num" json:"newDiscoveryNum"`                  // 新发现漏洞数
	RepeatNum               int `gorm:"column:repeat_num" json:"repeatNum"`                               // 重复漏洞数
	IsReviseNum             int `gorm:"column:is_revise_num" json:"isReviseNum"`                          // 已修复漏洞数
	LibraryNum              int `gorm:"column:library_num" json:"libraryNum"`                             // 库漏洞数
	CveNum                  int `gorm:"column:cve_num" json:"cveNum"`                                     // CVE漏洞数
	CnnvdNum                int `gorm:"column:cnnvd_num" json:"cnnvdNum"`                                 // CNNVD漏洞数

	CodeLineNum             int `gorm:"column:code_line_num" json:"codeLineNum"`                         // 代码行数
	CommentLines            int `gorm:"column:comment_lines" json:"commentLines"`                        // 注释行数
	BlankLines              int `gorm:"column:blank_lines" json:"blankLines"`                            // 空白行数
	CyclomaticComplexityNum int `gorm:"column:cyclomatic_complexity_num" json:"cyclomaticComplexityNum"` // 圈复杂度超标个数
	RepetitiveLines         int `gorm:"column:repetitive_lines" json:"repetitiveLines"`                  // 重复代码行数
	FileNum                 int `gorm:"column:file_num" json:"fileNum"`                                  // 文件数
	FileSize                int `gorm:"column:file_size" json:"fileSize"`                                // 文件总大小

	LanguageId   int    `gorm:"column:language_id" json:"languageId"`     // 语言ID
	LanguageName string `gorm:"column:language_name" json:"languageName"` // 语言名称

	GitBranch    string `gorm:"column:git_branch" json:"gitBranch"`        // Git分支
	GitCommitId  string `gorm:"column:git_commit_id" json:"gitCommitId"`   // Git提交ID
	GitExtraMark string `gorm:"column:git_extra_mark" json:"gitExtraMark"` // Git额外标记

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

// TableName 指定表名
func (vi *CodesecSummary) TableName() string {
	return "codesec_scan_summary"
}

func (vi *CodesecSummary) Check() error {
	if vi.ProjectUuid == "" {
		return fmt.Errorf("project_uuid is required")
	}
	if vi.TaskId == "" {
		return fmt.Errorf("task_id is required")
	}
	return nil
}

func (vi *CodesecSummary) GenUniqueID() uint64 {
	key := fmt.Sprintf("%s-%s", vi.ProjectUuid, vi.TaskId)
	uid := util.GenerateUUID64(key)
	vi.UniqueID = uid
	return uid
}

func (vi *CodesecSummary) Serialize() {
	if vi.UniqueID == 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
}

func (vi *CodesecSummary) Deserialize() {
}

func (vi *CodesecSummary) Same(af *CodesecSummary) bool {
	return vi.UniqueID == af.UniqueID
}

type ScanProgress struct {
	Msg        string `json:"msg"`        // 扫描状态信息（扫描成功）
	Progress   int    `json:"progress"`   // 扫描进度 (0~100)
	CommitId   string `json:"commitId"`   // 最新提交的commitId（源代码来源选择GIT时返回）
	ScanTime   string `json:"scanTime"`   // 扫描开始时间
	FinishTime string `json:"finishTime"` // 扫描结束时间（扫描完成后返回）
	SpendTime  string `json:"spendTime"`  // 扫描时长（扫描完成后返回）
}
