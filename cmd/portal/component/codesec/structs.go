package codesec

import (
	portal "gitlab.com/piccolo_su/vegeta/cmd/portal/model"
)

// ===== 通用结构体 =====

// APIResponse 通用API响应结构
type APIResponse struct {
	Status  bool   `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

// ===== 扫描结果相关结构体 =====

// ScanResultParam 获取扫描结果的请求参数
type ScanResultParam struct {
	ProjectUuid  string `json:"projectUuid"`
	TaskId       string `json:"taskId"`
	AccessSecret string `json:"accessSecret"`
	AccessKey    string `json:"accessKey"`
}

// ScanResultResponse 扫描结果响应
type ScanResultResponse struct {
	APIResponse
	Data                ScanResultData    `json:"data"`
	QualityWeaknessNum  int               `json:"qualityWeaknessNum,omitempty"`
	StatisticalCodelist []StatisticalCode `json:"statisticalCodelist,omitempty"`
	GitInfo             GitInfo           `json:"gitInfo,omitempty"`
}

// ScanResultData 扫描结果数据
type ScanResultData struct {
	Language                Language          `json:"language"`
	CyclomaticComplexityNum int               `json:"cyclomaticComplexityNum"`
	RepetitiveLines         int               `json:"repetitiveLines"`
	FileNum                 int               `json:"fileNum"`
	FileSize                int               `json:"fileSize"`
	ScanResult              ScanResult        `json:"scanResult"`
	QualityWeaknessNum      int               `json:"qualityWeaknessNum,omitempty"`
	StatisticalCodelist     []StatisticalCode `json:"statisticalCodelist,omitempty"`
	GitInfo                 GitInfo           `json:"gitInfo,omitempty"`
}

// Language 编程语言信息
type Language struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// ScanResult 扫描结果统计
type ScanResult struct {
	SecurityVulNum          int            `json:"securityVulNum"`
	CodeSecurityWeaknessNum int            `json:"codeSecurityWeaknessNum"`
	CriticalNum             int            `json:"criticalNum"`
	HighNum                 int            `json:"highNum"`
	MediumNum               int            `json:"mediumNum"`
	LowNum                  int            `json:"lowNum"`
	NoteNum                 int            `json:"noteNum"`
	NewDiscoveryNum         int            `json:"newDiscoveryNum"`
	RepeatNum               int            `json:"repeatNum"`
	IsReviseNum             int            `json:"isReviseNum"`
	LibraryNum              int            `json:"libraryNum"`
	CveNum                  int            `json:"cveNum"`
	CnnvdNum                int            `json:"cnnvdNum"`
	CodeLineNum             int            `json:"codeLineNum"`
	CommentLines            int            `json:"commentLines"`
	BlankLines              int            `json:"blankLines"`
	TreeList                []TreeListNode `json:"treeList"`
}

// TreeListNode 漏洞树节点
type TreeListNode struct {
	Label         string         `json:"label"`
	AuditCount    int            `json:"auditCount"`
	Count         int            `json:"count"`
	Data          TreeNodeData   `json:"data,omitempty"`
	Children      []TreeListNode `json:"children,omitempty"`
	VulDataId     string         `json:"vulDataId,omitempty"`
	RiskId        int            `json:"riskId,omitempty"`
	VulDataName   string         `json:"vulDataName,omitempty"`
	VulDataCnName string         `json:"vulDataCnName,omitempty"`
}

// TreeNodeData 树节点附加数据
type TreeNodeData struct {
	IsTop bool `json:"isTop,omitempty"`
}

// StatisticalCode 代码统计信息
type StatisticalCode struct {
	ID                      int     `json:"id"`
	CodeLanguageName        string  `json:"codeLanguageName"`
	CodeLineNum             int     `json:"codeLineNum"`
	CommentLines            int     `json:"commentLines"`
	BlankLines              int     `json:"blankLines"`
	CyclomaticComplexityNum int     `json:"cyclomaticComplexityNum"`
	RepetitiveLines         int     `json:"repetitiveLines"`
	FileNum                 int     `json:"fileNum"`
	FileSize                float64 `json:"fileSize"`
	CodeRate                float64 `json:"codeRate"`
}

// GitInfo Git仓库信息
type GitInfo struct {
	Branch    string `json:"branch"`
	CommitId  string `json:"commitId"`
	ExtraMark string `json:"extraMark"`
}

// ===== 漏洞列表相关结构体 =====

// VulTrace 漏洞跟踪信息
type VulTrace struct {
	VulId     string    `json:"vulId"`
	VulTypeId string    `json:"vulTypeId"`
	Filename  string    `json:"filename"`
	RowNum    string    `json:"rowNum"`
	VulDataId string    `json:"vulDataId"`
	VulFlag   string    `json:"vulFlag"`
	Name      string    `json:"name"`
	TagId     int       `json:"tagId"`
	Tag       VulTag    `json:"tag"`
	RiskId    int       `json:"riskId"`
	Risk      VulRisk   `json:"risk"`
	NodeList  []VulNode `json:"nodeList"`
	Signer    string    `json:"signer"`
}

// VulTag 漏洞标签
type VulTag struct {
	ID         int    `json:"id"`
	NameLocale string `json:"nameLocale"`
	CnName     string `json:"cnName"`
}

// VulRisk 漏洞风险等级
type VulRisk struct {
	ID         int    `json:"id"`
	NameLocale string `json:"nameLocale"`
	CnName     string `json:"cnName"`
}

// VulNode 漏洞节点
type VulNode struct {
	ID        int    `json:"id"`
	OrgUuid   string `json:"orgUuid"`
	AppId     string `json:"appId"`
	RecordId  string `json:"recordId"`
	VulId     string `json:"vulId"`
	Filename  string `json:"filename"`
	LineCode  string `json:"lineCode"`
	LineNum   string `json:"lineNum"`
	CodeBlock string `json:"codeBlock"`
	IsSource  int    `json:"isSource"`
}

// VulnerabilityListParam 漏洞列表查询参数
type VulnerabilityListParam struct {
	CodesecAppId string `json:"codesecAppId"`
	TaskId       string `json:"taskId"`
	VulDataId    string `json:"vulDataId"`
	PageCurrent  int    `json:"pageCurrent,omitempty"`
	PageSize     int    `json:"pageSize,omitempty"`
	AccessKey    string `json:"accessKey"`
	AccessSecret string `json:"accessSecret"`
}

// VulnerabilityListResponse 漏洞列表响应
type VulnerabilityListResponse struct {
	APIResponse
	Data VulnerabilityListData `json:"data"`
}

// VulnerabilityListData 漏洞列表数据
type VulnerabilityListData struct {
	Total       int                  `json:"total"`
	PageTotal   int                  `json:"pageTotal"`
	PageCurrent int                  `json:"pageCurrent"`
	PageSize    int                  `json:"pageSize"`
	VulTraces   []VulnerabilityTrace `json:"vulTraces"`
}

// VulnerabilityTrace 漏洞跟踪信息
type VulnerabilityTrace struct {
	VulTrace  VulTrace  `json:"vulTrace"`
	VulId     string    `json:"vulId"`
	VulTypeId string    `json:"vulTypeId"`
	Filename  string    `json:"filename"`
	RowNum    string    `json:"rowNum"`
	VulDataId string    `json:"vulDataId"`
	VulFlag   string    `json:"vulFlag"`
	Name      string    `json:"name"`
	TagId     int       `json:"tagId"`
	Tag       VulTag    `json:"tag"`
	RiskId    int       `json:"riskId"`
	Risk      VulRisk   `json:"risk"`
	NodeList  []VulNode `json:"nodeList"`
	Signer    string    `json:"signer"`
}

// ===== 扫描任务相关结构体 =====

// ScanSubProjectResponse 发起扫描任务响应
type ScanSubProjectResponse struct {
	APIResponse
	Data ScanSubProjectData `json:"data"`
}

// ScanSubProjectData 发起扫描任务响应数据
type ScanSubProjectData struct {
	AppId    string `json:"appId"`    // 扫描任务id
	RecordId string `json:"recordId"` // 扫描记录id
}

// GetScanProgressResponse 查询扫描进度响应
type GetScanProgressResponse struct {
	APIResponse
	Data ScanProgressData `json:"data"`
}

// ScanProgressData 扫描进度响应数据
type ScanProgressData struct {
	Progress   int    `json:"progess"`    // 扫描进度 (0~100) - 注意：API返回的字段名是progess，不是progress
	CommitId   string `json:"commitId"`   // 最新提交的commitId（源代码来源选择GIT时返回）
	ScanTime   string `json:"scanTime"`   // 扫描开始时间
	FinishTime string `json:"finishTime"` // 扫描结束时间（扫描完成后返回）
	SpendTime  string `json:"spendTime"`  // 扫描时长（扫描完成后返回）
}

// ===== 扫描结果存储相关结构体 =====

// ScanResultRecord 扫描结果记录（用于数据库存储，不包含treeList）
type ScanResultRecord struct {
	ProjectUuid             string `json:"projectUuid"`
	TaskId                  string `json:"taskId"`
	SecurityVulNum          int    `json:"securityVulNum"`
	CodeSecurityWeaknessNum int    `json:"codeSecurityWeaknessNum"`
	CriticalNum             int    `json:"criticalNum"`
	HighNum                 int    `json:"highNum"`
	MediumNum               int    `json:"mediumNum"`
	LowNum                  int    `json:"lowNum"`
	NoteNum                 int    `json:"noteNum"`
	NewDiscoveryNum         int    `json:"newDiscoveryNum"`
	RepeatNum               int    `json:"repeatNum"`
	IsReviseNum             int    `json:"isReviseNum"`
	LibraryNum              int    `json:"libraryNum"`
	CveNum                  int    `json:"cveNum"`
	CnnvdNum                int    `json:"cnnvdNum"`
	CodeLineNum             int    `json:"codeLineNum"`
	CommentLines            int    `json:"commentLines"`
	BlankLines              int    `json:"blankLines"`
	// 项目基本信息
	LanguageId              int    `json:"languageId"`
	LanguageName            string `json:"languageName"`
	CyclomaticComplexityNum int    `json:"cyclomaticComplexityNum"`
	RepetitiveLines         int    `json:"repetitiveLines"`
	FileNum                 int    `json:"fileNum"`
	FileSize                int    `json:"fileSize"`
	// Git信息
	GitBranch    string `json:"gitBranch"`
	GitCommitId  string `json:"gitCommitId"`
	GitExtraMark string `json:"gitExtraMark"`
}

// ScanResultWithProjectInfo 包含项目信息的扫描结果（用于返回给调用方）
type ScanResultWithProjectInfo struct {
	ProjectUuid    string                `json:"projectUuid"`
	TaskId         string                `json:"taskId"`
	ScanResultData portal.CodesecSummary `json:"scanResultData"`
	Language       Language              `json:"language"`
}
