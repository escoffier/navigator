package model

import (
	"fmt"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type Project struct {
	ID          int64  `gorm:"primary_key;AUTO_INCREMENT" json:"id"`  // 项目ID
	Uuid        string `gorm:"column:uuid" json:"uuid"`               // 项目标识符
	Name        string `gorm:"column:name" json:"name"`               // 项目名称
	Url         string `gorm:"column:url" json:"url"`                 // 仓库地址
	UserID      int64  `gorm:"column:user_id" json:"userId"`          // 所属的用户ID
	Description string `gorm:"column:description" json:"description"` // 项目描jj

	// git类型  1 : gitlab  2 : github  3 : gitee  6 : gerrit  7 : bitbucket
	GitType string `gorm:"column:git_type" json:"gitType"` // 仓库类型

	// git地址是否以https开头 0：否    1：是
	// UrlHead int `gorm:"column:url_head" json:"urlHead"`
	// git 认证类型  0.用户名密码认证（默认）  1.token认证 2.SSH密钥  凭据认证
	// AuthenticationMethod int    `gorm:"column:authentication_method" json:"authenticationMethod"`
	Token string `gorm:"column:token" json:"token"` // 仓库token

	CodesecUUID  string `gorm:"column:codesec_uuid" json:"codesecUUID"`    // codesec项目UUID
	CodesecAppID string `gorm:"column:codesec_app_id" json:"codesecAppID"` // codesec appID  用于扫描和获取扫描结果
	CodesecOrgID string `gorm:"column:codesec_org_id" json:"codesecOrgID"` // 团队 uuid

	SourceCheckUUID string `gorm:"column:source_check_uuid" json:"sourceCheckUUID"` // sourcecheck应用ID(appID)

	// gitlab版本 当gitType为gitlab必填 枚举值有   V3、V4说明：在GitLab 9.0及更高版本中，请选择 API V4版本
	// GitlabApiVersion string `gorm:"column:gitlab_api_version" json:"gitlabApiVersion"`
	// Protocol string `gorm:"column:protocol" json:"protocol"`
	Branch    string `gorm:"column:branch" json:"branch"` // 分支名
	Tag       string `gorm:"column:tag" json:"tag"`       // tag名
	BranchTag string `gorm:"-" json:"branchTag"`          // 分支名和tag名  当branch和tag同时存在时，branch优先级高于tag

	CodesecScanStatus       string `gorm:"column:codesec_scan_status" json:"codesecScanStatus"`              // codesec扫描状态
	SourceCheckScanStatus   string `gorm:"column:source_check_scan_status" json:"sourceCheckScanStatus"`     // sourcecheck扫描状态
	CodesecHighRisk         string `gorm:"column:codesec_high_risk" json:"codesecHighRisk"`                  // codesec最高风险等级
	CodesecHighSeverity     int64  `gorm:"column:codesec_high_severity" json:"codesecHighSeverity"`          // codesec最高风险等级
	CodesecScanStartAt      int64  `gorm:"column:codesec_scan_start_at" json:"codesecScanStartAt"`           // codesec扫描开始时间
	CodesecScanEndAt        int64  `gorm:"column:codesec_scan_end_at" json:"codesecScanEndAt"`               // codesec扫描结束时间
	CodesecScanMsg          string `gorm:"column:codesec_scan_msg" json:"codesecScanMsg"`                    // codesec扫描消息
	SourceCheckHighRisk     string `gorm:"column:source_check_high_risk" json:"sourceCheckHighRisk"`         // sourcecheck最高风险等级
	SourceCheckHighSeverity int64  `gorm:"column:source_check_high_severity" json:"sourceCheckHighSeverity"` // sourcecheck最高风险等级
	SourceCheckCheckNo      string `gorm:"column:source_check_check_no" json:"sourceCheckCheckNo"`           // sourcecheck检测任务的编号
	SourceCheckScanStartAt  int64  `gorm:"column:source_check_scan_start_at" json:"sourceCheckScanStartAt"`  // sourcecheck扫描开始时间
	SourceCheckScanMsg      string `gorm:"column:source_check_scan_msg" json:"sourceCheckScanMsg"`           // sourcecheck扫描消息
	SourceCheckScanEndAt    int64  `gorm:"column:source_check_scan_end_at" json:"sourceCheckScanEndAt"`      // sourcecheck扫描结束时间
	RiskLevel               string `gorm:"column:risk_level" json:"riskLevel"`                               // 风险级别
	LastScanAt              int64  `gorm:"column:last_scan_at" json:"lastScanAt"`                            // 最近扫描时间，也就是最近一次扫描开始时间

	Updater string `gorm:"column:updater" json:"updater"` // 最近一次更新人
	// sourceCheck
	SourceCheckToken string `gorm:"column:source_check_token" json:"sourceCheckToken"` // sourceCheck的访问令牌
	// codesec使用
	CodesecAk string `gorm:"column:codesec_ak" json:"codesecAk"` // 也就是 codesec的UserUuid
	CodesecSk string `gorm:"column:codesec_sk" json:"codesecSk"` // 也就是 codesec的AccessSecret

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *Project) LogStr() string {
	s := fmt.Sprintf("ID: %d, Name: %s, Url: %s, UserID: %d, CodesecUUID: %s, "+
		"SourceCheckUUID: %s", vi.ID, vi.Name, vi.Url, vi.UserID, vi.CodesecUUID, vi.SourceCheckUUID)
	return s
}

// 前端可更新的项目
func (vi *Project) ToUpdater() map[string]interface{} {
	updater := map[string]interface{}{
		"name":               vi.Name,
		"url":                vi.Url,
		"git_type":           vi.GitType,
		"description":        vi.Description,
		"token":              vi.Token,
		"branch":             vi.Branch,
		"tag":                vi.Tag,
		"source_check_token": vi.SourceCheckToken,
		"codesec_ak":         vi.CodesecAk,
		"codesec_sk":         vi.CodesecSk,
		"uuid":               vi.Uuid,
		"updater":            vi.Updater,
		"updated_at":         time.Now().UnixMilli(),
	}
	return updater
}

func (vi *Project) Serialize() {
	vi.Name = strings.TrimSpace(vi.Name)
	vi.Url = strings.TrimSpace(vi.Url)
	vi.Description = strings.TrimSpace(vi.Description)
	vi.Branch = strings.TrimSpace(vi.Branch)
	if vi.BranchTag == "tag" {
		vi.Tag = vi.Branch
		vi.Branch = ""
	}
	if vi.BranchTag == "branch" {
		vi.Tag = ""
	}
}

func (vi *Project) Deserialize() {
	if vi.Branch == "" && vi.Tag == "" {
		vi.BranchTag = "branch"
		vi.Branch = BranchMaster // 默认master
	}

	if vi.Branch != "" {
		vi.BranchTag = "branch"
	} else {
		vi.BranchTag = "tag"
	}

	if vi.BranchTag == "tag" {
		vi.Branch = vi.Tag
		vi.Tag = ""
	}
	if vi.BranchTag == "branch" {
		vi.Tag = ""
	}
}

func (vi *Project) Check() error {
	if vi.Name == "" {
		return fmt.Errorf("not get name")
	}
	if vi.Url == "" {
		return fmt.Errorf("not get url")
	}
	if vi.GitType == "" {
		return fmt.Errorf("not get gitType")
	}
	return nil
}

func (vi *Project) TableName() string {
	return "portal_project"
}

func (vi *Project) NeedUpdateCodesec() bool {
	if vi.CodesecScanStatus == consts.ScanStatusScanning {
		return true
	}

	return false
}

func (vi *Project) NeedUpdateSourceCheck() bool {
	if vi.SourceCheckScanStatus == consts.ScanStatusScanning {
		return true
	}
	return false
}

type SearchProjectParam struct {
	StartID               int64 `json:"startID"`
	UserID                int64
	ID                    int64
	Ids                   []int64
	Name                  string   // 用户名搜
	Url                   string   // 项目地址搜索
	Category              string   // 项目分类搜索
	GitType               []string // 仓库类型搜索
	RiskLevel             []string // 风险级别搜索
	ProjectUuid           string   // 项目UUID
	CodesecScanStatus     string   // codesec扫描状态搜索
	SourceCheckScanStatus string   // sourcecheck扫描状态搜索
	Filter                *imagesec.Filter
}

type UpdateProjectParam struct {
	ID              int64  `json:"id"`              // 项目ID
	CodesecUUID     string `json:"codesecUUID"`     // codesec项目UUID
	SourceCheckUUID string `json:"sourceCheckUUID"` // sourcecheck项目UUID
	Updater         map[string]interface{}
}
