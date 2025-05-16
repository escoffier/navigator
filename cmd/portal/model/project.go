package portal

import (
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type Project struct {
	ID          int64  `gorm:"primary_key;AUTO_INCREMENT" json:"id"`
	Name        string `gorm:"column:name" json:"name"`
	Url         string `gorm:"column:url" json:"url"`
	UserID      int64  `gorm:"column:user_id" json:"userId"`
	Description string `gorm:"column:description" json:"description"`
	// git类型  1 : gitlab  2 : github  3 : gitee  6 : gerrit  7 : bitbucket
	GitType string `gorm:"column:git_type" json:"gitType"`
	// git地址是否以https开头 0：否    1：是
	// UrlHead int `gorm:"column:url_head" json:"urlHead"`
	// git 认证类型  0.用户名密码认证（默认）  1.token认证 2.SSH密钥  凭据认证
	// AuthenticationMethod int    `gorm:"column:authentication_method" json:"authenticationMethod"`
	Token           string `gorm:"column:token" json:"token"`
	CodesecUUID     string `gorm:"column:codesec_uuid" json:"codesecUUID"`
	SourceCheckUUID string `gorm:"column:source_check_uuid" json:"sourceCheckUUID"`
	// gitlab版本 当gitType为gitlab必填 枚举值有   V3、V4说明：在GitLab 9.0及更高版本中，请选择 API V4版本
	// GitlabApiVersion string `gorm:"column:gitlab_api_version" json:"gitlabApiVersion"`
	// Protocol string `gorm:"column:protocol" json:"protocol"`
	Branch    string `gorm:"column:branch" json:"branch"` // 分支名
	Tag       string `gorm:"column:tag" json:"tag"`       // tag名
	BranchTag string `gorm:"-" json:"branchTag"`          // 分支名和tag名  当branch和tag同时存在时，branch优先级高于tag

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (u *Project) ToUpdater() map[string]interface{} {
	updater := map[string]interface{}{
		"name":        u.Name,
		"url":         u.Url,
		"git_type":    u.GitType,
		"description": u.Description,
		"token":       u.Token,
		"branch":      u.Branch,
		"tag":         u.Tag,
	}
	return updater
}

func (u *Project) Serialize() {
	u.Name = strings.TrimSpace(u.Name)
	u.Url = strings.TrimSpace(u.Url)
	u.Description = strings.TrimSpace(u.Description)
	u.Branch = strings.TrimSpace(u.Branch)
	if u.BranchTag == "tag" {
		u.Tag = u.Branch
		u.Branch = ""
	}
	if u.BranchTag == "branch" {
		u.Tag = ""
	}
}

func (u *Project) Deserialize() {
	if u.Branch != "" {
		u.BranchTag = "branch"
	} else {
		u.BranchTag = "tag"
	}

	if u.BranchTag == "tag" {
		u.Branch = u.Tag
		u.Tag = ""
	}
	if u.BranchTag == "branch" {
		u.Tag = ""
	}
}

func (u *Project) Check() error {
	if u.Name == "" {
		return fmt.Errorf("not get name")
	}
	if u.Url == "" {
		return fmt.Errorf("not get url")
	}
	if u.GitType == "" {
		return fmt.Errorf("not get gitType")
	}
	return nil
}

func (u *Project) TableName() string {
	return "portal_project"
}

type SearchProjectParam struct {
	UserID   int64
	ID       int64
	Name     string
	Url      string
	Category string
	GitType  string
	Filter   *imagesec.Filter
}

type UpdateProjectParam struct {
	ID      int64
	Updater map[string]interface{}
}
