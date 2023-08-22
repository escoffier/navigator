package model

import (
	json "github.com/json-iterator/go"
)

type ModuleGroup struct {
	Id           int    `gorm:"primary_key;AUTO_INCREMENT" json:"id"`
	ModuleNameZh string `json:"module_name_zh"`
	ModuleNameEn string `json:"module_name_en"`
}

func (m ModuleGroup) TableName() string {
	return "ivan_platform_modules"
}

type Url struct {
	Id      int    `gorm:"primary_key;AUTO_INCREMENT" json:"id" `
	UrlId   int    `gorm:"column:url_id" json:"url_id"`
	UrlName string `json:"url_name"`
}

func (u Url) TableName() string {
	return "ivan_platform_urls"
}

type RoleType string

const (
	RoleTypeSuperAdmin    RoleType = "super-admin"
	RoleTypePlatformAdmin RoleType = "platform-admin"
	RoleTypeAdmin         RoleType = "admin"
	RoleTypeAudit         RoleType = "audit"
	RoleTypeNormal        RoleType = "normal"

	SuperAdminUsername = "SeedAdmin"
	DefaultPassword    = "ksJ@12MczH"

	UserStatusNormal   = 1 // "normal"
	UserStatusInactive = 2 // "inactive"
	UserStatusLock     = 3 // "lock"
	UserStatusDisabled = 4 // "disabled"
)

type User struct {
	ID                     int64    `gorm:"primary_key;AUTO_INCREMENT" json:"-"`
	UserName               string   `gorm:"index:username,unique;column:username" json:"userName"` // index
	Account                string   `gorm:"index:account,unique;column:account" json:"account"`
	Nickname               string   `gorm:"column:nickname"`
	Pwd                    string   `json:"-" bson:"pwd"`
	Salt                   string   `gorm:"column:salt" json:"-"`
	Role                   RoleType `gorm:"column:rule" json:"rule"` // typo; role
	ModuleID               string   `gorm:"column:module_id" json:"-"`
	CreatedAt              int64    `json:"create_at"`
	Creator                string   `gorm:"column:creator"`
	LoginSecretKey         string   `gorm:"column:login_secret_key" json:"-"`
	LoginSecretKeyExpireAt int64    `gorm:"column:login_secret_key_expire_at" json:"-"`
	Token                  string   `gorm:"column:token; type:text" json:"-"`
	TokenExpireAt          int64    `gorm:"column:token_expire_at" json:"-"`
	Platform               string   `gorm:"column:platform" json:"platform"`
	Status                 int      `gorm:"column:status" json:"status"`
	MustChangePwd          bool     `gorm:"column:must_change_pwd" json:"mustChangePwd"`      // 该用户是否必须修改密码
	LastChangePwdAt        int64    `gorm:"column:last_change_pwd_at" json:"lastChangePwdAt"` // 上次修改密码的时间

	// 添加字段：MFA密钥 和 MFA绑定状态
	MfaSecret            string `gorm:"column:mfa_secret" json:"-"`
	MfaStatus            bool   `gorm:"column:mfa_status" json:"-"`
	TwoFactorKey         string `gorm:"column:two_factor_key" json:"-"`
	TwoFactorKeyExpireAt int64  `gorm:"column:two_factor_key_expire_at" json:"-"`
}

func (u User) TableName() string {
	return "ivan_platform_users"
}

type UserLite struct {
	Username string `json:"username"`
	Account  string `json:"account"`
}

type Email struct {
	ID        int64  `gorm:"primary_key;AUTO_INCREMENT" json:"id"`
	HashCode  string `gorm:"index:hash_code, unique;column:hash_code;size:64" json:"hash_code"`
	CreatedAt int64  `gorm:"column:created_at" json:"created_at"`
	UserName  string `gorm:"index:email_username, unique;column:username" json:"userName"` // index
}

func (e Email) TableName() string {
	return "ivan_platform_emails"
}

type LdapGroup struct {
	ID      int32    `gorm:"primaryKey;autoIncrement;column:id"`
	Name    string   `gorm:"column:name; unique"`
	Role    RoleType `gorm:"column:role"`
	Modules string   `gorm:"column:modules"`
}

type LdapGroupDisplay struct {
	ID      int32          `json:"id"`
	Name    string         `json:"name"`
	Role    RoleType       `json:"role"`
	Modules []*ModuleGroup `json:"modules"`
}

func (l LdapGroup) TableName() string {
	return "ivan_platform_ldap_groups"
}

func GetModuleIDByGroup(group *LdapGroup) []int {
	var result []int
	if group.Modules != "" {
		_ = json.Unmarshal([]byte(group.Modules), &result)
	}

	return result
}

func GetModuleIDByGroups(groups []*LdapGroup) []int {
	var hash = make(map[int]struct{})
	for _, group := range groups {
		modules := GetModuleIDByGroup(group)
		for _, moduleID := range modules {
			hash[moduleID] = struct{}{}
		}
	}
	var result = make([]int, 0, len(hash))
	for moduleID := range hash {
		result = append(result, moduleID)
	}

	return result
}
