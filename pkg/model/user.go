package model

import (
	"context"

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

const (
	RoleSuperAdmin     = "super-admin"
	RoleAdmin          = "admin"
	RoleNormal         = "normal"
	UserSuperAdmin     = "SeedAdmin"
	PasswordSuperAdmin = "e$Db8Cf6@3"
	DefaultPassword    = "ksJ@12MczH"
)

type User struct {
	ID          int64         `gorm:"primary_key;AUTO_INCREMENT" json:"-"`
	UserName    string        `gorm:"index:username,unique;column:username" json:"userName"` // index
	Pwd         string        `json:"-" bson:"pwd"`
	Salt        string        `gorm:"column:salt" json:"-"`
	Rule        string        `gorm:"column:rule" json:"rule"` // typo; role
	ModuleID    string        `gorm:"column:module_id" json:"-"`
	ModuleGroup []ModuleGroup `gorm:"-" json:"module_group"`
	External    bool          `gorm:"-" json:"-"`
	Checked     bool          `json:"checked"`
	CreatedAt   int64         `json:"create_at"`
	BanStatus   int32         `json:"ban_status" gorm:"column:ban_status"`
}

func (u *User) GenerateSession(external bool) *UserSession {
	return &UserSession{
		Username:  u.UserName,
		Role:      u.Rule,
		ModuleID:  u.ModuleID,
		Checked:   u.Checked,
		BanStatus: u.BanStatus,
		External:  external,
	}
}

type UserSession struct {
	Username  string `json:"username"`
	Role      string `json:"role"`
	ModuleID  string `json:"moduleID"`
	Checked   bool   `json:"checked"`
	BanStatus int32  `json:"banStatus"`
	External  bool   `json:"external"`
}

func (u User) TableName() string {
	return "ivan_platform_users"
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
	ID      int32  `gorm:"primaryKey;autoIncrement;column:id"`
	Name    string `gorm:"column:name; unique"`
	Role    string `gorm:"column:role"`
	Modules string `gorm:"column:modules"`
}

type LdapGroupDisplay struct {
	ID      int32          `json:"id"`
	Name    string         `json:"name"`
	Role    string         `json:"role"`
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

const (
	CtxUserSessionKey = "ctx_user_session"
)

func GetSessionFromContext(ctx context.Context) (*UserSession, bool) {
	val := ctx.Value(CtxUserSessionKey)
	if val == nil {
		return nil, false
	}
	userSession, ok := val.(*UserSession)
	return userSession, ok
}

func GetUsernameFromContext(ctx context.Context) string {
	userSession, ok := GetSessionFromContext(ctx)
	if ok && userSession != nil {
		return userSession.Username
	}
	return ""
}
