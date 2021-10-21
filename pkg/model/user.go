package model

import (
	"encoding/json"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ModuleGroup struct {
	Id           int    `gorm:"primary_key;AUTO_INCREMENT" json:"id"`
	ModuleNameZh string `json:"module_name_zh"`
	ModuleNameEn string `json:"module_name_en"`
}

func (m ModuleGroup) TableName() string {
	return "tensor_module"
}

type Url struct {
	Id      int    `gorm:"primary_key;AUTO_INCREMENT" json:"id" `
	UrlId   int    `gorm:"column:url_id" json:"url_id"`
	UrlName string `json:"url_name"`
}

func (u Url) TableName() string {
	return "tensor_url"
}

const (
	RoleSuperAdmin     = "super-admin"
	RoleAdmin          = "admin"
	RoleNormal         = "normal"
	UserSuperAdmin     = "SuperAdmin"
	PasswordSuperAdmin = "9a39820591e511160e9f993d30d92b19"
	DefaultPassword    = "tanzhen2020"
)

type MongoUser struct {
	ID       primitive.ObjectID `json:"id" bson:"_id"`
	UserName string             `json:"userName" bson:"user_name"` // index
	Pwd      string             `json:"pwd" bson:"pwd"`
	Title    string             `json:"title" bson:"title"`
	Name     string             `json:"name" bson:"name"`
	Email    string             `json:"email" bson:"email"`
	Group    string             `json:"group" bson:"group"`
	Avatar   string             `json:"avatar" bson:"avatar"`
}

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
	CreateAt    int64         `json:"create_at"`
	BanStatus   int32         `json:"ban_status" gorm:"column:ban_status"`
}

func (u *User) GenerateSession(external bool) *UserSession {
	return &UserSession{
		Username:  u.UserName,
		Pwd:       u.Pwd,
		Salt:      u.Salt,
		Role:      u.Rule,
		ModuleID:  u.ModuleID,
		Checked:   u.Checked,
		BanStatus: u.BanStatus,
		External:  external,
	}
}

type UserSession struct {
	Username  string `json:"username"`
	Pwd       string `json:"pwd"`
	Salt      string `json:"salt"`
	Role      string `json:"role"`
	ModuleID  string `json:"moduleID"`
	Checked   bool   `json:"checked"`
	BanStatus int32  `json:"banStatus"`
	External  bool   `json:"external"`
}

func (u User) TableName() string {
	return "tensor_user"
}

type Email struct {
	ID       int64  `gorm:"primary_key;AUTO_INCREMENT" json:"id"`
	HashCode string `gorm:"index:hash_code, unique;column:hash_code;size:64" json:"hash_code"`
	CreateAt int64  `json:"create_at"`
	UserName string `gorm:"index:email_username, unique;column:username" json:"userName"` // index
}

func (e Email) TableName() string {
	return "tensor_email"
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
	return "ldap_groups"
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
