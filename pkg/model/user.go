package model

import "go.mongodb.org/mongo-driver/bson/primitive"

type ModuleGroup struct {
	Id           int    `gorm:"primary_key;AUTO_INCREMENT" json:"id"`
	ModuleNameZh string `json:"module_name_zh"`
	ModuleNameEn string `json:"module_name_en"`
	Url          []Url  `gorm:"-" json:"-"`
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
	Rule        string        `gorm:"column:rule" json:"rule"`
	ModuleID    string        `gorm:"column:module_id" json:"-"`
	ModuleGroup []ModuleGroup `gorm:"-" json:"module_group"`
	Checked     bool          `json:"checked"`
	CreateAt    int64         `json:"create_at"`
	BanStatus   int32         `json:"ban_status" gorm:"column:ban_status"`
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
