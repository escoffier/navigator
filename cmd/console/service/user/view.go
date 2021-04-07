package user

import "gitlab.com/piccolo_su/vegeta/pkg/model"

type UView struct {
	ID          int64             `gorm:"primary_key" json:"id" bson:"_id"`
	UserName    string            `gorm:"index:username;column:username" json:"userName" bson:"user_name"` // index
	Pwd         string            `json:"pwd" bson:"pwd"`
	Salt        string            `gorm:"column:salt" json:"salt"`
	Rule        string            `gorm:"column:rule" json:"rule"`
	ModuleID    string            `gorm:"column:module_id" json:"module_id"`
	ModuleGroup model.ModuleGroup `json:"module_group"`
	Checked     bool              `json:"checked"`
	CreateAt    int64             `json:"create_at"`
}
