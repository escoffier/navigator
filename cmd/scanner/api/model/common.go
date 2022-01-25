package apimodel

import "gorm.io/gorm"

type Page struct {
	// 查询结构数据条数
	Limit int `json:"limit" query:"limit" form:"limit"`
	// 查询结果数据偏移
	Offset int `json:"offset" query:"offset" form:"offset"`
}

func (p *Page) SqlBuild(db *gorm.DB) *gorm.DB { // nolint
	return db.Limit(p.Limit).Offset(p.Offset)
}
