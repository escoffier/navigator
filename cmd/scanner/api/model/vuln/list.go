package vuln

import (
	"fmt"

	"gorm.io/gorm"

	api "gitlab.com/piccolo_su/vegeta/cmd/scanner/api/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

// ListReq 漏洞列表请求
type ListReq struct {
	api.Page `json:",inline"`
	// 搜索关键字, 如果为空则不关键字搜索
	Keyword string `json:"keyword" query:"keyword" form:"keyword"`
}

func (l *ListReq) SqlBuild(db *gorm.DB) *gorm.DB { // nolint
	db = l.Page.SqlBuild(db)
	if l.Keyword != "" {
		db = db.Where("name LIKE ?", fmt.Sprintf("%%%s%%", l.Keyword))
	}
	return db
}

// ListResp 漏洞列表响应
type ListResp []*Detail

func (l *ListResp) Build(vulns []*model.Vuln) {
	*l = make([]*Detail, 0, len(vulns))
	for _, v := range vulns {
		detail := new(Detail)
		detail.Build(v)
		*l = append(*l, detail)
	}
}
