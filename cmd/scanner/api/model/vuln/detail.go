package vuln

import (
	"strconv"

	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type Detail struct {
	// 漏洞编号
	Name string `json:"name" query:"name" form:"name"`
	// 严重程度
	Severity string `json:"severity" query:"severity" form:"severity"`
	// 修复版本
	FixedVersion string `json:"fixedVersion" query:"fixedVersion" form:"fixedVersion"`
	// 漏洞介绍
	Description string `json:"description" query:"description" form:"description"`
	// 修复建议
	FixSuggestion string `json:"fixSuggestion" query:"fixSuggestion" form:"fixSuggestion"`
	// 参考链接
	References []string `json:"references" query:"references" form:"references"`
	// 漏洞类型
	Title string `json:"title" query:"title" form:"title"`
	// 漏洞评分
	Score float64 `json:"score" query:"score" form:"score"`
	// 软件包
	PkgName string `json:"pkgName" query:"pkgName" form:"pkgName"`
	// 软件版本
	PkgVersion string `json:"pkgVersion" query:"pkgVersion" form:"pkgVersion"`
	// cvss系统评分
	Cvss *Cvss `json:"cvss" query:"cvss" form:"cvss"`
}

type Cvss struct {
	Score  float64 `json:"score" query:"score" form:"score"`
	Vector string  `json:"vector" query:"vector" form:"vector"`
}

func (d *Detail) Build(vuln *model.Vuln) {
	if d == nil {
		*d = Detail{}
	}

	d.Name = vuln.Name
	d.Severity = vuln.Severity
	d.Description = vuln.Description
	d.References = vuln.Link
	d.FixedVersion = vuln.FixedBy

	for i := range vuln.Metadata.CNVDs {
		if vuln.Metadata.CNVDs[i].Title != "" {
			d.Title = vuln.Metadata.CNVDs[i].Title
			break
		}
	}

	if vuln.Metadata.CNNVDs.FixSuggestion != "" {
		d.FixSuggestion = vuln.Metadata.CNNVDs.FixSuggestion
	} else {
		d.FixSuggestion = vuln.FixedBy
	}

	d.Score, _ = strconv.ParseFloat(vuln.Metadata.CVSS.CVSSv3Score, 64)
	d.PkgName = vuln.PkgName
	d.PkgVersion = vuln.PkgVersion
	d.Cvss = &Cvss{
		Score:  d.Score,
		Vector: vuln.Metadata.CVSS.CVSSv3Vector,
	}
}

type DetailReq struct {
	Name string `json:"name" query:"name" form:"name" uri:"name"`
}

func (d *DetailReq) SqlBuild(db *gorm.DB) *gorm.DB { // nolint
	return db.Where("name = ?", d.Name)
}

type DetailResp = Detail
