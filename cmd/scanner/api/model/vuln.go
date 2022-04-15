package apimodel

import (
	"strconv"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type Detail struct {
	// 漏洞编号
	Name string `json:"name"`
	// 严重程度
	Severity string `json:"severity"`
	// 修复版本
	FixedVersion string `json:"fixedVersion"`
	// 漏洞介绍
	Description string `json:"description"`
	// 修复建议
	FixSuggestion string `json:"fixSuggestion"`
	// 参考链接
	References []string `json:"references"`
	// 漏洞类型
	Title string `json:"title"`
	// 漏洞评分
	Score float64 `json:"score"`
	// 软件包
	PkgName string `json:"pkgName"`
	// 软件版本
	PkgVersion string `json:"pkgVersion"`
	// cvss系统评分
	Cvss *Cvss `json:"cvss"`
}

type Cvss struct {
	Score  float64 `json:"score"`
	Vector string  `json:"vector"`
}

func ModelToOpenapiDetail(vuln model.Vuln) Detail {
	d := Detail{References: make([]string, 0)} // 防止前端null

	d.Name = vuln.Name
	d.Severity = vuln.Severity
	d.Description = vuln.Description
	d.References = vuln.Link
	d.FixedVersion = vuln.FixedBy

	if vuln.Metadata != nil {
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
	}
	d.PkgName = vuln.PkgName
	d.PkgVersion = vuln.PkgVersion
	d.Cvss = &Cvss{
		Score: d.Score,
	}
	if vuln.Metadata != nil {
		d.Cvss.Vector = vuln.Metadata.CVSS.CVSSv3Vector
	}

	return d
}
