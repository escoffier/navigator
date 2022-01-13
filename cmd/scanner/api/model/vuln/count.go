package vuln

import (
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

// StatisticResp 漏洞计数统计响应
type StatisticResp struct {
	Severity  *CountBySeverity `json:"severity" query:"severity" form:"severity"`
	Top5      []*CountByImage  `json:"top5" query:"top5" form:"top5"`
	VulnTotal int64            `json:"vulnTotal" query:"vulnTotal" form:"vulnTotal"`
}

// CountBySeverity 根据漏洞严重程度统计漏洞
type CountBySeverity struct {
	// 高危漏洞数
	Critical int64 `json:"critical" query:"critical" form:"critical"`
	// 高风险漏洞数
	High int64 `json:"high" query:"high" form:"high"`
	// 低风险漏洞数
	Low int64 `json:"low" query:"low" form:"low"`
	// 中风险漏洞数
	Medium int64 `json:"medium" query:"medium" form:"medium"`
	// 可忽略漏洞数
	Negligibel int64 `json:"negligibel" query:"negligibel" form:"negligibel"`
	// 未知风险漏洞
	Unknown int64 `json:"unknown" query:"unknown" form:"unknown"`
}

// CountByImage 每个镜像的漏洞计数
type CountByImage struct {
	// 镜像名
	Image string `json:"image" query:"image" form:"image"`
	// 漏洞评分
	Score float64 `json:"score" query:"score" form:"score"`
	// 该镜像的漏洞统计信息
	Severity *CountBySeverity `json:"severity" query:"severity" form:"severity"`
}

func (s *StatisticResp) BuildCountBySeverity(d *model.SeverityCount) *StatisticResp {
	if s == nil {
		*s = StatisticResp{}
	}

	c := &CountBySeverity{
		Critical:   int64(d.Critical),
		High:       int64(d.High),
		Low:        int64(d.Low),
		Medium:     int64(d.Medium),
		Negligibel: int64(d.Negligible),
		Unknown:    int64(d.Unknown),
	}
	s.Severity = c

	s.VulnTotal = int64(d.Critical + d.High +
		d.Medium + d.Low + d.Negligible + d.Unknown)

	return s
}

func (s *StatisticResp) BuildCountByTops(d []*model.ImageListUnionScanImage) *StatisticResp {
	if s == nil {
		*s = StatisticResp{}
	}

	s.Top5 = make([]*CountByImage, 0, len(d))

	for _, v := range d {

		var c = new(CountByImage)

		if len(v.SeverityHistogramJSON) != 0 {
			c.Severity = &CountBySeverity{
				Critical:   v.SeverityHistogram.NumCritical,
				Low:        v.SeverityHistogram.NumLow,
				Medium:     v.SeverityHistogram.NumMedium,
				Negligibel: v.SeverityHistogram.NumNegligible,
				Unknown:    v.SeverityHistogram.NumUnknown,
				High:       v.SeverityHistogram.NumHigh,
			}
		}

		c.Score = v.VulnScore
		if v.FromType != model.ImageFromSafeNode {
			c.Image = fmt.Sprintf("%s:%s", v.FullRepoName, v.Tags)
		} else {
			split := strings.Split(v.FullRepoName, "/")
			if len(split) <= 6 {
				continue
			}

			name := fmt.Sprintf("%s-%s-%s", v.NodeHostname, v.NodeIp, strings.Join(split[5:], "/"))
			c.Image = fmt.Sprintf("%s:%s", name, v.Tags)
		}

		s.Top5 = append(s.Top5, c)
	}
	return s
}
