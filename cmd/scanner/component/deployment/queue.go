package deployment

import (
	"sort"
	"sync"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type DeployTrend struct {
	WG    sync.Mutex
	Trend imagesecModel.DeployTrend
}

func NewDeployTrend() *DeployTrend {
	return &DeployTrend{
		WG:    sync.Mutex{},
		Trend: imagesecModel.DeployTrend{},
	}
}

func (vi *DeployTrend) Get() imagesecModel.DeployTrend {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	ans := imagesecModel.DeployTrend{
		Day7:   vi.Trend.Day7,
		Day30:  vi.Trend.Day30,
		Hour24: vi.Trend.Hour24,
	}
	return ans
}

func (vi *DeployTrend) SetDay7(d int64) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	vi.Trend.Day7 = d
}

func (vi *DeployTrend) SetDay30(d int64) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	vi.Trend.Day30 = d
}

func (vi *DeployTrend) SetHour24(d int64) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	vi.Trend.Hour24 = d
}

type ReasonOverview struct {
	WG     sync.Mutex
	TopN   int
	Reason []imagesecModel.ReasonOverview
}

func NewReasonOverview(topN int) *ReasonOverview {
	return &ReasonOverview{
		WG:     sync.Mutex{},
		Reason: make([]imagesecModel.ReasonOverview, 0),
		TopN:   topN,
	}
}

func (vi *ReasonOverview) Get() []imagesecModel.ReasonOverview {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	ans := make([]imagesecModel.ReasonOverview, 0)
	ans = append(ans, vi.Reason...)
	ans = ans[:util.MinInt(vi.TopN, len(ans))]
	return ans
}

func (vi *ReasonOverview) Set(group []imagesecModel.DeployFlagGroup) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	exit := make(map[string]int64)

	for i := range group {
		if !util.ExistBit1(group[i].Flag, imagesecModel.FlagImageDeployBlock) {
			continue
		}
		for fl, reason := range imagesecModel.GetSecurityIssueLabelKey() {
			if util.ExistBit1(group[i].Flag, fl) {
				exit[reason] += group[i].Count
			}
		}
	}

	ans := make([]imagesecModel.ReasonOverview, 0)
	for reason, cnt := range exit {
		ans = append(ans, imagesecModel.ReasonOverview{
			Reason: reason,
			Count:  cnt,
		})
	}
	sort.Slice(ans, func(i, j int) bool {
		return ans[i].Count > ans[j].Count
	})

	ans = ans[:util.MinInt(vi.TopN, len(ans))]
	vi.Reason = ans
}
