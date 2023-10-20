package metaGlobal

import (
	"sort"
	"sync"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

var (
	riskImageTop5 *RiskImageTop5
)

func GetRiskImageTop5() *RiskImageTop5 {
	if riskImageTop5 != nil {
		return riskImageTop5
	}

	ri := &RiskImageTop5{
		WG:               sync.Mutex{},
		TopN:             consts.RiskImageTOPN,
		Top5RiskImage:    make([]*imagesecModel.ImageBaseResponse, 0),
		Top5RiskImageMap: make(map[string]bool),
	}
	riskImageTop5 = ri
	return riskImageTop5
}

type RiskImageTop5 struct {
	WG               sync.Mutex
	TopN             int
	Top5RiskImage    []*imagesecModel.ImageBaseResponse
	Top5RiskImageMap map[string]bool
}

type ImageBaseResponses []*imagesecModel.ImageBaseResponse

func (vi ImageBaseResponses) Len() int {
	return len(vi)
}

func (vi ImageBaseResponses) Less(i, j int) bool {
	return vi[i].RiskScore < vi[j].RiskScore
}

func (vi ImageBaseResponses) Swap(i, j int) {
	vi[i], vi[j] = vi[j], vi[i]
}

func (vi *RiskImageTop5) Get() []*imagesecModel.ImageBaseResponse {
	vi.WG.Lock()
	defer vi.WG.Unlock()

	ans := make([]*imagesecModel.ImageBaseResponse, 0)
	ans = append(ans, vi.Top5RiskImage...)
	return ans
}

func (vi *RiskImageTop5) Add(ims ...*imagesecModel.ImageBaseResponse) {
	vi.WG.Lock()
	defer vi.WG.Unlock()

	for i := range ims {
		im := ims[i]
		// 只统计在线镜像
		if !im.Online {
			return
		}
		if im.RiskScore == 100 {
			return
		}
		if im.Digest == "" {
			return
		}
		if im.VulnStatic.Critical == 0 && im.VulnStatic.High == 0 {
			return
		}

		if vi.Top5RiskImageMap[im.Digest] {
			return
		}

		vi.Top5RiskImageMap[im.Digest] = true

		vi.Top5RiskImage = append(vi.Top5RiskImage, im)
	}
	sort.Sort(ImageBaseResponses(vi.Top5RiskImage))

	if len(vi.Top5RiskImage) > vi.TopN {
		for i := vi.TopN; i < len(vi.Top5RiskImage); i++ {
			delete(vi.Top5RiskImageMap, vi.Top5RiskImage[i].Digest)
		}
		ans := make([]*imagesecModel.ImageBaseResponse, 0)
		ans = append(ans, vi.Top5RiskImage[:vi.TopN]...)
		vi.Top5RiskImage = ans
	}
}

func (vi *RiskImageTop5) Exit() bool {
	vi.WG.Lock()
	defer vi.WG.Unlock()

	return len(vi.Top5RiskImage) > 0
}
