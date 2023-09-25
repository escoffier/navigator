package service

import (
	"sync"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type VulnOverView struct {
	Overview         *imagesecModel.VulnOverview
	Top5RiskImage    []imagesecModel.ImageBaseResponse
	Top5RiskImageMap map[string]bool
	WG               sync.Mutex
}

func NewVulnOverView() *VulnOverView {
	return &VulnOverView{
		Overview: &imagesecModel.VulnOverview{},
		WG:       sync.Mutex{},
	}
}

func (vi *VulnOverView) Get() imagesecModel.VulnOverview {
	vi.WG.Lock()
	defer vi.WG.Unlock()

	vv := imagesecModel.VulnOverview{
		VulnTotal: vi.Overview.VulnTotal,
		Severity: imagesecModel.SeverityCount{
			Critical: vi.Overview.Severity.Critical,
			High:     vi.Overview.Severity.High,
			Medium:   vi.Overview.Severity.Medium,
			Low:      vi.Overview.Severity.Low,
			Unknown:  vi.Overview.Severity.Unknown,
		},
	}
	return vv
}

func (vi *VulnOverView) Set(o *imagesecModel.VulnOverview) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	vi.Overview = o
}

func (vi *VulnOverView) Exit() bool {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	return vi.Overview != nil
}
