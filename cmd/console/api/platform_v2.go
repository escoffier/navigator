package api

import (
	"github.com/go-chi/chi"
)

func (api *api) platform() func(chi.Router) {
	return func(r chi.Router) {
		r.Route("/riskExplorer", api.riskExplorer())
		r.Route("/version", api.version())
		// r.Route("/eventsCenter", api.eventsCenter())
		r.Route("/sherlock", api.sherlock())
		r.Route("/processingCenter", api.processingCenter())
		r.Route("/data", api.data())
		r.Route("/networkTopo", api.networkTopo())
		r.Route("/apiscan", api.apiScan())
		r.Route("/assets", api.assets())
		r.Route("/audit", api.audit())
		r.Route("/drift", api.drift())
		r.Route("/hunter", api.kubeHunter())
		r.Route("/palace", api.palace())
		r.Route("/report", api.platformReport())
		r.Route("/naviAudit", api.naviAudit())
	}
}

func (api *api) platformOpenapi() func(chi.Router) {
	return func(r chi.Router) {
		r.Route("/assets", api.assetsForOpenapi())
	}
}
