package api

import (
	"github.com/go-chi/chi"
)

func (api *api) platform() func(chi.Router) {
	return func(r chi.Router) {
		r.Route("/riskExplorer", api.riskExplorer())
		r.Route("/version", api.version())
		r.Route("/config", api.config())
		r.Route("/eventsCenter", api.eventsCenter())
		r.Route("/processingCenter", api.processingCenter())
		r.Route("/data", api.data())
		r.Route("/networkTopo", api.networkTopo())
		r.Route("/apiscan",api.apiScan())
		r.Route("/assets", api.assets())
		r.Route("/audit", api.audit())
		r.Route("/hunter", api.kubeHunter())
		r.Route("/report", api.platformReport())
	}
}
