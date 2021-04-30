package api

import (
	"github.com/go-chi/chi"
)

func (api *api) platform() func(chi.Router) {
	return func(r chi.Router) {
		r.Route("/riskExplorer", api.riskExplorer())
		r.Route("/microservice", api.Microservice())
		r.Route("/audit", api.audit())
		r.Route("/cleanup", api.cleanup())
		r.Route("/config", api.config())
		r.Route("/eventsCenter", api.eventsCenter())
	}
}
