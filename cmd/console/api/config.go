package api

import (
	"github.com/go-chi/chi"
)

func (api *api) config() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/agent/{agentID}", api.getAgent())
		r.Get("/agents", api.listAgents())
		r.Post("/agents", api.createAgent())
		r.Get("/cluster", api.getCluster())
		r.Post("/cluster", api.updateCluster())
		r.Delete("/cluster", api.delCluster())
		r.Get("/cluster/{clusterID}", api.getCluster())
		r.Get("/clusters", api.listClusters())
		r.Post("/cluster", api.addCluster())
		r.Delete("/cluster/{clusterID}", api.delCluster())
		r.Put("/cluster/{clusterID}", api.updateCluster())
	}
}
