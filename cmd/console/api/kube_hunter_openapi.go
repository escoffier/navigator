package api

import (
	"net/http"

	"github.com/go-chi/chi"
)

func (a *api) hunterOpenAPI() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/scan", a.runKubeHunter())
		r.Get("/", a.getKubeHunterResult())
		r.Get("/status", a.getKubeHunterStatus())
	}
}

func (a *api) runKubeHunterOpenAPI() http.HandlerFunc {
	return a.runKubeHunter()
}

func (a *api) getKubeHunterResultOpenAPI() http.HandlerFunc {
	return a.getKubeHunterResult()
}

func (a *api) getKubeHunterStatusOpenAPI() http.HandlerFunc {
	return a.getKubeHunterStatus()
}
