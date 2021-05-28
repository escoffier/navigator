package api

import "github.com/go-chi/chi"

func (api *api) containerSec() func(chi.Router) {
	return func(r chi.Router) {
		r.Route("/scap", api.scap())
		r.Route("/scanner", api.scanner())
		r.Route("/onlineVulnerabilities", api.onlineVulnerabilities())
	}
}
