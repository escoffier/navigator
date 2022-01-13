package api

import "github.com/go-chi/chi"

func (api *api) containerSecOpen() func(chi.Router) {
	return func(r chi.Router) {
		r.Route("/scap", api.scapOpen())
		r.Route("/scanner", api.scannerOpen())
	}
}
func (api *api) containerSec() func(chi.Router) {
	return func(r chi.Router) {
		r.Route("/scap", api.scap())
		r.Route("/scanner", api.scanner())
		r.Route("/immune", api.immune())
		// proxy to security profiles management
		// TODO remove
		r.Handle("/secprofiles/*", api.secProfiles())
	}
}

func (api *api) OpenApiContainerSec() func(chi.Router) {
	return func(r chi.Router) {
		r.Route("/scap", api.scapOpenApi())
		r.Route("/scanner", api.scannerOpenApi())
	}
}
