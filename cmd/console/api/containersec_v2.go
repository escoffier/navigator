package api

import (
	"github.com/go-chi/chi"
)

func (api *api) containerSec() func(chi.Router) {
	return func(r chi.Router) {
		r.Route("/ATTCK", api.ATTCK())
		r.Route("/scap", api.scap())
		r.Route("/scanner", api.scanner())
		r.Route("/export", api.export())
		r.Route("/immune", api.immune())
		r.Route("/watson", api.defense())
	}
}

func (api *api) OpenApiContainerSec() func(chi.Router) {
	return func(r chi.Router) {
		r.Route("/scap", api.scapOpenApi())
		r.Route("/scanner", api.scannerOpenApi())
	}
}
