package api

import (
	"context"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

// SetupRoutes is to set up the chi router
func SetupRoutes(
	ctx context.Context,
	r *chi.Mux,
) {
	log.Debug().Msg("setting up routes...")

	api := newAPI(ctx)
	r.Get("/ping", response.Pong)

	// backward compatibility
	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/policy", api.policy())
		r.Route("/resource", api.resource())
		r.Route("/config", api.config())
	})

	r.Route("/api/v2", func(r chi.Router) {
		r.Route("/containerSec", func(r chi.Router) {
			r.Route("/secprofiles", func(r chi.Router) {
				r.Route("/policy", api.policy())
				r.Route("/resource", api.resource())
				r.Route("/config", api.config())
			})
		})
	})

}
