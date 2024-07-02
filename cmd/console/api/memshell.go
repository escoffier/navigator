package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/memshell"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) memshell() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/{cluster}/{namespace}/{kind}/{resource_name}/scan", api.memshellScan())
	}
}

func (api *api) memshellScan() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		clusterKey := chi.URLParam(r, "cluster")
		namespace := chi.URLParam(r, "namespace")
		kind := chi.URLParam(r, "kind")
		resourceName := chi.URLParam(r, "resource_name")
		logging.GetLogger().Info().Msgf("memshell scan resource: %s/%s/%s/%s", clusterKey, namespace, kind, resourceName)
		ms, ok := memshell.GetService()
		if !ok {
			logging.GetLogger().Error().Msg("memshell service not initialized")
		}
		err := ms.ScanResource(ctx, clusterKey, namespace, kind, resourceName)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("memshell scan resource failed")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w)

		return
	}
}
