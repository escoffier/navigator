package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/riskexplorer"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) riskExplorer() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/wholeGraphOverall", api.wholeGraphOverrall())
	}
}

// @Summary List current assets
// @Description list current assets in the cluster
// @Produce json
// @Router /api/v1/riskExplorer/wholeGraphOverrall [get]
// @Param cluster query string true "k8s cluster"
func (api *api) wholeGraphOverrall() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*15)
		defer cancel()

		cluster, err := param.QueryString(r, "cluster")
		if err != nil || len(cluster) == 0 {
			cluster = "default"
		}
		query := dal.ResourceContainersQuery().WithCluster(cluster)
		appType, err := param.QueryString(r, "apptype")
		if err == nil && len(appType) > 0 {
			if appType == "*" {
				query = query.WithAppTypeNotEmpty()
			} else {
				query = query.WithAppType(appType)
			}
		}
		reSvc, ok := riskexplorer.Get(ctx)
		if !ok {
			RespAndLog(w, ctx, NewFieldError(http.StatusServiceUnavailable, errors.New("RiskExplorer Service not found")))
			return
		}

		summary, err := reSvc.WholeSummary(ctx, query)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w, response.WithItems(summary))
	}
}
