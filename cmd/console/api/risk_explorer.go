package api

import (
	"context"
	"errors"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
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

		query := dal.ResourceContainersQuery()
		cluster, _ := param.QueryString(r, "cluster")
		if cluster != "" {
			query.WithCluster(cluster)
		}
		// resource-detail page has these param
		namespace, _ := param.QueryString(r, "namespace")
		if namespace != "" {
			query.WithNamespace(namespace)
		}
		resourceKind, _ := param.QueryString(r, "resource_kind")
		if resourceKind != "" {
			query.WithResourceKind(assets.ResourceKind(resourceKind))
		}
		resourceName, _ := param.QueryString(r, "resource_name")
		if resourceName != "" {
			query.WithResourceName(resourceName)
		}

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
		// resource-detail page  need  "managers"
		if resourceName != "" && len(summary) == 1 && len(summary[0].ResourcesList) == 1 {
			summary[0].ResourcesList[0].Managers = reSvc.GetResourceName(ctx, cluster, namespace, resourceKind, resourceName)
		}
		response.Ok(w, response.WithItems(summary))
	}
}
