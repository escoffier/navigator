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
		r.Get("/cluster/{clusterKey}/namespace/{namespace}/kind/{resourceKind}/name/{resourceName}/detail", api.serviceDetails())
	}
}

// @Summary List current assets
// @Description list current assets in the cluster
// @Produce json
// @Router /api/v1/riskExplorer/wholeGraphOverrall [get]
// @Param cluster query string true "k8s cluster"
func (api *api) wholeGraphOverrall() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		cluster, err := param.QueryString(r, "cluster")
		if err != nil || len(cluster) == 0 {
			cluster = "default"
		}
		reSvc, ok := riskexplorer.Get(ctx)
		if !ok {
			RespAndLog(w, ctx, NewFieldError(http.StatusServiceUnavailable, errors.New("RiskExplorer Service not found")))
			return
		}

		summary, err := reSvc.WholeSummary(ctx, dal.ResourceContainersQuery().WithCluster(cluster))
		if err != nil {
			RespAndLog(w, ctx, NewFieldError(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w, response.WithItems(summary))
	}
}

// @Summary List current assets
// @Description list current assets in the cluster
// @Produce json
// @Router /resourceDetails/namespace/{namespace}/kind/{resourceKind}/name/{resourceName} [get]
// @Param nodeType url string true "service/ownerReferene"
// @Param  namespace url string true "k8s cluster"
// @Param serviceName url string true "serviceName"
// @Param cluster query string true "k8s cluster"
func (api *api) serviceDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		queryOpt := dal.ResourcesQuery()

		clusterKey := chi.URLParam(r, "clusterKey")
		if clusterKey != "" {
			queryOpt.WithCluster(clusterKey)
		}

		namespace := chi.URLParam(r, "namespace")
		if namespace != "" {
			queryOpt.WithNamespace(namespace)
		}

		resKind := chi.URLParam(r, "resourceKind")
		if resKind != "" {
			queryOpt.WithResourceKind(assets.ResourceKind(resKind))
		}

		resName := chi.URLParam(r, "resourceName")
		if resName != "" {
			queryOpt.WithResourceName(resName)
		}

		reSvc, ok := riskexplorer.Get(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusServiceUnavailable, errors.New("RiskExplorer Service not found")))
			return
		}

		detail, err := reSvc.ResourceDetail(ctx, clusterKey, namespace, resKind, resName)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItem(*detail))
	}
}
