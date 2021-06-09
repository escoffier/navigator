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
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) riskExplorer() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/wholeGraphOverall", api.wholeGraphOverrall())
		r.Get("/serviceDetails/{nodeType}/{namespace}/{serviceName}", api.serviceDetails())
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
		if err != nil {
			cluster = "default"
		}
		reSvc, ok := riskexplorer.GetRiskExplorerService()
		if !ok {
			RespAndLog(w, ctx, NewFieldError(http.StatusServiceUnavailable, errors.New("RiskExplorer Service not found")))
			return
		}

		summary, err := reSvc.WholeSummary(ctx, cluster, api.scannerURL)
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
// @Router /serviceDetails/{nodeType}/{namespace}/{serviceName} [get]
// @Param nodeType url string true "service/ownerReferene"
// @Param  namespace url string true "k8s cluster"
// @Param serviceName url string true "serviceName"
// @Param cluster query string true "k8s cluster"
func (api *api) serviceDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		ntype := chi.URLParam(r, "nodeType")
		namespace := chi.URLParam(r, "namespace")
		if len(namespace) == 0 {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, errors.New("missing namespace in url")))
			return
		}
		sname := chi.URLParam(r, "serviceName")
		if len(sname) == 0 {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, errors.New("missing serviceName in url")))
			return
		}

		cluster, err := param.QueryString(r, "cluster")
		if err != nil {
			cluster = "default"
		}
		reSvc, ok := riskexplorer.GetRiskExplorerService()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusServiceUnavailable, errors.New("RiskExplorer Service not found")))
			return
		}

		detail, err := reSvc.ServiceDetail(ctx, cluster, ntype, namespace, sname, api.scannerURL)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItem(*detail))
	}
}
