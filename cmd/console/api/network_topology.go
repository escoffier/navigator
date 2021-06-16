package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/networktopo"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) networkTopo() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/upstream/cluster/{cluster}/namespace/{namespace}/kind/{kind}/resource/{resource}", api.listUpstreamInfo())
		r.Get("/downstream/cluster/{cluster}/namespace/{namespace}/kind/{kind}/resource/{resource}", api.listDownstreamInfo())
	}
}

// @Summary Find upstream services
// @Description list upstream services for specified service
// @Produce json
// @Router /upstream/cluster/{cluster}/namespace/{namespace}/kind/{kind}/resource/{resource} [get]
// @Param cluster url string true "k8s cluster"
// @Param  namespace url string true "namespace"
// @Param kind url string true "resource kind"
// @Param resource query string true "resource name"
func (api *api) listUpstreamInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		cluster := chi.URLParam(r, "cluster")
		namespace := chi.URLParam(r, "namespace")
		kind := chi.URLParam(r, "kind")
		resource := chi.URLParam(r, "resource")
		if len(cluster) == 0 || len(namespace) == 0 || len(kind) == 0 || len(resource) == 0 {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, errors.New("missing cluster or namespace or kind or resource in url")))
			return
		}

		networkTopoService, _ := networktopo.Get(ctx)
		items, total, err := networkTopoService.ListUpstreamInfo(ctx, cluster, namespace, kind, resource, 24)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(items), response.WithTotalItems(total))
	}
}

// @Summary Find downstream services
// @Description list downstream services for specified service
// @Produce json
// @Router /downstream/cluster/{cluster}/namespace/{namespace}/kind/{kind}/resource/{resource} [get]
// @Param cluster url string true "k8s cluster"
// @Param  namespace url string true "namespace"
// @Param kind url string true "resource kind"
// @Param resource query string true "resource name"
func (api *api) listDownstreamInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		cluster := chi.URLParam(r, "cluster")
		namespace := chi.URLParam(r, "namespace")
		kind := chi.URLParam(r, "kind")
		resource := chi.URLParam(r, "resource")
		if len(cluster) == 0 || len(namespace) == 0 || len(kind) == 0 || len(resource) == 0 {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, errors.New("missing cluster or namespace or kind or resource in url")))
			return
		}

		networkTopoService, _ := networktopo.Get(ctx)
		items, total, err := networkTopoService.ListDownstreamInfo(ctx, cluster, namespace, kind, resource, 24)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(items), response.WithTotalItems(total))
	}
}
