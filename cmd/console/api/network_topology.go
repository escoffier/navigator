package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/networktopo"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) networkTopo() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/upstream/cluster/{cluster}/namespace/{namespace}/kind/{kind}/resource/{resource}", api.listUpstreamInfo())
		r.Get("/downstream/cluster/{cluster}/namespace/{namespace}/kind/{kind}/resource/{resource}", api.listDownstreamInfo())
		r.Put("/topology", api.addNetTopology())
		r.Put("/topologies", api.addNetTopologiges())
		r.Get("/topology", api.getNetTopology())
	}
}

type request struct {
	UUID   uint32 `json:"uuid"`
	Time   int64  `json:"time"`
	Status int    `json:"status"`
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

// @Summary
// @Description add multiple net topologies https://tensorsecurity.feishu.cn/wiki/wikcnUMvm0NSivY9gDZJIlECSZg#
// @Produce json
// @Method PUT
// @Router /internal/platform/networkTopo/topologies
func (api *api) addNetTopologiges() http.HandlerFunc {
	type resp struct{}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		var topologies []*model.TensorNetworkFlow
		err := util.DecodeJSONBody(w, r, &topologies)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		networkTopoService, _ := networktopo.Get(ctx)

		err = networkTopoService.AddNetTopologies(ctx, topologies)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to add net topology: %w", err)))
			return
		}
		response.Ok(w, response.WithItem(resp{}))
	}
}

// @Summary
// @Description add a net topology https://tensorsecurity.feishu.cn/wiki/wikcnUMvm0NSivY9gDZJIlECSZg#
// @Produce json
// @Method PUT
// @Router /internal/platform/networkTopo/topology
func (api *api) addNetTopology() http.HandlerFunc {
	type resp struct {
		ID uint32 `json:"ID"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		topology := model.TensorNetworkFlow{}
		err := util.DecodeJSONBody(w, r, &topology)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		networkTopoService, _ := networktopo.Get(ctx)

		err = networkTopoService.AddNetTopology(ctx, &topology)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to add net topology: %w", err)))
			return
		}
		response.Ok(w, response.WithItem(resp{
			ID: topology.UUID,
		}))
	}
}

func (api *api) getNetTopology() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		networkTopoService, _ := networktopo.Get(ctx)
		i, err := param.QueryInt64(r, "time")
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("invalid time param: %v", err))
			return
		}

		t := time.Unix(i, 0)
		nts, count, err := networkTopoService.ListNetTopologies(ctx, t)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("couldn't list net topology: %v", err))
			return
		}
		response.Ok(w,
			response.WithItems(nts),
			response.WithTotalItems(count))
	}
}
