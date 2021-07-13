package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	assetsPkg "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) assets() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/clusters", api.getClusters())
		r.Get("/namespaces", api.getNamespaces())
		r.Get("/namespace/{namespace}/kind/{kind}/resources", api.getResourcesInNamespace())
		// r.Get("/namespace/{namespace}/kind/{kind}/resource/{resource_name}", api.getResource())
		r.Get("/namespace/{namespace}/kind/{kind}/resource/{resource_name}/containers", api.getResourceContainers())
	}
}

func getLimitAndOffset(r *http.Request) (int, int, error) {
	limitStr, err := param.QueryString(r, "limit")
	if err != nil {
		return 0, 0, err
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		return 0, 0, err
	}
	offsetStr, err := param.QueryString(r, "offset")
	if err != nil {
		return 0, 0, err
	}
	offset, err := strconv.Atoi(offsetStr)
	if err != nil {
		return 0, 0, err
	}
	return limit, offset, nil
}

// @Summary
// @Description get the list of clusters
// @Produce json
// @Method GET
// @Router /api/v2/platform/assets/cluters
func (api *api) getClusters() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		clusters, err := resSvc.GetClusters(ctx)
		if err != nil {
			logging.GetLogger().Err(err).Msg("get cluster error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get cluster error")))
			return
		}
		response.Ok(w, response.WithItems(clusters), response.WithTotalItems(int64(len(clusters))))
	}
}

// @Summary
// @Description get the list of namespaces in given cluster
// @Produce json
// @Method GET
// @Router /api/v2/platform/assets/namespaces
func (api *api) getNamespaces() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.GetLogger().Err(err).Msg("get cluster_key param error.")
			clusterKey = "default"
		}
		query, err := param.QueryString(r, "query")
		if err != nil {
			logging.GetLogger().Err(err).Msg("get query param error.")
			query = ""
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		namespaces, totalCnt, err := resSvc.GetNamespaces(ctx, clusterKey, query, offset, limit)
		if err != nil {
			logging.GetLogger().Err(err).Msg("getNamespaces error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(namespaces),
			response.WithTotalItems(totalCnt),
			response.WithStartIndex(int64(offset+len(namespaces))),
		)
	}
}

func (api *api) getResourcesInNamespace() http.HandlerFunc {
	type resource struct {
		Cluster   string `json:"cluster"`
		Namespace string `json:"namespace"`
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		UID       string `json:"uid"`
	}
	modelToResource := func(rm *model.TensorResource) *resource {
		r := new(resource)
		r.Cluster = rm.ClusterKey
		r.Namespace = rm.Namespace
		r.Kind = rm.Kind
		r.Name = rm.Name
		r.UID = rm.UID
		return r
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.GetLogger().Err(err).Msg("get cluster_key param error.")
			clusterKey = ""
		}
		query, err := param.QueryString(r, "query")
		if err != nil {
			logging.GetLogger().Err(err).Msg("get query param error.")
			query = ""
		}

		namespace := chi.URLParam(r, "namespace")
		kind := chi.URLParam(r, "kind")

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		rquery := assetsPkg.ResourcesQuery()
		if clusterKey != "" {
			rquery = rquery.WithCluster(clusterKey)
		}
		if namespace != "" {
			rquery = rquery.WithNamespace(namespace)
		}
		if kind != "" {
			rquery = rquery.WithResourceKind(assetsPkg.ResourceKind(kind))
		}
		if query != "" {
			rquery = rquery.WithColumnQuery("name", query)
		}
		resources, totalCnt, err := resSvc.GetResources(ctx, rquery, offset, limit)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("query: %+v. offset: %d, limit: %d. get resources error", rquery, offset, limit)
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resources error")))
			return
		}

		items := make([]*resource, len(resources))
		for i, resource := range resources {
			items[i] = modelToResource(resource)
		}

		response.Ok(w, response.WithItems(items), response.WithTotalItems(totalCnt), response.WithStartIndex(int64(offset+len(items))))
	}
}

func (api *api) getResourceContainers() http.HandlerFunc {
	type container struct {
		Cluster      string `json:"cluster"`
		Namespace    string `json:"namespace"`
		ResourceKind string `json:"resource_kind"`
		ResourceName string `json:"resource_name"`
		Name         string `json:"name"`
		Image        string `json:"image"`
	}
	fromModelToContainer := func(cm *model.TensorContainer) *container {
		c := new(container)
		c.Cluster = cm.ClusterKey
		c.Namespace = cm.Namespace
		c.ResourceKind = cm.ResourceKind
		c.ResourceName = cm.ResourceName
		c.Name = cm.Name
		c.Image = cm.Image
		return c
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.GetLogger().Err(err).Msg("get cluster_key param error.")
			clusterKey = ""
		}
		query, err := param.QueryString(r, "query")
		if err != nil {
			logging.GetLogger().Err(err).Msg("get query param error.")
			query = ""
		}

		namespace := chi.URLParam(r, "namespace")
		kind := chi.URLParam(r, "kind")
		resourceName := chi.URLParam(r, "resource_name")

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		rquery := assetsPkg.ResourceContainersQuery()
		if clusterKey != "" {
			rquery = rquery.WithCluster(clusterKey)
		}
		if namespace != "" {
			rquery = rquery.WithNamespace(namespace)
		}
		if kind != "" {
			rquery = rquery.WithResourceKind(assetsPkg.ResourceKind(kind))
		}
		if resourceName != "" {
			rquery = rquery.WithResourceName(resourceName)
		}
		if query != "" {
			rquery = rquery.WithColumnQuery("name", query)
		}
		containers, totalCnt, err := resSvc.GetResourceContainers(ctx, rquery, offset, limit)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("query: %+v. offset: %d, limit: %d. get containers error", rquery, offset, limit)
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get containers error")))
			return
		}

		items := make([]*container, len(containers))
		for i, container := range containers {
			items[i] = fromModelToContainer(container)
		}

		response.Ok(w, response.WithItems(items), response.WithTotalItems(totalCnt), response.WithStartIndex(int64(offset+len(items))))
	}
}
