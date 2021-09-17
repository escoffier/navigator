package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	assetsPkg "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) assets() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/clusters", api.getClusters())
		r.Put("/cluster", api.addNewCluster())
		r.Post("/cluster", api.updateClusterInfo())
		r.Delete("/cluster/{clusterKey}", api.deleteCluster())
		r.Get("/namespaces", api.getNamespaces())
		r.Get("/namespace/{namespace}/kind/{kind}/resources", api.getResourcesInNamespace())
		r.Get("/namespace/{namespace}/kind/{kind}/resource/{resource_name}/containers", api.getResourceContainers())
		r.Get("/resources/byImage", api.getResourcesByImage())
		r.Get("/resources/byImageVulns", api.getResourcesByImageVuln())
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

type resourceContainer struct {
	Image         string `json:"image"`
	Cluster       string `json:"cluster"`
	Namespace     string `json:"namespace"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	ContainerName string `json:"container_name"`
}

func (api *api) getResourcesByImage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}

		lib, err := param.QueryString(r, "library")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get library query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no library given in params")))
			return
		}
		repo, err := param.QueryString(r, "repo")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get repo query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no repo given in params")))
			return
		}
		tag, err := param.QueryString(r, "tag")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get tag query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no tag given in params")))
			return
		}

		imageID := fmt.Sprintf("%s/%s:%s", lib, repo, tag)
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		containers, totalCnt, err := resSvc.GetResourceContainers(ctx, dal.ResourceContainersQuery().WithCustom("image", imageID), offset, limit)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GetResourceContainers error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resources error")))
			return
		}
		ret := make([]resourceContainer, len(containers))
		for i, cont := range containers {
			ret[i].Cluster = cont.ClusterKey
			ret[i].Namespace = cont.Namespace
			ret[i].Name = cont.ResourceName
			ret[i].Kind = cont.ResourceKind
			ret[i].ContainerName = cont.Name
			ret[i].Image = cont.Image
		}

		response.Ok(w, response.WithItems(ret), response.WithTotalItems(totalCnt))
	}
}

func (api *api) getResourcesByImageVuln() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}

		vulnID, err := param.QueryString(r, "vuln_id")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get vuln_id query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no vuln_id given in params")))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		containers, totalCnt, err := resSvc.GetResourceContainersWithGivenVuln(ctx, vulnID, offset, limit)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GetResourceContainers error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resources error")))
			return
		}
		ret := make([]resourceContainer, len(containers))
		for i, cont := range containers {
			ret[i].Cluster = cont.ClusterKey
			ret[i].Namespace = cont.Namespace
			ret[i].Name = cont.ResourceName
			ret[i].Kind = cont.ResourceKind
			ret[i].ContainerName = cont.Name
			ret[i].Image = cont.Image
		}

		response.Ok(w, response.WithItems(ret), response.WithTotalItems(int64(totalCnt)))
	}
}

// @Summary
// @Description get the list of clusters https://tensorsecurity.feishu.cn/wiki/wikcnUMvm0NSivY9gDZJIlECSZg#
// @Produce json
// @Method GET
// @Router /api/v2/platform/assets/cluters
func (api *api) getClusters() http.HandlerFunc {
	type cluster struct {
		Key         string `json:"key"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Creator     string `json:"creator"`
		CreatedAt   int64  `json:"createdAt"`
		Updater     string `json:"updater"`
		UpdatedAt   int64  `json:"updatedAt"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		clusters, totalCnt, err := resSvc.GetClusters(ctx, offset, limit)
		if err != nil {
			logging.GetLogger().Err(err).Msg("get cluster error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get cluster error")))
			return
		}
		ret := make([]cluster, len(clusters))
		for i, cluster := range clusters {
			ret[i].Key = cluster.Key
			ret[i].Description = cluster.Description
			ret[i].Name = cluster.Name
			ret[i].Creator = cluster.Creator
			ret[i].CreatedAt = cluster.CreatedAt.Unix()
			ret[i].UpdatedAt = cluster.UpdatedAt.Unix()
			ret[i].Updater = cluster.Updater
		}

		response.Ok(w, response.WithItems(ret), response.WithTotalItems(totalCnt))
	}
}

// @Summary
// @Description add a cluster https://tensorsecurity.feishu.cn/wiki/wikcnUMvm0NSivY9gDZJIlECSZg#
// @Produce json
// @Method PUT
// @Router /api/v2/platform/assets/cluster
func (api *api) addNewCluster() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		var cluster model.TensorCluster
		err := util.DecodeJSONBody(w, r, &cluster)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		clusterManager, ok := k8s.GetClusterManager()
		if !ok {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("cluster manager not exist")))
			return
		}
		err = clusterManager.WatchCluster(ctx, &cluster)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, err))
			return
		}

		err = resSvc.AddCluster(ctx, &cluster)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("add cluster error. clusterKey: %s", cluster.Key)
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, fmt.Errorf("add cluster error. clusterKey: %s", cluster.Key)))
			return
		}
		response.Ok(w)
	}
}

// @Summary
// @Description update the info of a cluster https://tensorsecurity.feishu.cn/wiki/wikcnUMvm0NSivY9gDZJIlECSZg#
// @Produce json
// @Method POST
// @Router /api/v2/platform/assets/cluster
func (api *api) updateClusterInfo() http.HandlerFunc {
	type req struct {
		ClusterKey  string `json:"cluster_key"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		var request req
		err := util.DecodeJSONBody(w, r, &request)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		err = resSvc.UpdateCluster(ctx, request.ClusterKey, request.Name, request.Description)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("update cluster error. data: %v", request)
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("update cluster error")))
			return
		}
		response.Ok(w)
	}
}

// @Summary
// @Description delete the info of a cluster https://tensorsecurity.feishu.cn/wiki/wikcnUMvm0NSivY9gDZJIlECSZg#
// @Produce json
// @Method DELETE
// @Router /api/v2/platform/assets/cluster
func (api *api) deleteCluster() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		clusterKey := chi.URLParam(r, "clusterKey")
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		clusterManager, ok := k8s.GetClusterManager()
		if !ok {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("cluster manager not exist")))
			return
		}
		err := clusterManager.UnWatchCluster(ctx, clusterKey)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("stop watcher err")))
			return
		}

		err = resSvc.DeleteCluster(ctx, clusterKey)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, fmt.Errorf("delete cluster error: %v", err)))
			return
		}
		response.Ok(w)
	}
}

// @Summary
// @Description get the list of namespaces in given cluster
// @Produce json
// @Method GET
// @Router /api/v2/platform/assets/namespaces
func (api *api) getNamespaces() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
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
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
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
		rquery := dal.ResourcesQuery()
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
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
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
		rquery := dal.ResourceContainersQuery()
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
