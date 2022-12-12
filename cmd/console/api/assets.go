package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/go-containerregistry/pkg/name"
	json "github.com/json-iterator/go"
	param "github.com/oceanicdev/chi-param"
	"github.com/pkg/errors"
	"gitlab.com/security-rd/go-pkg/logging"
	v1 "k8s.io/api/core/v1"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	containers2 "gitlab.com/piccolo_su/vegeta/cmd/console/service/containers"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	assetsPkg "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
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
		r.Post("/namespace", api.updateNamespace())
		r.Get("/namespace/{namespace}/kind/{kind}/resources", api.getResourcesInNamespace())
		r.Get("/resources", api.getResources())
		r.Post("/resource/userData", api.updateResourceUserData())
		r.Get("/namespace/{namespace}/kind/{kind}/resource/{resource_name}/containers", api.getResourceContainers())
		r.Get("/imageinfos", api.getImageInfos())
		r.Get("/imageProblems", api.getImageProblems())
		r.Get("/resources/byImage", api.getResourcesByImage())
		r.Get("/resources/byImageVulns", api.getResourcesByImageVuln())
		r.Get("/pods", api.getPods())

		r.Get("/resources/count", api.countResource())
		r.Get("/containers/count", api.countContainers())
		r.Get("/pods/count", api.countPods())
		r.Get("/namespaces/count", api.countNamespaces())
		r.Get("/images/count", api.countImages())
		r.Get("/nodes/count", api.countNodes())
		r.Get("/nodes", api.getNodes())
		r.Get("/frameworks", api.getFrameworks())

		r.Get("/container/processlist", api.GetProcessList())
		r.Get("/resource/netflow/info", api.GetResourceAssociate())
		r.Get("/container/netflow/info", api.GetContainerAssociate())
		r.Get("/container/process/netflow/info", api.GetProcessAssociate())

		exportContainers := os.Getenv("EXPORT_CONTAINERS")
		if exportContainers == "true" {
			r.Get("/containers", api.getContainers())
		}

		r.Get("/rawContainers", api.getRawContainers())
		r.Get("/rawContainers/count", api.countRawContainers())
		r.Get("/rawContainer/{containerID}", api.getRawContainer())
		r.Get("/resources/types", api.getResourceTypes())
	}
}

type countResp struct {
	Count int64 `json:"count"`
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

func getLimitAndOffsetWithDefault(r *http.Request) (int, int) {
	// 取默认值，所以忽略所有的err
	defaultLimit, defaultOffset := 10, 0
	limitStr, _ := param.QueryString(r, "limit")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 {
		limit = defaultLimit
	}

	if limit > 100 {
		limit = 100
	}

	offsetStr, _ := param.QueryString(r, "offset")
	offset, _ := strconv.Atoi(offsetStr) // 如果是"",还是会报错
	if offset <= 0 {
		offset = defaultOffset
	}

	return limit, offset
}

type resourceContainer struct {
	Image         string `json:"image"`
	Cluster       string `json:"cluster"`
	Namespace     string `json:"namespace"`
	ContainerName string `json:"container_name"`

	ResourceName string               `json:"resource_name"`
	ClusterKey   string               `json:"cluster_key"`
	ResourceKind string               `json:"resource_kind"`
	Ports        model.ContainerPorts `json:"ports"`
	Type         string               `json:"type"`
	ImageUUID    uint32               `json:"image_uuid"`

	ImageRepo  string   `json:"image_repo"`
	ImageName  string   `json:"image_name"`
	ImageTag   string   `json:"image_tag"`
	WorkingDir string   `json:"working_dir"`
	Command    []string `json:"command"`

	PopName string `json:"popName"`
}

func (api *api) getResourcesByImage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}

		lib, err := param.QueryString(r, "library")
		if err != nil {
			logging.Get().Err(err).Msgf("get library query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no library given in params")))
			return
		} else {
			lib = strings.TrimPrefix(lib, "http://")
			lib = strings.TrimPrefix(lib, "https://")
			lib = strings.TrimRight(lib, "/")
		}
		repo, err := param.QueryString(r, "repo")
		if err != nil {
			logging.Get().Err(err).Msgf("get repo query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no repo given in params")))
			return
		}
		tag, err := param.QueryString(r, "tag")
		if err != nil {
			logging.Get().Err(err).Msgf("get tag query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no tag given in params")))
			return
		}

		imageID := fmt.Sprintf("%s/%s:%s", lib, repo, tag)
		imageUUID := util.GenerateUUID(imageID)
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		containers, totalCnt, err := resSvc.GetResourceContainers(ctx, dal.ResourceContainersQuery().WithCustom("image_uuid", imageUUID), offset, limit)
		if err != nil {
			logging.Get().Err(err).Msg("GetResourceContainers error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resources error")))
			return
		}

		// KEY `idx_aprr_res` (`cluster_key`,`namespace`,`resource_kind`,`resource_name`),
		ret := make([]resourceContainer, len(containers))
		for i, cont := range containers {
			ret[i].Cluster = cont.ClusterKey
			ret[i].Namespace = cont.Namespace
			ret[i].ContainerName = cont.Name
			ret[i].Ports = cont.Ports
			ret[i].ResourceKind = cont.ResourceKind
			ret[i].ResourceName = cont.ResourceName
			ret[i].Type = cont.Type

			imageRepo, imageName, imageTag := parseImage(cont.Image)
			ret[i].ImageRepo = imageRepo
			ret[i].ImageName = imageName
			ret[i].ImageTag = imageTag
			ret[i].Image = cont.Image
			if cont.Spec != nil {
				ret[i].WorkingDir = cont.Spec.WorkingDir
				ret[i].Command = cont.Spec.Command
			}

			// 因为clusterKey+namespace+resource_kind+resource_name确定一个pod,所以在循环中取这一批Pod
			queryOpt := dal.ResourcePodssQuery()
			queryOpt.WithCluster(cont.ClusterKey)
			queryOpt.WithNamespace(cont.Namespace)
			queryOpt.WithResourceKind(assetsPkg.ResourceKind(cont.ResourceKind))
			queryOpt.WithResourceName(cont.ResourceName)
			pods, _, err := resSvc.GetResourcePods(ctx, queryOpt, offset, limit)
			if err != nil {
				logging.Get().Err(err).Msg("GetResourceContainers error")
				continue
			}
			if len(pods) > 0 {
				ret[i].PopName = pods[0].PodName
			}
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
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}

		vulnName, err := param.QueryString(r, "vulnName")
		if err != nil {
			logging.Get().Err(err).Msgf("get vulnName query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no vulnName given in params")))
			return
		}

		pkgName, err := param.QueryString(r, "pkgName")
		if err != nil {
			logging.Get().Err(err).Msgf("get pkgName query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no pkgName given in params")))
			return
		}

		pkgVersion, err := param.QueryString(r, "pkgVersion")
		if err != nil {
			logging.Get().Err(err).Msgf("get pkgVersion query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no pkgVersion given in params")))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		containers, totalCnt, err := resSvc.GetResourceContainersWithGivenVuln(ctx, vulnName, pkgName, pkgVersion, offset, limit)
		if err != nil {
			logging.Get().Err(err).Msg("GetResourceContainers error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resources error")))
			return
		}
		ret := make([]resourceContainer, len(containers))
		for i, cont := range containers {
			ret[i].Cluster = cont.ClusterKey
			ret[i].Namespace = cont.Namespace
			ret[i].ResourceName = cont.ResourceName
			ret[i].ResourceKind = cont.ResourceKind
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
		Key           string `json:"key"`
		Name          string `json:"name"`
		PlatForm      string `json:"platForm"`
		APIServerAddr string `json:"apiServerAddr"`
		Description   string `json:"description"`
		Version       string `json:"version"`
		Creator       string `json:"creator"`
		CreatedAt     int64  `json:"createdAt"`
		Updater       string `json:"updater"`
		UpdatedAt     int64  `json:"updatedAt"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		clusters, totalCnt, err := resSvc.GetClusters(ctx, offset, limit)
		if err != nil {
			logging.Get().Err(err).Msg("get cluster error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get cluster error")))
			return
		}
		ret := make([]cluster, len(clusters))
		for i, c := range clusters {
			ret[i].Key = c.Key
			ret[i].Description = c.Description
			ret[i].Name = c.Name
			ret[i].PlatForm = c.Platform
			ret[i].APIServerAddr = c.APIServerAddr
			ret[i].Version = c.Version
			ret[i].Creator = c.Creator
			ret[i].CreatedAt = c.CreatedAt.Unix()
			ret[i].UpdatedAt = c.UpdatedAt.Unix()
			ret[i].Updater = c.Updater
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
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
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
		err = clusterManager.UpdateCluster(ctx, &cluster)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, err))
			return
		}

		err = resSvc.AddCluster(ctx, &cluster)
		if err != nil {
			logging.Get().Err(err).Msgf("add cluster error. clusterKey: %s", cluster.Key)
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
		ClusterName string `json:"cluster_name"`
		Description string `json:"description"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
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
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		err = resSvc.UpdateCluster(ctx, request.ClusterKey, request.ClusterName, request.Description)
		if err != nil {
			logging.Get().Err(err).Msgf("update cluster error. data: %v", request)
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("update cluster error")))
			return
		}
		clusterManager, ok := k8s.GetClusterManager()
		if !ok {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("cluster manager not exist")))
			return
		}
		err = clusterManager.UpdateClusterName(ctx, request.ClusterKey, request.ClusterName, request.Description)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("update cluster name failed")))
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
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
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
		err := clusterManager.DeleteCluster(ctx, clusterKey)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, err))
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
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.Get().Err(err).Msg("get cluster_key param error.")
			clusterKey = ""
		}
		query, err := param.QueryString(r, "query")
		if err != nil {
			query = ""
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		namespaces, totalCnt, err := resSvc.GetNamespaces(ctx, clusterKey, query, offset, limit)
		if err != nil {
			logging.Get().Err(err).Msg("getNamespaces error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(namespaces),
			response.WithTotalItems(totalCnt),
			response.WithStartIndex(int64(offset+len(namespaces))),
		)
	}
}

func (api *api) updateNamespace() http.HandlerFunc {
	type Ns struct {
		ClusterKey string   `json:"cluster_key"`
		Name       string   `json:"name"`
		Alias      string   `json:"alias"`
		Managers   []string `json:"managers"`
		Authority  string   `json:"authority"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		var tensorNs Ns
		err := util.DecodeJSONBody(w, r, &tensorNs)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		err = resSvc.UpdateNamespaces(ctx, tensorNs.ClusterKey, tensorNs.Name, tensorNs.Alias, tensorNs.Managers, tensorNs.Authority)
		if err != nil {
			logging.Get().Err(err).Msg("update Namespaces error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		link := fmt.Sprintf("/api/v2/platform/assets/namespaces?cluster_key=%s&name=%s",
			tensorNs.ClusterKey, tensorNs.Name)

		var clusterName string
		clusterManger, ok := k8s.GetClusterManager()
		if ok {
			clusterName, _ = clusterManger.GetClusterName(tensorNs.ClusterKey)
		}
		response.Ok(w, response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s", clusterName, tensorNs.Name),
			ID:   "",
			Link: link,
		}))
	}
}

func (api *api) countNamespaces() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.Get().Err(err).Msg("get cluster_key param error.")
			clusterKey = ""
		}
		query, err := param.QueryString(r, "query")
		if err != nil {
			logging.Get().Err(err).Msg("get query param error.")
			query = ""
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		cnt, err := resSvc.CountNamespaces(ctx, clusterKey, query)
		if err != nil {
			logging.Get().Err(err).Msg("count Namespaces error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		type resp struct {
			Count int64 `json:"count"`
		}

		response.Ok(w, response.WithItem(resp{Count: cnt}))
	}
}

func (api *api) getResourcesInNamespace() http.HandlerFunc {
	type resource struct {
		Cluster        string   `json:"cluster"`
		Namespace      string   `json:"namespace"`
		Kind           string   `json:"kind"`
		Name           string   `json:"name"`
		UID            string   `json:"uid"`
		Alias          string   `json:"alias"`
		Managers       []string `json:"managers"`
		Authority      string   `json:"authority"`
		IsSupportDrift bool     `json:"is_support_drift"`
		Reason         string   `json:"reason"`
	}
	modelToResource := func(rm *model.TensorResource) *resource {
		r := new(resource)
		r.Cluster = rm.ClusterKey
		r.Namespace = rm.Namespace
		r.Kind = rm.Kind
		r.Name = rm.Name
		r.UID = rm.UID
		r.Alias = rm.Alias
		r.Managers = rm.Managers
		r.Authority = rm.Authority
		r.IsSupportDrift = rm.IsSupportDrift
		r.Reason = rm.Reason
		return r
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.Get().Info().Msg("cluster_key param is empty.")
			clusterKey = ""
		}
		query, err := param.QueryString(r, "query")
		if err != nil {
			query = ""
		}

		namespace := chi.URLParam(r, "namespace")
		kind := chi.URLParam(r, "kind")

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
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
		if kind != "" && kind != "_" {
			rquery = rquery.WithResourceKind(assetsPkg.ResourceKind(kind))
		}
		if query != "" {
			rquery = rquery.WithColumnQuery("name", query)
		}
		resources, totalCnt, err := resSvc.GetResources(ctx, rquery, offset, limit)
		if err != nil {
			logging.Get().Err(err).Msgf("query: %+v. offset: %d, limit: %d. get resources error", rquery, offset, limit)
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

func (api *api) getResources() http.HandlerFunc {
	type resource struct {
		Cluster   string   `json:"cluster"`
		Namespace string   `json:"namespace"`
		Kind      string   `json:"kind"`
		Name      string   `json:"name"`
		UID       string   `json:"uid"`
		Alias     string   `json:"alias"`
		Managers  []string `json:"managers"`
		Authority string   `json:"authority"`
	}
	modelToResource := func(rm *model.TensorResource) *resource {
		r := new(resource)
		r.Cluster = rm.ClusterKey
		r.Namespace = rm.Namespace
		r.Kind = rm.Kind
		r.Name = rm.Name
		r.UID = rm.UID
		r.Alias = rm.Alias
		r.Managers = rm.Managers
		r.Authority = rm.Authority
		return r
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.Get().Info().Msg("cluster_key param is empty.")
			clusterKey = ""
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			logging.Get().Info().Msg("namespace param is empty.")
			namespace = ""
		}

		kind, err := param.QueryString(r, "kind")
		if err != nil {
			logging.Get().Info().Msg("kind param is empty.")
			kind = ""
		}

		query, err := param.QueryString(r, "query")
		if err != nil {
			query = ""
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		rQuery := dal.ResourcesQuery()
		if clusterKey != "" {
			rQuery = rQuery.WithCluster(clusterKey)
		}
		if namespace != "" {
			rQuery = rQuery.WithNamespace(namespace)
		}
		if kind != "" && kind != "_" {
			rQuery = rQuery.WithResourceKind(assetsPkg.ResourceKind(kind))
		}
		if query != "" {
			rQuery = rQuery.WithColumnQuery("name", query)
		}
		resources, totalCnt, err := resSvc.GetResources(ctx, rQuery, offset, limit)
		if err != nil {
			logging.Get().Err(err).Msgf("query: %+v. offset: %d, limit: %d. get resources error", rQuery, offset, limit)
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

func (api *api) updateResourceUserData() http.HandlerFunc {
	type UserData struct {
		ClusterKey string   `json:"cluster_key"`
		Namespace  string   `json:"namespace"`
		Kind       string   `json:"kind"`
		Name       string   `json:"name"`
		Alias      string   `json:"alias"`
		Managers   []string `json:"managers"`
		Authority  string   `json:"authority"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		var userData UserData
		err := util.DecodeJSONBody(w, r, &userData)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		res := &model.TensorResource{
			Name:       userData.Name,
			Namespace:  userData.Namespace,
			ClusterKey: userData.ClusterKey,
			Kind:       userData.Kind,
			Alias:      userData.Alias,
			Managers:   userData.Managers,
			Authority:  userData.Authority,
		}
		err = resSvc.UpdateResourceUserData(ctx, res)
		if err != nil {
			logging.Get().Err(err).Msg("update resource user data error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		var clusterName string
		clusterManger, ok := k8s.GetClusterManager()
		if ok {
			clusterName, _ = clusterManger.GetClusterName(res.ClusterKey)
		}
		link := fmt.Sprintf("/api/v2/platform/assets/resources?cluster_key=%s&namespace=%s&kind=%s&query=%s",
			res.ClusterKey, res.Namespace, res.Kind, res.Name)
		response.Ok(w, response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s/%s%s", clusterName, res.Kind, res.Namespace, res.Name),
			ID:   "",
			Link: link,
		}))
	}
}

func parseImage(image string) (string, string, string) {
	var repo, imageName, tag string
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)
	ref, err := name.ParseReference(image, nameOpts...)
	if err != nil {
		return "", "", ""
	}
	repo = ref.Context().RegistryStr()
	imageName = ref.Context().RepositoryStr()
	tag = ref.Identifier()
	return repo, imageName, tag
}

type container struct {
	Cluster       string               `json:"cluster"`
	Namespace     string               `json:"namespace"`
	ResourceKind  string               `json:"resource_kind"`
	ResourceName  string               `json:"resource_name"`
	Name          string               `json:"name"`
	WorkingDir    string               `json:"working_dir"`
	Command       []string             `json:"command"`
	Type          string               `json:"type"`
	ImageRepo     string               `json:"image_repo"`
	ImageName     string               `json:"image_name"`
	ImageTag      string               `json:"image_tag"`
	Ports         []v1.ContainerPort   `json:"ports"`
	Envs          []v1.EnvVar          `json:"envs"`
	FrameWorkInfo []model.WebFrameInfo `json:"frame_work_info"`
	VolumeMounts  []v1.VolumeMount     `json:"volume_mounts"`
}

func fromModelToContainer(cm *model.TensorContainer) *container {
	c := new(container)
	c.Cluster = cm.ClusterKey
	c.Namespace = cm.Namespace
	c.ResourceKind = cm.ResourceKind
	c.ResourceName = cm.ResourceName
	c.Name = cm.Name
	c.Type = cm.Type
	c.WorkingDir = cm.Spec.WorkingDir
	c.Command = cm.Spec.Command
	c.Ports = make([]v1.ContainerPort, len(cm.Ports))
	copy(c.Ports, cm.Ports)

	c.Envs = make([]v1.EnvVar, len(cm.Spec.Env))
	copy(c.Envs, cm.Spec.Env)

	c.VolumeMounts = make([]v1.VolumeMount, len(cm.Spec.VolumeMounts))
	copy(c.VolumeMounts, cm.Spec.VolumeMounts)

	repo, name, tag := parseImage(cm.Image)
	c.ImageRepo = repo
	c.ImageName = name
	c.ImageTag = tag
	return c
}
func (api *api) getResourceContainers() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.Get().Err(err).Msg("get cluster_key param error.")
			clusterKey = ""
		}
		query, err := param.QueryString(r, "query")
		if err != nil {
			query = ""
		}

		namespace := chi.URLParam(r, "namespace")
		kind := chi.URLParam(r, "kind")
		resourceName := chi.URLParam(r, "resource_name")

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
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

		if kind != "" && kind != "_" {
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
			logging.Get().Err(err).Msgf("query: %+v. offset: %d, limit: %d. get containers error", rquery, offset, limit)
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get containers error")))
			return
		}

		items := make([]*container, len(containers))
		for i, container := range containers {
			items[i] = fromModelToContainer(container)
			uuid := util.GenerateUUID(container.Image)
			webFrameScan, err := resSvc.GetFramework(ctx, uuid)
			if err != nil || webFrameScan == nil {
				continue
			}
			var infos []model.WebFrameInfo
			err = json.Unmarshal(webFrameScan.WebFrameInfoJSON, &infos)
			if err != nil {
				logging.Get().Err(err).Msg("get web frame")
				continue
			}
			items[i].FrameWorkInfo = infos
		}

		response.Ok(w, response.WithItems(items), response.WithTotalItems(totalCnt), response.WithStartIndex(int64(offset+len(items))))
	}
}

// @Summary
// @Description get the list of pods with options
// @Produce json
// @Method GET
// @Router /api/v2/platform/assets/pods
func (api *api) getPods() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}

		queryOpt := dal.ResourcePodssQuery()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			clusterKey = ""
		}
		if clusterKey != "" {
			queryOpt.WithCluster(clusterKey)
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			namespace = ""
		}
		if namespace != "" {
			queryOpt.WithNamespace(namespace)
		}

		nodeName, err := param.QueryString(r, "node_name")
		if err != nil {
			nodeName = ""
		}
		if nodeName != "" {
			queryOpt.WithNodeName(nodeName)
		}

		resKind, err := param.QueryString(r, "resourceKind")
		if err != nil {
			resKind = ""
		}
		if resKind != "" {
			queryOpt.WithResourceKind(assetsPkg.ResourceKind(resKind))
		}

		resName, err := param.QueryString(r, "resourceName")
		if err != nil {
			resName = ""
		}
		if resName != "" {
			queryOpt.WithResourceName(resName)
		}

		query, err := param.QueryString(r, "query")
		if err != nil {
			query = ""
		}
		if query != "" {
			// queryOpt.WithColumnQuery("pod_name", query)
			queryOpt.WithMulColumnQuery([]string{"pod_name"}, query)
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resource service err")))
			return
		}

		pods, cnt, err := resSvc.GetResourcePods(ctx, queryOpt, offset, limit)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, fmt.Errorf("get resource pod err: %v", err)))
			return
		}
		response.Ok(w, response.WithItems(pods), response.WithTotalItems(cnt))
	}
}

func (api *api) countResource() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		queryOpt := dal.ResourcesQuery()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.Get().Err(err).Msg("get cluster_key param error.")
			clusterKey = ""
		}
		if clusterKey != "" {
			queryOpt.WithCluster(clusterKey)
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			logging.Get().Err(err).Msg("get namespace param error.")
			namespace = ""
		}
		if namespace != "" {
			queryOpt.WithNamespace(namespace)
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		c, err := resSvc.CountResource(ctx, queryOpt)
		if err != nil {
			logging.Get().Error().Msg("count resource error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("count resource error")))
			return
		}
		response.Ok(w, response.WithItem(countResp{Count: c}))
	}
}

func (api *api) countContainers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		queryOpt := dal.ResourceContainersQuery()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.Get().Err(err).Msg("get cluster_key param error.")
		}
		if clusterKey != "" {
			queryOpt.WithCluster(clusterKey)
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			logging.Get().Err(err).Msg("get namespace param error.")
		}
		if namespace != "" {
			queryOpt.WithNamespace(namespace)
		}

		resKind, err := param.QueryString(r, "resourceKind") // chi.URLParam(r, "resourceKind")
		if err != nil {
			resKind = ""
		}
		if resKind != "" {
			queryOpt.WithResourceKind(assetsPkg.ResourceKind(resKind))
		}

		resName, err := param.QueryString(r, "resourceName") // chi.URLParam(r, "resourceName")
		if err != nil {
			resName = ""
		}
		if resName != "" {
			queryOpt.WithResourceName(resName)
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		c, err := resSvc.CountContainer(ctx, queryOpt)
		if err != nil {
			logging.Get().Error().Msg("count container error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("count container error")))
			return
		}
		response.Ok(w, response.WithItem(countResp{Count: c}))
	}
}

func (api *api) countPods() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		queryOpt := dal.ResourcePodssQuery()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.Get().Err(err).Msg("get cluster_key param error.")
		}
		if clusterKey != "" {
			queryOpt.WithCluster(clusterKey)
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			logging.Get().Err(err).Msg("get namespace param error.")
		}
		if namespace != "" {
			queryOpt.WithNamespace(namespace)
		}

		resKind, err := param.QueryString(r, "resourceKind")
		if err != nil {
			resKind = ""
		}
		if resKind != "" {
			queryOpt.WithResourceKind(assetsPkg.ResourceKind(resKind))
		}

		resName, err := param.QueryString(r, "resourceName")
		if err != nil {
			resName = ""
		}
		if resName != "" {
			queryOpt.WithResourceName(resName)
		}
		nodeName, err := param.QueryString(r, "node_name")
		if err != nil {
			nodeName = ""
		}
		if nodeName != "" {
			queryOpt.WithNodeName(nodeName)
		}

		cnt, err := resSvc.CountPods(ctx, queryOpt)
		if err != nil {
			logging.Get().Error().Msg("count pods error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("count pods error")))
			return
		}
		response.Ok(w, response.WithItem(countResp{Count: cnt}))
	}
}

func (api *api) getNodes() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			clusterKey = ""
		}
		query, err := param.QueryString(r, "query")
		if err != nil {
			query = ""
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		queryOpt := dal.NodeQuery()
		queryOpt.WithCluster(clusterKey)
		if query != "" {
			queryOpt.WithCustom("host_name", query)
		}
		nodes, err := resSvc.GetNodes(ctx, queryOpt, offset, limit)
		if err != nil {
			logging.Get().Err(err).Msg("getNodes error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		totalCnt, err := resSvc.CountNodes(ctx, queryOpt)
		if err != nil {
			logging.Get().Err(err).Msg("countNodes error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(nodes),
			response.WithTotalItems(totalCnt),
			response.WithStartIndex(int64(offset+len(nodes))),
		)
	}
}

func (api *api) countNodes() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			clusterKey = ""
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		query := dal.NodeQuery()
		if clusterKey != "" {
			query = query.WithCluster(clusterKey)
		}
		totalCnt, err := resSvc.CountNodes(ctx, query)
		if err != nil {
			logging.Get().Err(err).Msg("countNodes error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItem(countResp{totalCnt}))
	}
}
func (api *api) GetResourceAssociate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resource service failed")))
			return
		}

		arguments, err := resSvc.GetArguments(r)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		// print debug log
		// logging.Get().Info().Msgf("resource argument : %+v", *arguments)
		// get resource relation
		res, err := resSvc.GetResourceRelation(arguments)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.Errorf("get resource relations failed, %v", err)))
			return
		}

		response.Ok(w, response.WithItems(res))
	}
}

func (api *api) GetContainerAssociate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resource service failed")))
			return
		}

		arguments, err := resSvc.GetArguments(r)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		// print debug log
		// logging.Get().Info().Msgf("container argument : %+v", *arguments)
		// get container relation
		container, err := resSvc.GetContainerRelation(arguments)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.Errorf("get container relations failed, %v", err)))
			return
		}

		response.Ok(w, response.WithItems(container))
	}
}

func (api *api) GetProcessAssociate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resource service failed")))
			return
		}

		arguments, err := resSvc.GetArguments(r)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		// print debug log
		// logging.Get().Info().Msgf("process argument : %+v", *arguments)
		// get resource relation
		process, err := resSvc.GetProcessRelation(arguments)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.Errorf("get process relations failed, %v", err)))
			return
		}

		response.Ok(w, response.WithItems(process))
	}
}

func (api *api) GetProcessList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resource service failed")))
			return
		}

		arguments, err := resSvc.GetArguments(r)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.Errorf("get process argument failed, %v", err)))
			return
		}
		// print debug log
		// logging.Get().Info().Msgf("process argument : %+v", *arguments)
		// get resource relation
		process, err := resSvc.GetContainerProcessList(arguments)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.Errorf("get process list failed, %v", err)))
			return
		}

		response.Ok(w, response.WithItems(process))
	}
}

func (api *api) getFrameworks() http.HandlerFunc {
	type Item struct {
		Managers     []string           `json:"managers"`
		WebFrameInfo model.WebFrameInfo `json:"web_frame_info"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var items []*Item
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		_, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			clusterKey = ""
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		query := dal.ResourceContainersQuery()
		query.WithCluster(clusterKey)

		containers, _, err := resSvc.GetResourceContainers(ctx, query, offset, -1)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("pod get error")))
			return
		}
		frameInfos, err := resSvc.GetFrameworks(ctx)

		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("frameworks get error")))
			return
		}

		logging.Get().Debug().Msgf("frames : %d,  containers : %d", len(frameInfos), len(containers))
		for _, frm := range frameInfos {
			for _, c := range containers {
				uuid := util.GenerateUUID(c.Image)
				if frm.ImageUUID == uuid && frm.WebFrameInfoJSON != nil && len(frm.WebFrameInfoJSON) > 0 {
					var infos []model.WebFrameInfo
					err = json.Unmarshal(frm.WebFrameInfoJSON, &infos)
					if err != nil {
						logging.Get().Err(err).Msg("get web frame")
						continue
					}
					if len(infos) > 0 {
						for i := range infos {
							items = append(items, &Item{WebFrameInfo: infos[i]})
							logging.Get().Debug().Msgf("frame infos %+v", infos[i])
						}
					}
					break
				}
			}
		}
		response.Ok(w, response.WithItems(items), response.WithTotalItems(int64(len(items))))
	}
}

func (api *api) countImages() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		queryOpt := dal.ResourceContainersQuery()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			clusterKey = ""
		}

		if clusterKey != "" {
			queryOpt.WithCluster(clusterKey)
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			logging.Get().Err(err).Msg("get namespace param error.")
		}
		if namespace != "" {
			queryOpt.WithNamespace(namespace)
		}

		resKind, err := param.QueryString(r, "resourceKind")
		if err != nil {
			resKind = ""
		}
		if resKind != "" {
			queryOpt.WithResourceKind(assetsPkg.ResourceKind(resKind))
		}

		resName, err := param.QueryString(r, "resourceName")
		if err != nil {
			resName = ""
		}
		if resName != "" {
			queryOpt.WithResourceName(resName)
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resource service failed")))
			return
		}

		cnt, err := resSvc.CountImages(ctx, queryOpt)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get images failed")))
			return
		}
		response.Ok(w, response.WithItem(countResp{cnt}))
	}
}

func (api *api) getImageInfos() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		queryOpt := dal.ResourceContainersQuery()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.Get().Err(err).Msg("get cluster_key param error.")
		}
		if clusterKey != "" {
			queryOpt.WithCluster(clusterKey)
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			logging.Get().Err(err).Msg("get namespace param error.")
		}
		if namespace != "" {
			queryOpt.WithNamespace(namespace)
		}

		resKind, err := param.QueryString(r, "resourceKind")
		if err != nil {
			resKind = ""
		}
		if resKind != "" {
			queryOpt.WithResourceKind(assetsPkg.ResourceKind(resKind))
		}

		resName, err := param.QueryString(r, "resourceName")
		if err != nil {
			resName = ""
		}
		if resName != "" {
			queryOpt.WithResourceName(resName)
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resource service failed")))
			return
		}
		imageInfos, err := resSvc.GetImageInfos(ctx, queryOpt)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resource service failed")))
			return
		}

		response.Ok(w, response.WithItems(imageInfos), response.WithTotalItems(int64(len(imageInfos))))
	}
}

func (api *api) getImageProblems() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}

		queryOpt := dal.ResourceContainersQuery()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			clusterKey = ""
		}
		if clusterKey != "" {
			queryOpt.WithCluster(clusterKey)
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			namespace = ""
		}
		if namespace != "" {
			queryOpt.WithNamespace(namespace)
		}

		resKind, err := param.QueryString(r, "resourceKind")
		if err != nil {
			resKind = ""
		}
		if resKind != "" {
			queryOpt.WithResourceKind(assetsPkg.ResourceKind(resKind))
		}

		resName, err := param.QueryString(r, "resourceName")
		if err != nil {
			resName = ""
		}
		if resName != "" {
			queryOpt.WithResourceName(resName)
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resource service failed")))
			return
		}
		images, err := resSvc.GetImages(ctx, queryOpt, offset, limit)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get images failed")))
			return
		}
		problems := make(map[int64]struct{})
		for _, i := range images {
			for _, q := range i.SecurityIssue {
				problems[q.Value] = struct{}{}
			}
		}

		var resp []int64
		for k, _ := range problems {
			resp = append(resp, k)
		}
		response.Ok(w, response.WithItems(resp), response.WithTotalItems(int64(len(resp))))
	}
}

func (api *api) getContainers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		offsetID, err := param.QueryInt64(r, "offsetID")
		if err != nil {
			offsetID = -1
		}

		offset, err := param.QueryInt(r, "offset")
		if err != nil {
			offset = -1
		}

		limit, err := param.QueryInt(r, "limit")
		if err != nil {
			limit = maxAuditLogBatchSize
		}

		queryOpt := dal.ResourceContainersQuery()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			clusterKey = ""
		}
		if clusterKey != "" {
			queryOpt.WithCluster(clusterKey)
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			namespace = ""
		}
		if namespace != "" {
			queryOpt.WithNamespace(namespace)
		}

		resKind, err := param.QueryString(r, "resourceKind")
		if err != nil {
			resKind = ""
		}
		if resKind != "" {
			queryOpt.WithResourceKind(assetsPkg.ResourceKind(resKind))
		}

		resName, err := param.QueryString(r, "resourceName")
		if err != nil {
			resName = ""
		}
		if resName != "" {
			queryOpt.WithResourceName(resName)
		}
		cntSvc, ok := containers2.GetContainersService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resource service failed")))
			return
		}
		containers, totalCnt, err := cntSvc.GetContainerInfo(ctx, queryOpt, offsetID, offset, limit)
		if err != nil {
			logging.Get().Err(err).Msg("get container info failed")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get container info failed")))
			return
		}
		response.Ok(w, response.WithItems(containers), response.WithTotalItems(totalCnt))
	}
}

func (api *api) getResourceTypes() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resourceTypes := []assetsPkg.ResourceKind{
			assetsPkg.KindDeployment,
			assetsPkg.KindReplicaSet,
			assetsPkg.KindStatefulSet,
			assetsPkg.KindReplicationController,
			assetsPkg.KindDaemonSet,
			assetsPkg.KindJob,
			assetsPkg.KindCronJob,
			assetsPkg.KindPodNoOwner,
		}
		response.Ok(w, response.WithItems(resourceTypes),
			response.WithTotalItems(int64(len(resourceTypes))),
			response.WithStartIndex(0),
		)
	}
}

func (api *api) getRawContainers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		query := dal.RawContainersQuery()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		clusterKey, _ := param.QueryString(r, "cluster_key")
		nodeNames, _ := param.QueryStringArray(r, "node_name")
		namespaces, _ := param.QueryStringArray(r, "namespace")
		podNames, _ := param.QueryStringArray(r, "pod_name")
		containerNames, _ := param.QueryStringArray(r, "container_name")

		isK8sManaged, err := param.QueryBool(r, "k8s_managed")
		if err == nil {
			query.WithK8sManaged(isK8sManaged)
		}
		status, _ := param.QueryInt32Array(r, "status")
		if len(status) > 0 {
			query.WithInConditionCustom("status", status)
		}
		resourceNames, _ := param.QueryStringArray(r, "resource_name")

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		if clusterKey != "" {
			query = query.WithCluster(clusterKey)
		}
		if len(nodeNames) != 0 {
			query = query.WithColumnMultiQuery("node_name", nodeNames)
		}
		if len(namespaces) != 0 {
			query = query.WithColumnMultiQuery("namespace", namespaces)
		}
		if len(podNames) != 0 {
			query = query.WithColumnMultiQuery("pod_name", podNames)
		}
		if len(containerNames) != 0 {
			query = query.WithColumnMultiQuery("name", containerNames)
		}
		if len(resourceNames) != 0 {
			query = query.WithColumnMultiQuery("resource_name", resourceNames)
		}

		containers, err := resSvc.GetRawContainer(ctx, query, offset, limit)
		if err != nil {
			logging.Get().Err(err).Msg("get raw container error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		totalCnt, err := resSvc.CountRawContainer(ctx, query)
		if err != nil {
			logging.Get().Err(err).Msg("count raw container error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(containers),
			response.WithTotalItems(totalCnt),
			response.WithStartIndex(int64(offset+len(containers))),
		)
	}
}

func (api *api) getRawContainer() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			clusterKey = ""
		}

		containerID := chi.URLParam(r, "containerID")

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		query := dal.RawContainersQuery()
		if clusterKey != "" {
			query = query.WithCluster(clusterKey)
		}

		if containerID != "" {
			query = query.WithID(containerID)
		}
		query.WithInConditionCustom("status", assetsPkg.All)
		containers, err := resSvc.GetRawContainer(ctx, query, -1, -1)
		if err != nil || len(containers) == 0 {
			logging.Get().Err(err).Msgf("get raw container error, got number %d", len(containers))
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w, response.WithItem(containers[0]))
	}
}

func (api *api) countRawContainers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		query := dal.RawContainersQuery()

		clusterKey, _ := param.QueryString(r, "cluster_key")

		nodeName, _ := param.QueryString(r, "node_name")

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		if clusterKey != "" {
			query = query.WithCluster(clusterKey)
		}
		if nodeName != "" {
			query = query.WithNodeName(nodeName)
		}

		totalCnt, err := resSvc.CountRawContainer(ctx, query)
		if err != nil {
			logging.Get().Err(err).Msg("count raw container error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItem(countResp{Count: totalCnt}))
	}
}
