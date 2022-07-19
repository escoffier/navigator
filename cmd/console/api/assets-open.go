package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	assetsPkg "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) assetsForOpenapi() func(chi.Router) {
	rate, err := strconv.Atoi(os.Getenv("OPENAPI_RATE_LIMIT_PER_MIN"))
	if err != nil || rate <= 0 {
		rate = 20
	}

	return func(r chi.Router) {

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/pods", api.getPodsForOpenapi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/namespaces", api.getNamespacesForOpenapi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/resContainers", api.getResourceContainersForOpenapi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/resources/vulns/detail", api.getResourcesByImageVulnForOpenapi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/nodes", api.getNodesForOpenapi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/resources", api.getResourcesInNamespaceForOpenapi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/resources/byImage", api.getResourcesByImageForOpenapi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/clusters", api.getClustersForOpenapi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/summary", api.getSummaryForOpenapi())

		exportContainers := os.Getenv("EXPORT_CONTAINERS")
		if exportContainers == "true" {
			r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
				Get("/containers", api.getContainers())
		}
	}
}

// 获取Pod列表
func (api *api) getPodsForOpenapi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		limit, offset := getLimitAndOffsetWithDefault(r)

		queryOpt := dal.ResourcePodssQuery()

		clusterKey, err := param.QueryString(r, "clusterKey")
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

		nodeName, err := param.QueryString(r, "nodeName")
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

		query, err := param.QueryString(r, "keyword")
		if err != nil {
			query = ""
		}
		if query != "" {
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

		resPods := make([]PodResourceRelationOpenApi, 0)
		for _, pod := range pods {
			res := PodResourceRelationOpenApi{
				ClusterKey:   pod.ClusterKey,
				PodIP:        pod.PodIP,
				PodUID:       pod.PodUID,
				HostIP:       pod.HostIP,
				Namespace:    pod.Namespace,
				PodName:      pod.PodName,
				NodeName:     pod.NodeName,
				ResourceName: pod.ResourceName,
				ResourceKind: pod.ResourceKind,
				CreatedAt:    pod.CreatedAt.Unix(),
				UpdatedAt:    pod.UpdatedAt.Unix(),
			}
			resPods = append(resPods, res)
		}

		response.Ok(w, response.WithItems(resPods),
			response.WithTotalItems(cnt),
			response.WithItemsPerPage(int64(limit)),
			response.WithStartIndex(int64(offset)))
	}
}

// 获取命名空间列表
func (api *api) getNamespacesForOpenapi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset := getLimitAndOffsetWithDefault(r)
		clusterKey, err := param.QueryString(r, "clusterKey")
		if err != nil {
			logging.GetLogger().Err(err).Msg("get cluster_key param error.")
		}

		if clusterKey == "" {
			response.RespError(w, http.StatusExpectationFailed, response.WithMessage("not get clusterKey"))
			return
		}

		query, err := param.QueryString(r, "keyword")
		if err != nil {
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
		nss := make([]TensorNamespaceOpenApi, 0)
		for _, ns := range namespaces {
			nss = append(nss, TensorNamespaceOpenApi{
				Name:       ns.Name,
				ClusterKey: ns.ClusterKey,
				Alias:      ns.Alias,
				Authority:  ns.Authority,
			})
		}

		response.Ok(w, response.WithItems(nss),
			response.WithTotalItems(totalCnt),
			response.WithItemsPerPage(int64(limit)),
			response.WithStartIndex(int64(offset)))
	}
}

// 获取资源容器列表
func (api *api) getResourceContainersForOpenapi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset := getLimitAndOffsetWithDefault(r)
		clusterKey, err := param.QueryString(r, "clusterKey")
		if err != nil {
			logging.GetLogger().Err(err).Msg("get cluster_key param error.")
			clusterKey = ""
		}
		query, err := param.QueryString(r, "keyword")
		if err != nil {
			query = ""
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil || namespace == "" {
			response.RespError(w, http.StatusExpectationFailed, response.WithMessage("not get namespace"))
			return
		}

		kind, err := param.QueryString(r, "resourceKind")
		if err != nil || kind == "" {
			response.RespError(w, http.StatusExpectationFailed, response.WithMessage("not get resourceKind"))
			return
		}

		resourceName, err := param.QueryString(r, "resourceName")
		if err != nil || resourceName == "" {
			response.RespError(w, http.StatusExpectationFailed, response.WithMessage("not get resourceName"))
			return
		}

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
			logging.GetLogger().Err(err).Msgf("query: %+v. offset: %d, limit: %d. get containers error", rquery, offset, limit)
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get containers error")))
			return
		}

		res := make([]ContainerOpenApi, 0)
		for _, b := range containers {
			res = append(res, ContainerOpenApi{
				ClusterKey:   b.ClusterKey,
				Name:         b.Name,
				Namespace:    b.Namespace,
				ResourceKind: b.ResourceKind,
				ResourceName: b.ResourceName,
				Image:        b.Image,
			})
		}

		response.Ok(w, response.WithItems(res),
			response.WithTotalItems(totalCnt),
			response.WithItemsPerPage(int64(limit)),
			response.WithStartIndex(int64(offset)))
	}
}

func (api *api) getResourcesByImageVulnForOpenapi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset := getLimitAndOffsetWithDefault(r)

		vulnName, _ := param.QueryString(r, "vulnName")
		pkgName, _ := param.QueryString(r, "pkgName")
		pkgVersion, _ := param.QueryString(r, "pkgVersion")
		if vulnName == "" || pkgName == "" || pkgVersion == "" {
			response.RespError(w, http.StatusExpectationFailed, response.WithMessage("not get vulnName or pkgName or pkgVersion"))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		containers, totalCnt, err := resSvc.GetResourceContainersWithGivenVuln(ctx, vulnName, pkgName, pkgVersion, offset, limit)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GetResourceContainers error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resources error")))
			return
		}
		ret := make([]resourceContainerOpenApi, len(containers))
		for i, cont := range containers {
			ret[i].ClusterKey = cont.ClusterKey
			ret[i].Namespace = cont.Namespace
			ret[i].ResourceName = cont.ResourceName
			ret[i].ResourceKind = cont.ResourceKind
			ret[i].ContainerName = cont.Name
			ret[i].Image = cont.Image
		}
		response.Ok(w, response.WithItems(ret),
			response.WithTotalItems(totalCnt),
			response.WithItemsPerPage(int64(limit)),
			response.WithStartIndex(int64(offset)))
	}
}

func (api *api) getNodesForOpenapi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset := getLimitAndOffsetWithDefault(r)
		clusterKey, err := param.QueryString(r, "clusterKey")
		if err != nil {
			logging.GetLogger().Err(err).Msg("get cluster_key param error.")
			clusterKey = ""
		}
		if clusterKey == "" {
			response.RespError(w, http.StatusExpectationFailed, response.WithMessage("not get clusterKey"))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		nodes, err := resSvc.GetNodes(ctx, dal.NodeQuery().WithCluster(clusterKey), offset, limit)
		if err != nil {
			logging.GetLogger().Err(err).Msg("getNodes error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		totalCnt, err := resSvc.CountNodes(ctx, dal.NodeQuery().WithCluster(clusterKey))
		if err != nil {
			logging.GetLogger().Err(err).Msg("countNodes error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		res := make([]TensorNodeOpenApi, 0)
		for i := range nodes {
			no := TensorNodeOpenApi{
				ClusterKey:              nodes[i].ClusterKey,
				HostName:                nodes[i].HostName,
				NodeIP:                  nodes[i].NodeIP,
				KernelVersion:           nodes[i].KernelVersion,
				OsInfo:                  nodes[i].OsInfo,
				OsImage:                 nodes[i].OsImage,
				ContainerRuntimeVersion: nodes[i].ContainerRuntimeVersion,
				KubeletVersion:          nodes[i].KubeletVersion,
				KubeProxyVersion:        nodes[i].KubeProxyVersion,
				Architecture:            nodes[i].Architecture,
				Volumes:                 make([]NodeVolume, 0),
				ContainerImages:         nodes[i].ContainerImages,
				CreatedAt:               nodes[i].CreatedAt.Unix(),
				UpdatedAt:               nodes[i].UpdatedAt.Unix(),
				Status:                  nodes[i].Status,
			}
			for j := range nodes[i].Volumes {
				no.Volumes = append(no.Volumes, NodeVolume{
					Type:       nodes[i].Volumes[j].Type,
					VolumeName: nodes[i].Volumes[j].VolumeName,
					DevicePath: nodes[i].Volumes[j].DevicePath,
				})
			}
			res = append(res, no)
		}

		response.Ok(w, response.WithItems(res),
			response.WithTotalItems(totalCnt),
			response.WithItemsPerPage(int64(limit)),
			response.WithStartIndex(int64(offset)))
	}
}

func (api *api) getResourcesInNamespaceForOpenapi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset := getLimitAndOffsetWithDefault(r)
		rquery := dal.ResourcesQuery()
		clusterKey, err := param.QueryString(r, "clusterKey")
		if err == nil && clusterKey != "" {
			rquery = rquery.WithCluster(clusterKey)
		}
		query, err := param.QueryString(r, "keyword")
		if err == nil && query != "" {
			rquery = rquery.WithColumnQuery("name", query)
		}

		namespace, err := param.QueryString(r, "namespace")
		if err == nil && namespace != "" {
			rquery = rquery.WithNamespace(namespace)
		}

		kind, err := param.QueryString(r, "resourceKind")
		if err == nil && kind != "" && kind != "_" {
			rquery = rquery.WithResourceKind(assetsPkg.ResourceKind(kind))
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		resources, totalCnt, err := resSvc.GetResources(ctx, rquery, offset, limit)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("query: %+v. offset: %d, limit: %d. get resources error", rquery, offset, limit)
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resources error")))
			return
		}

		items := make([]TensorResourceOpenApi, len(resources))
		for i := range resources {
			items[i] = TensorResourceOpenApi{
				Alias:        resources[i].Alias,
				ResourceName: resources[i].Name,
				Namespace:    resources[i].Namespace,
				ClusterKey:   resources[i].ClusterKey,
				UID:          resources[i].UID,
				ResourceKind: resources[i].Kind,
				Managers:     append([]string{}, resources[i].Managers...),
				Authority:    resources[i].Authority,
				CreatedAt:    resources[i].CreatedAt.Unix(),
				UpdatedAt:    resources[i].UpdatedAt.Unix(),
			}
		}
		response.Ok(w, response.WithItems(items),
			response.WithTotalItems(totalCnt),
			response.WithItemsPerPage(int64(limit)),
			response.WithStartIndex(int64(offset)))
	}
}

func (api *api) getResourcesByImageForOpenapi() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset := getLimitAndOffsetWithDefault(r)

		imageName, _ := param.QueryString(r, "image")
		if imageName == "" {
			response.RespError(w, http.StatusExpectationFailed, response.WithMessage("not get image"))
			return
		}

		imageName = strings.TrimPrefix(imageName, "https://")
		imageName = strings.TrimPrefix(imageName, "http://")
		imageUUID := util.GenerateUUID(imageName)
		logging.GetLogger().Info().Uint32("imageUUID", imageUUID).Str("imageName", imageName).Msg("getResourcesByImageForOpenapi")

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		containers, totalCnt, err := resSvc.GetResourceContainers(ctx, dal.ResourceContainersQuery().WithCustom("image_uuid", imageUUID), offset, limit)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GetResourceContainers error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resources error")))
			return
		}
		ret := make([]ResourceContainerOpenApi, len(containers))
		for i, cont := range containers {
			ret[i].ClusterKey = cont.ClusterKey
			ret[i].Namespace = cont.Namespace
			ret[i].ContainerName = cont.Name
			ret[i].Ports = cont.Ports
			ret[i].ResourceKind = cont.ResourceKind
			ret[i].ResourceName = cont.ResourceName
			ret[i].Image = imageName
			ret[i].Command = make([]string, 0)

			if cont.Spec != nil {
				ret[i].WorkingDir = cont.Spec.WorkingDir
				ret[i].Command = append(ret[i].Command, cont.Spec.Command...)
			}
		}
		response.Ok(w, response.WithItems(ret),
			response.WithTotalItems(totalCnt),
			response.WithItemsPerPage(int64(limit)),
			response.WithStartIndex(int64(offset)))
	}
}

func (api *api) getClustersForOpenapi() http.HandlerFunc {
	type cluster struct {
		ClusterKey  string `json:"clusterKey"`
		ClusterName string `json:"clusterName"`
		Description string `json:"description"`
		Creator     string `json:"creator"`
		CreatedAt   int64  `json:"createdAt"`
		Updater     string `json:"updater"`
		UpdatedAt   int64  `json:"updatedAt"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
		defer cancel()

		limit, offset := getLimitAndOffsetWithDefault(r)

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
			ret[i].ClusterKey = cluster.Key
			ret[i].Description = cluster.Description
			ret[i].ClusterName = cluster.Name
			ret[i].Creator = cluster.Creator
			ret[i].CreatedAt = cluster.CreatedAt.Unix()
			ret[i].UpdatedAt = cluster.UpdatedAt.Unix()
			ret[i].Updater = cluster.Updater
		}

		response.Ok(w, response.WithItems(ret),
			response.WithTotalItems(totalCnt),
			response.WithItemsPerPage(int64(limit)),
			response.WithStartIndex(int64(offset)))
	}
}

func (api *api) getSummaryForOpenapi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		podQueryOpt := dal.ResourcePodssQuery()
		resourceQueryOpt := dal.ResourcesQuery()
		containerQueryOpt := dal.ResourceContainersQuery()
		nodeQuery := dal.NodeQuery()

		// 不是必传参数，忽略错误
		clusterKey, _ := param.QueryString(r, "clusterKey")
		if clusterKey != "" {
			podQueryOpt.WithCluster(clusterKey)
			resourceQueryOpt.WithCluster(clusterKey)
			containerQueryOpt.WithCluster(clusterKey)
			nodeQuery.WithCluster(clusterKey)
		}

		if namespace, _ := param.QueryString(r, "namespace"); namespace != "" {
			podQueryOpt.WithNamespace(namespace)
			resourceQueryOpt.WithNamespace(namespace)
			containerQueryOpt.WithNamespace(namespace)
		}

		resourceCount, err1 := resSvc.CountResource(ctx, resourceQueryOpt)
		containerCount, err2 := resSvc.CountContainer(ctx, containerQueryOpt)
		nsCount, err3 := resSvc.CountNamespaces(ctx, clusterKey, "")
		nodeCout, err4 := resSvc.CountNodes(ctx, nodeQuery)
		podCont, err5 := resSvc.CountPods(ctx, podQueryOpt)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
			logging.GetLogger().Err(err1).Err(err2).Err(err3).Err(err4).Err(err5).Msg("getSummaryForOpenapi")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("count pods error")))
			return
		}

		res := ResourceSummery{
			NamespacesNum: nsCount,
			ResourcesNum:  resourceCount,
			NodeNum:       nodeCout,
			PodNum:        podCont,
			ContainerNum:  containerCount,
		}

		response.Ok(w, response.WithItem(res))
	}
}
