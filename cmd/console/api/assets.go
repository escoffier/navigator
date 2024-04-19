package api

import (
	"context"
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/jinzhu/copier"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	json "github.com/json-iterator/go"
	param "github.com/oceanicdev/chi-param"
	"github.com/pkg/errors"
	"gitlab.com/security-rd/go-pkg/logging"
	v1 "k8s.io/api/core/v1"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	containers2 "gitlab.com/piccolo_su/vegeta/cmd/console/service/containers"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/defense"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	assetsPkg "gitlab.com/piccolo_su/vegeta/pkg/assets"
	pkgAssets "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) assets() func(chi.Router) {
	return func(r chi.Router) {
		//tag
		r.Get("/assetsTags", api.getAssetsTags)
		r.Get("/enableAssetsTags", api.getEnableAssetsTags)
		r.Put("/assetsTagChangeStatus", api.changeAssetsTags)
		r.Get("/assetsTag/{tagId}", api.getAssetsTagRelCountsById)
		r.Post("/assetsTag", api.saveAssetsTag)
		r.Delete("/assetsTag/{tagId}", api.deleteAssetsTag)
		r.Post("/assetsChangeTag", api.assetsChangeTags) // 批量修改关联标签
		r.Get("/assetsCustomTags", api.getAssetsCustomTags)
		r.Get("/assetsCountInTag", api.getAssetsCountInTag) //资产卡片计数

		r.Get("/clusters", api.getClusters())
		r.Post("/cluster", api.addNewCluster())
		r.Put("/cluster", api.updateClusterInfo())
		r.Delete("/cluster/{clusterKey}", api.deleteCluster())
		r.Get("/namespaces", api.getNamespaces())
		r.Post("/namespace", api.updateNamespace())
		r.Get("/namespace/{namespace}/kind/{kind}/resources", api.getResourcesInNamespace())
		r.Get("/resources", api.getResources())
		// TODO: support redis search
		r.Get("/resources/fuzz", api.getResourcesFuzzy())
		r.Post("/resource/userData", api.updateResourceUserData())
		r.Get("/namespace/{namespace}/kind/{kind}/resource/{resource_name}/containers", api.getResourceContainers())
		r.Get("/imageinfos", api.getImageInfosV2())
		r.Get("/imageProblems", api.getImageProblems())
		r.Get("/resources/byImage", api.getResourcesByImage())
		r.Get("/resources/byImageVulns", api.getResourcesByImageVuln())
		// TODO: support redis search
		r.Get("/pods", api.getPods())
		r.Get("/podsByOwner", api.getPodsByOwner())
		r.Get("/podsBySvc", api.getPodsBySvc())

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
		r.Get("/pod/netflow/info", api.GetPodAssociate())
		r.Get("/container/netflow/info", api.GetContainerAssociate())
		r.Get("/container/process/netflow/info", api.GetProcessAssociate())

		exportContainers := os.Getenv("EXPORT_CONTAINERS")
		if exportContainers == "true" {
			r.Get("/containers", api.getContainers())
		}
		// TODO: support redis search
		r.Get("/rawContainers", api.getRawContainersWithFramework())
		r.Get("/rawContainersByPod", api.getRawContainersByPod())
		r.Get("/rawContainers/count", api.countRawContainers())
		r.Get("/rawContainer/{containerID}", api.getRawContainer())
		r.Get("/resources/types", api.getResourceTypes())
		r.Get("/cluster/ruleversion", api.getRuleVersion())

		r.Get("/cluster/{cluster_key}/namespaces/{name}", api.getNamespace())
		r.Get("/cluster/{cluster_key}/namespace/{namespace}/kind/{kind}/resources/{name}", api.getResource())
		r.Get("/cluster/{cluster_key}/namespace/{namespace}/pods/{name}", api.getPod())
		r.Get("/cluster/{cluster_key}/nodes/{name}", api.getNode())
		r.Get("/cluster/{cluster_key}/nodes/withCount/{name}", api.getNodeWithCount())

		r.Get("/applications", api.getApplications())
		r.Get("/applications/count", api.countApplications())
		r.Get("/applications/types", api.getApplicationTypes())
		r.Get("/applications/versions", api.getApplicationVersions())
		r.Get("/applications/targets", api.getApplicationTargets())

		// ingress
		r.Get("/ingresses", api.getIngresses())
		r.Get("/cluster/{cluster_key}/namespace/{namespace}/ingresses/{ingress_name}", api.getIngressBase())
		r.Get("/ingresses/backendKinds", api.getIngressBackendKinds())
		r.Get("/ingresses/{ingress_id}/rules", api.getIngressRules())
		// service
		r.Get("/services", api.getServices())
		r.Get("/cluster/{cluster_key}/namespace/{namespace}/services/{service_name}", api.getService())
		// endpoints
		r.Get("/endpoints", api.getEndpointsList())
		r.Get("/cluster/{cluster_key}/namespace/{namespace}/endpoints/{endpoints_name}", api.getEndpointsBase())
		r.Get("/endpoints/SubsetKinds", api.getEndpointSubsetKinds())
		r.Get("/endpoints/{endpoints_id}/subsets", api.getEndpointsSubsets())
		r.Get("/secrets", api.getSecrets())
		r.Get("/pvs", api.getPVs())
		r.Get("/pvcs", api.getPVCs())
		// ns's labels
		r.Get("/namespaceLabels", api.getNamespaceLabels())
		r.Post("/namespaceLabel", api.addNamespaceLabel())
		r.Put("/namespaceLabel/{label_id}", api.updateNamespaceLabel())
		r.Delete("/namespaceLabel/{label_id}", api.deleteNamespaceLabels())
		//服务识别
		r.Get("/busiServices", api.getBusiServices())
		r.Get("/busiServicesType", api.getBusiServicesType()) //应用类别
		r.Get("/busiServicesKind", api.getBusiServicesKind()) // 应用名称
		r.Get("/busiServices/db", api.getDbBusiServices())
		r.Get("/busiServices/web", api.getWebBusiServices())
		r.Get("/busiServices/startUser", api.getBusiStartUser())
		r.Get("/busiService/{id}", api.getBusiService())
		r.Get("/busiServiceWebKind", api.getBusiServiceWebKind())
		r.Get("/busiServiceDbKind", api.getBusiServiceDbKind())
		// 站点
		r.Get("/exposeHosts", api.getExposeHosts())
		r.Get("/exposeHost/{id}", api.getExposeHostDetail())
		// 监控
		r.Get("/monitor/total", api.getExposeHostDetail())
		r.Get("/monitor/detail/holms", api.getExposeHostDetail())
		r.Get("/monitor/detail/clusterManager", api.getExposeHostDetail())
		r.Get("/monitor/detail/scanner", api.getExposeHostDetail())
	}
}

func getNormalizedQueryParam(r *http.Request, key string) string {
	p, _ := param.QueryString(r, key)
	p = strings.TrimSpace(p)
	return p
}

func getNormalizedURLParam(r *http.Request, key string) string {
	p := chi.URLParam(r, key)
	p = strings.TrimSpace(p)
	return p
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
	ContainerID   uint32 `json:"containerID"`

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

	PodName string `json:"podName"`
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
		clusterMap := make(map[string]string) // clusterKey-->clusterName

		// KEY `idx_aprr_res` (`cluster_key`,`namespace`,`resource_kind`,`resource_name`),
		ret := make([]resourceContainer, len(containers))
		for i, cont := range containers {
			ret[i].Cluster = cont.ClusterKey
			ret[i].ClusterKey = cont.ClusterKey
			ret[i].Namespace = cont.Namespace
			ret[i].ContainerName = cont.ResourceName
			ret[i].Ports = cont.Ports
			ret[i].ResourceKind = cont.ResourceKind
			ret[i].ResourceName = cont.ResourceName
			ret[i].Type = cont.Type
			ret[i].ImageUUID = imageUUID

			imageRepo, imageName, imageTag := parseImage(cont.Image)
			ret[i].ImageRepo = imageRepo
			ret[i].ImageName = imageName
			ret[i].ImageTag = imageTag
			ret[i].Image = cont.Image
			if cont.Spec != nil {
				ret[i].WorkingDir = cont.Spec.WorkingDir
				ret[i].Command = cont.Spec.Command
			}
			clusterName := clusterMap[cont.ClusterKey]
			if clusterName != "" {
				ret[i].Cluster = clusterName
			} else {
				cluster := resSvc.GetClusterByKey(ctx, cont.ClusterKey)
				if cluster != nil {
					ret[i].Cluster = cluster.Name
					clusterMap[cont.ClusterKey] = cluster.Name
				}
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
				ret[i].PodName = pods[0].PodName
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
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no vulnName given in params")))
			return
		}

		pkgName, err := param.QueryString(r, "pkgName")
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no pkgName given in params")))
			return
		}

		pkgVersion, err := param.QueryString(r, "pkgVersion")
		if err != nil {
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
		Key           string   `json:"key"`
		Name          string   `json:"name"`
		PlatForm      string   `json:"platForm"`
		APIServerAddr string   `json:"apiServerAddr"`
		Description   string   `json:"description"`
		Version       string   `json:"version"`
		Creator       string   `json:"creator"`
		CreatedAt     int64    `json:"createdAt"`
		Updater       string   `json:"updater"`
		UpdatedAt     int64    `json:"updatedAt"`
		RuleVersion   string   `json:"ruleVersion"`
		NodeNumber    int64    `json:"nodeNumber"`
		Tags          []string `json:"tags"`
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
		query := dal.ClusterQuery()

		clusterKey, _ := param.QueryString(r, "key")
		clusterKey = strings.TrimSpace(clusterKey)
		if clusterKey != "" {
			query.WithKey(clusterKey)
		}
		name, _ := param.QueryString(r, "name")
		name = strings.TrimSpace(name)
		if name != "" {
			query.WithName(name)
		}
		apiServerAddr, _ := param.QueryString(r, "api_server_addr")
		apiServerAddr = strings.TrimSpace(apiServerAddr)
		if apiServerAddr != "" {
			query.WithAPIServerAddr(apiServerAddr)
		}
		version, _ := param.QueryString(r, "version")
		version = strings.TrimSpace(version)
		if version != "" {
			query.WithVersion(version)
		}
		clusterType, _ := param.QueryString(r, "cluster_type")
		if clusterType != "" {
			query.WithType(clusterType)
		}
		rulesVersion, _ := param.QueryString(r, "rules_version")
		if rulesVersion != "" {
			query.WithRulesVersion(rulesVersion)
		}
		platform, _ := param.QueryString(r, "platform")
		if platform != "" {
			query.WithPlatform(platform)
		}
		idList, _ := param.QueryString(r, "idList")
		if idList != "" {
			query.WithIdList(strings.Split(idList, ","))
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		clusters, totalCnt, err := resSvc.GetClusters(ctx, query, offset, limit)
		if err != nil {
			logging.Get().Err(err).Msg("get cluster error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get cluster error")))
			return
		}
		ret := make([]cluster, len(clusters))
		var clusterKeyList []string
		for i, c := range clusters {
			ret[i].Key = c.Key
			clusterKeyList = append(clusterKeyList, c.Key)
			ret[i].Description = c.Description
			ret[i].Name = c.Name
			ret[i].PlatForm = c.Platform
			ret[i].APIServerAddr = c.APIServerAddr
			ret[i].Version = c.Version
			ret[i].Creator = c.Creator
			ret[i].CreatedAt = c.CreatedAt.Unix()
			ret[i].UpdatedAt = c.UpdatedAt.Unix()
			ret[i].Updater = c.Updater
			ret[i].RuleVersion = c.RuleVersion

			nodeQuery := dal.NodeQuery()
			nodeQuery.WithCluster(c.Key)
			nodeQuery.WithStatus(0)
			nodeNum, _ := resSvc.CountNodes(ctx, nodeQuery)
			ret[i].NodeNumber = nodeNum
		}
		hideTags, _ := param.QueryBool(r, "hideTags") // 隐藏tag
		//isEnglish(r)
		if !hideTags {
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_cluster, clusterKeyList)
			if err != nil {
				logging.Get().Err(err).Msg("query cluster's tags failed")
				response.Ok(w, response.WithItems(ret), response.WithTotalItems(totalCnt))
				return
			}
			for i, tensorCluster := range ret {
				ret[i].Tags = tagsMapByAssetsIds[tensorCluster.Key]
				ret[i].Tags = append(ret[i].Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_cluster]...)
			}
		}

		response.Ok(w, response.WithItems(ret), response.WithTotalItems(totalCnt))
	}
}

func clusterApiAdaptorProcess(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var cluster model.TensorCluster

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		RespAndLog(w, ctx,
			NewAnError(http.StatusInternalServerError, errors.New("err read request body")))
		return
	}

	// process add cluster request
	err = json.Unmarshal(data, &cluster)
	if err == nil && cluster.APIServerAddr != "" {
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
		return
	}

	// process update cluster request
	type UpdateReq struct {
		ClusterKey  string `json:"cluster_key"`
		ClusterName string `json:"cluster_name"`
		Description string `json:"description"`
		RuleVersion string `json:"rule_version"`
	}

	var request UpdateReq
	err = json.Unmarshal(data, &request)
	if err == nil {
		err = resSvc.UpdateCluster(ctx, request.ClusterKey, request.ClusterName, request.Description, request.RuleVersion)
		if err != nil {
			logging.Get().Err(err).Msgf("update cluster error. data: %v", request)
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("update cluster error")))
			return
		}
		response.Ok(w, response.WithTarget(&response.TargetRef{
			Name: request.ClusterKey,
			ID:   "",
			Link: "/api/v2/platform/assets/cluster",
		}))
		return
	}

	RespAndLog(w, ctx, NewMalformedRequestError(http.StatusInternalServerError,
		fmt.Errorf("failed to decode json: %w", err)))
}

// @Summary
// @Description add a cluster https://tensorsecurity.feishu.cn/wiki/wikcnUMvm0NSivY9gDZJIlECSZg#
// @Produce json
// @Method POST
// @Router /api/v2/platform/assets/cluster
func (api *api) addNewCluster() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		clusterApiAdaptorProcess(ctx, w, r)
	}
}

// @Summary
// @Description update the info of a cluster https://tensorsecurity.feishu.cn/wiki/wikcnUMvm0NSivY9gDZJIlECSZg#
// @Produce json
// @Method PUT
// @Router /api/v2/platform/assets/cluster
func (api *api) updateClusterInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		clusterApiAdaptorProcess(ctx, w, r)
	}
}

// @Summary
// @Description delete the info of a cluster https://tensorsecurity.feishu.cn/wiki/wikcnUMvm0NSivY9gDZJIlECSZg#
// @Produce json
// @Method DELETE
// @Router /api/v2/platform/assets/cluster
func (api *api) deleteCluster() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		now := time.Now()
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

		defSvc, ok := defense.GetDefenseService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("defense instance get error")))
			return
		}
		err = defSvc.DeleteAllBaitServicesFromKube(ctx, clusterKey)
		if err != nil {
			logging.Get().Warn().Err(fmt.Errorf("delete bait services in cluster error: %v", err))
		}
		second := now.Sub(time.Now())
		logging.Get().Debug().Msgf("deleteCluster grpc api cost: %d ms", second.Milliseconds())
		err = resSvc.DeleteCluster(ctx, clusterKey)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, fmt.Errorf("delete cluster error: %v", err)))
			return
		}
		response.Ok(w, response.WithTarget(&response.TargetRef{
			Name: clusterKey,
			ID:   "",
			Link: "/api/v2/platform/assets/cluster",
		}))
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
			clusterKey = ""
		}
		name, err := param.QueryString(r, "name")
		if err != nil {
			name = ""
		}
		query := dal.NamespaceQuery()
		if clusterKey != "" {
			query.WithFuzzyCluster(clusterKey)
		}
		idList, _ := param.QueryString(r, "idList")
		if idList != "" {
			query.WithIdList(strings.Split(idList, ","))
		}
		if name != "" {
			query.WithFuzzyName(name)
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		namespaces, totalCnt, err := resSvc.GetNamespacesWithOption(ctx, query, offset, limit)
		if err != nil {
			logging.Get().Err(err).Msg("getNamespaces error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		hideTags, _ := param.QueryBool(r, "hideTags")
		var objIdList []string
		if !hideTags {
			for _, namespace := range namespaces {
				objIdList = append(objIdList, strconv.Itoa(int(namespace.ID)))
			}
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_namespace, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query namespace's tags failed")
				response.Ok(w, response.WithItems(namespaces),
					response.WithTotalItems(totalCnt),
					response.WithStartIndex(int64(offset+len(namespaces))),
				)
				return
			}
			for _, item := range namespaces {
				item.Tags = tagsMapByAssetsIds[strconv.Itoa(int(item.ID))]
				item.Tags = append(item.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_namespace]...)
			}
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
			clusterKey = ""
		}
		query, err := param.QueryString(r, "query")
		if err != nil {
			query = ""
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
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
		reasonOS, err := reasonStr2OSList(rm.Reason)
		if err != nil {
			logging.Get().Err(err).Msg("get resource reason os list failed")
		}
		r.Cluster = rm.ClusterKey
		r.Namespace = rm.Namespace
		r.Kind = rm.Kind
		r.Name = rm.Name
		r.UID = rm.UID
		r.Alias = rm.Alias
		r.Managers = rm.Managers
		r.Authority = rm.Authority
		r.IsSupportDrift = rm.IsSupportDrift
		r.Reason = reasonOS
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
			clusterKey = ""
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			namespace = ""
		}

		kind, err := param.QueryString(r, "kind")
		if err != nil {
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

type GetResourceFuzzy struct {
	Limit      int    `in:"query" name:"limit"`
	Offset     int    `in:"query" name:"offset"`
	ClusterKey string `in:"query" name:"cluster_key"`
	Namespace  string `in:"query" name:"namespace"`
	Kind       string `in:"query" name:"kind"`
	Query      string `in:"query" name:"query"`
	Name       string `in:"query" name:"name"`
	IdList     []string
	UseRedis   bool `in:"-"`
}

func (req *GetResourceFuzzy) Render(r *http.Request) error {
	limit, offset, err := getLimitAndOffset(r)
	if err != nil {
		return err
	}
	clusterKey, err := param.QueryString(r, "cluster_key")
	if err != nil {
		clusterKey = ""
	}

	namespace, err := param.QueryString(r, "namespace")
	if err != nil {
		namespace = ""
	}

	kind, err := param.QueryString(r, "kind")
	if err != nil {
		kind = ""
	}

	query, err := param.QueryString(r, "query")
	if err != nil {
		query = ""
	}

	name, err := param.QueryString(r, "name")
	if err != nil {
		query = ""
	}
	idList, _ := param.QueryString(r, "idList")
	if idList != "" {
		req.IdList = strings.Split(idList, ",")
	}

	req.Limit = limit
	req.Offset = offset
	req.ClusterKey = clusterKey
	req.Namespace = namespace
	req.Name = name
	req.Kind = kind
	req.Query = query
	return nil
}

func (req *GetResourceFuzzy) Execute(ctx context.Context) ([]*assets.TensorResourceView, int64, error) {
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, NewAnError(http.StatusInternalServerError, errors.New("service instance get error"))
	}

	rQuery := dal.ResourcesQuery()
	if req.ClusterKey != "" {
		rQuery = rQuery.WithCluster(req.ClusterKey)
	}
	if req.Namespace != "" {
		rQuery = rQuery.WithFuzzyNamespace(req.Namespace)
	}
	if req.Kind != "" && req.Kind != "_" {
		rQuery = rQuery.WithResourceKind(assetsPkg.ResourceKind(req.Kind))
	}
	if req.Query != "" {
		rQuery = rQuery.WithColumnQuery("name", req.Query)
	}
	if req.Name != "" {
		rQuery = rQuery.WithFuzzyName(req.Name)
	}
	if len(req.IdList) > 0 {
		rQuery = rQuery.WithIdList(req.IdList)
	}
	rQuery.WithUserAccount = true

	var (
		resources []*assets.TensorResourceView
		totalCnt  int64
		err       error
	)

	if req.UseRedis {
		resources, totalCnt, err = resSvc.GetResourceWithRedis(ctx, rQuery, req.Offset, req.Limit)
	} else {
		resources, totalCnt, err = resSvc.GetResourcesWithUserAccount(ctx, rQuery, req.Offset, req.Limit)
	}

	if err != nil {
		logging.Get().Err(err).Msgf("query: %+v. offset: %d, limit: %d. get resources error", rQuery, req.Offset, req.Limit)
		return nil, 0, err
	}

	return resources, totalCnt, nil
}

func (api *api) getResourcesFuzzy() http.HandlerFunc {
	type resource struct {
		ResourceID uint32                 `json:"resource_id"`
		Id         uint32                 `json:"id"`
		Cluster    string                 `json:"cluster"`
		Namespace  string                 `json:"namespace"`
		Kind       string                 `json:"kind"`
		Name       string                 `json:"name"`
		UID        string                 `json:"uid"`
		Alias      string                 `json:"alias"`
		Managers   []*dal.UserNameAccount `json:"managers"`
		Authority  string                 `json:"authority"`
		Tags       []string               `json:"tags"`
	}
	modelToResource := func(rm *assets.TensorResourceView) *resource {
		r := new(resource)
		r.Id = rm.ID
		r.Cluster = rm.ClusterKey
		r.Namespace = rm.Namespace
		r.Kind = rm.Kind
		r.Name = rm.Name
		r.UID = rm.UID
		r.Alias = rm.Alias
		r.Managers = rm.Managers
		r.Authority = rm.Authority
		r.ResourceID = rm.ID
		return r
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		req := &GetResourceFuzzy{UseRedis: true}
		if err := req.Render(r); err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("render req body failed")))
			return
		}
		resources, totalCnt, err := req.Execute(ctx)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		items := make([]*resource, len(resources))
		var objIdList []string
		for i, resource := range resources {
			items[i] = modelToResource(resource)
			objIdList = append(objIdList, strconv.Itoa(int(resource.ID)))
		}
		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_resource, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query resource's tags failed")
				response.Ok(w, response.WithItems(items), response.WithTotalItems(totalCnt), response.WithStartIndex(int64(req.Offset+len(items))))
				return
			}
			for _, item := range items {
				item.Tags = tagsMapByAssetsIds[strconv.Itoa(int(item.Id))]
				item.Tags = append(item.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_resource]...)
			}
		}

		response.Ok(w, response.WithItems(items), response.WithTotalItems(totalCnt), response.WithStartIndex(int64(req.Offset+len(items))))
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

type GetPods struct {
	Limit        int    `in:"query" name:"limit"`
	Offset       int    `in:"query" name:"offset"`
	ClusterKey   string `in:"query" name:"cluster_key"`
	Namespace    string `in:"query" name:"namespace"`
	NodeName     string `in:"query" name:"node_name"`
	ResourceKind string `in:"query" name:"resource_kind"`
	ResourceName string `in:"query" name:"resource_name"`
	Name         string `in:"query" name:"name"`
	PodIP        string `in:"query" name:"pod_ip"`
	Query        string `in:"query" name:"query"`
	IdList       []string
	StartTime    time.Time `in:"query" name:"start_time"`
	EndTime      time.Time `in:"query" name:"end_time"`
	UseRedis     bool      `in:"-"`
}

func (req *GetPods) Render(r *http.Request) error {
	limit, offset, err := getLimitAndOffset(r)
	if err != nil {
		return err
	}
	req.Limit = limit
	req.Offset = offset
	req.ClusterKey = getNormalizedQueryParam(r, "cluster_key")
	req.Namespace = getNormalizedQueryParam(r, "namespace")
	req.NodeName = getNormalizedQueryParam(r, "node_name")
	req.ResourceKind = getNormalizedQueryParam(r, "resource_kind")
	req.ResourceName = getNormalizedQueryParam(r, "resource_name")
	req.Name = getNormalizedQueryParam(r, "name")
	req.PodIP = getNormalizedQueryParam(r, "pod_ip")
	req.Query, _ = param.QueryString(r, "query")

	idList, _ := param.QueryString(r, "idList")
	if idList != "" {
		req.IdList = strings.Split(idList, ",")
	}
	var start, end time.Time
	startTime, _ := param.QueryString(r, "start_time")
	if startTime != "" {
		start, err = time.Parse(time.RFC3339, startTime)
		if err != nil {
			return err
		}
	}
	req.StartTime = start

	endTime, _ := param.QueryString(r, "end_time")
	if endTime != "" {
		end, err = time.Parse(time.RFC3339, endTime)
		if err != nil {
			return err
		}
	}

	req.EndTime = end
	return nil
}

type PodWithTags struct {
	*model.PodResourceRelation
	Tags []string
}

func (req *GetPods) Execute(ctx context.Context) ([]*model.PodResourceRelation, int64, error) {
	queryOpt := dal.ResourcePodssQuery()
	if req.ClusterKey != "" {
		queryOpt.WithCluster(req.ClusterKey)
	}
	if req.Namespace != "" {
		queryOpt.WithFuzzyNamespace(req.Namespace)
	}
	if req.NodeName != "" {
		queryOpt.WithNodeName(req.NodeName)
	}
	if req.ResourceKind != "" {
		queryOpt.WithResourceKind(assetsPkg.ResourceKind(req.ResourceKind))
	}
	if req.ResourceName != "" {
		queryOpt.WithFuzzyResourceName(req.ResourceName)
	}
	if req.Name != "" {
		queryOpt.WithFuzzyName(req.Name)
	}
	if req.PodIP != "" {
		queryOpt.WithFuzzyPodIP(req.PodIP)
	}
	if len(req.IdList) > 0 {
		queryOpt = queryOpt.WithIdList(req.IdList)
	}

	if req.Query != "" {
		queryOpt.WithMulColumnQuery([]string{"pod_name"}, req.Query)
	}
	queryOpt.WithTimeRange(req.StartTime, req.EndTime)

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, NewAnError(http.StatusInternalServerError, errors.New("get resource service err"))
	}

	var (
		pods []*model.PodResourceRelation
		cnt  int64
		err  error
	)

	if req.UseRedis {
		pods, cnt, err = resSvc.GetResourcePodsWithRedis(ctx, queryOpt, req.Offset, req.Limit)
	} else {
		pods, cnt, err = resSvc.GetResourcePods(ctx, queryOpt, req.Offset, req.Limit)
	}

	if err != nil {
		return nil, 0, NewAnError(http.StatusInternalServerError, fmt.Errorf("get resource pod err: %v", err))
	}
	return pods, cnt, nil

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

		req := &GetPods{UseRedis: true}
		err := req.Render(r)
		if err != nil {
			logging.Get().Err(err).Msgf("render GetPods body failed")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, err))
			return
		}
		pods, cnt, err := req.Execute(ctx)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, fmt.Errorf("get resource pod err: %v", err)))
			return
		}
		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			var objIdList []string
			for _, pod := range pods {
				objIdList = append(objIdList, strconv.Itoa(int(pod.ID)))
			}
			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_pod, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query pod's tags failed")
				response.Ok(w, response.WithItems(pods), response.WithTotalItems(cnt))
				return
			}
			var podWithT []*PodWithTags
			for _, item := range pods {
				tmp := PodWithTags{
					PodResourceRelation: item,
				}
				tmp.Tags = tagsMapByAssetsIds[strconv.Itoa(int(item.ID))]
				tmp.Tags = append(tmp.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_resource]...)
				podWithT = append(podWithT, &tmp)
			}
			response.Ok(w, response.WithItems(pods), response.WithTotalItems(cnt))
			return
		}
		response.Ok(w, response.WithItems(pods), response.WithTotalItems(cnt))
	}
}

type GetPodsByOwner struct {
	Limit        int    `in:"query" name:"limit"`
	Offset       int    `in:"query" name:"offset"`
	ClusterKey   string `in:"query" name:"cluster_key"`
	Namespace    string `in:"query" name:"namespace"`
	ResourceKind string `in:"query" name:"resource_kind"`
	ResourceName string `in:"query" name:"resource_name"`
	Query        string `in:"query" name:"query"`
	UseRedis     bool   `in:"-"`
}

func (req *GetPodsByOwner) Render(r *http.Request) error {
	limit, offset, err := getLimitAndOffset(r)
	if err != nil {
		return err
	}
	req.Limit = limit
	req.Offset = offset
	req.ClusterKey = getNormalizedQueryParam(r, "cluster_key")
	req.Namespace = getNormalizedQueryParam(r, "namespace")
	req.ResourceKind = getNormalizedQueryParam(r, "resource_kind")
	req.ResourceName = getNormalizedQueryParam(r, "resource_name")
	req.Query, _ = param.QueryString(r, "query")
	return nil
}
func (req *GetPodsByOwner) Execute(ctx context.Context) ([]*model.PodResourceRelation, int64, error) {
	query := dal.ResourcePodssQuery()
	if req.ClusterKey != "" {
		query.WithCluster(req.ClusterKey)
	}
	if req.Namespace != "" {
		query.WithNamespace(req.Namespace)
	}
	if req.ResourceKind != "" {
		query.WithResourceKind(assetsPkg.ResourceKind(req.ResourceKind))
	}
	if req.ResourceName != "" {
		query.WithResourceName(req.ResourceName)
	}
	if req.Query != "" {
		query.WithMulColumnQuery([]string{"pod_name"}, req.Query)
	}
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, NewAnError(http.StatusInternalServerError, errors.New("get resource service err"))
	}
	var (
		pods []*model.PodResourceRelation
		cnt  int64
		err  error
	)
	if req.UseRedis {
		pods, cnt, err = resSvc.GetResourcePodsWithRedis(ctx, query, req.Offset, req.Limit)
	} else {
		pods, cnt, err = resSvc.GetResourcePods(ctx, query, req.Offset, req.Limit)
	}

	return pods, cnt, err
}

func (api *api) getPodsByOwner() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelFunc()
		req := &GetPodsByOwner{UseRedis: true}
		err := req.Render(r)
		if err != nil {
			logging.Get().Err(err).Msgf("render GetPodsByOwner body failed")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, err))
			return
		}
		pods, cnt, err := req.Execute(ctx)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, fmt.Errorf("get resource pod by owner err: %v", err)))
			return
		}
		response.Ok(w, response.WithItems(pods), response.WithTotalItems(cnt))
	}
}

type PodsBySvcReq struct {
	Namespace  string
	ClusterKey string
	SvcName    string
	Query      string //pod_name
	Limit      int
	Offset     int
}

func (req *PodsBySvcReq) Render(r *http.Request) error {
	limit, offset, err := getLimitAndOffset(r)
	if err != nil {
		return err
	}
	req.Limit = limit
	req.Offset = offset
	req.ClusterKey = getNormalizedQueryParam(r, "cluster_key")
	req.Namespace = getNormalizedQueryParam(r, "namespace")
	req.SvcName = getNormalizedQueryParam(r, "svc_name")
	req.Query, _ = param.QueryString(r, "query")
	return nil
}

func (req *PodsBySvcReq) Execute(ctx context.Context) ([]*model.PodResourceRelation, int64, error) {

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, NewAnError(http.StatusInternalServerError, errors.New("get resource service err"))
	}
	var (
		pods []*model.PodResourceRelation
		cnt  int64
		err  error
	)
	r := assets.PodsBySvcReq{
		Namespace:  req.Namespace,
		ClusterKey: req.ClusterKey,
		SvcName:    req.SvcName,
		Query:      req.Query,
	}
	pods, cnt, err = resSvc.GetPodsBySvc(ctx, r, req.Offset, req.Limit)

	return pods, cnt, err
}

func (api *api) getPodsBySvc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelFunc()
		req := &PodsBySvcReq{}
		err := req.Render(r)
		if err != nil {
			logging.Get().Err(err).Msgf("render getPodsBySvc body failed")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, err))
			return
		}
		pods, cnt, err := req.Execute(ctx)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, fmt.Errorf("get resource pod by owner err: %v", err)))
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

		clusterKey, _ := param.QueryString(r, "cluster_key")
		if clusterKey != "" {
			queryOpt.WithCluster(clusterKey)
		}

		namespace, _ := param.QueryString(r, "namespace")
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

		clusterKey, _ := param.QueryString(r, "cluster_key")
		if clusterKey != "" {
			queryOpt.WithCluster(clusterKey)
		}

		namespace, _ := param.QueryString(r, "namespace")
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

type NodeWithTags struct {
	*model.TensorNode
	Tags []string `json:"tags"`
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

		clusterKey, _ := param.QueryString(r, "cluster_key")
		name, _ := param.QueryString(r, "name")
		nodeIP, _ := param.QueryString(r, "ip")
		idList, _ := param.QueryString(r, "idList")

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		queryOpt := dal.NodeQuery()
		if clusterKey != "" {
			queryOpt.WithCluster(clusterKey)
		}
		if name != "" {
			queryOpt.WithColumnFuzzyQuery("host_name", name)
		}
		if nodeIP != "" {
			queryOpt.WithColumnFuzzyQuery("node_ip", nodeIP)
		}
		if len(idList) > 0 {
			queryOpt.WithIdList(strings.Split(idList, ","))
		}
		status, err := param.QueryInt8(r, "status")
		if err == nil {
			switch status {
			case 0:
				queryOpt.WithStatus(0)
				queryOpt.WithReady(1)
			case 1:
				queryOpt.WithStatus(1)
			case 2:
				queryOpt.WithStatus(0)
				queryOpt.WithReady(0)
			default:
				logging.Get().Warn().Msgf("invalid status %d", status)
			}
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

		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			var objIdList []string
			for _, item := range nodes {
				objIdList = append(objIdList, strconv.Itoa(int(item.ID)))
			}
			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_node, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query ingress's tags failed")
				response.Ok(w, response.WithItems(nodes), response.WithTotalItems(totalCnt), response.WithStartIndex(int64(offset+len(nodes))))
				return
			}
			var withTags []*NodeWithTags
			for _, item := range nodes {
				tmp := &NodeWithTags{
					TensorNode: item,
				}
				tmp.Tags = tagsMapByAssetsIds[strconv.Itoa(int(item.ID))]
				tmp.Tags = append(tmp.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_node]...)
				withTags = append(withTags, tmp)
			}
			response.Ok(w, response.WithItems(withTags), response.WithTotalItems(totalCnt), response.WithStartIndex(int64(offset+len(nodes))))
			return
		}

		response.Ok(w, response.WithItems(nodes), response.WithTotalItems(totalCnt), response.WithStartIndex(int64(offset+len(nodes))))
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

func (api *api) GetPodAssociate() http.HandlerFunc {
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
		res, err := resSvc.GetPodRelation(arguments)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.Errorf("get resource relations failed, %v", err)))
			return
		}

		response.Ok(w, response.WithItems(res))
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

		namespace, _ := param.QueryString(r, "namespace")
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

// 查询rawContainer
func (api *api) getImageInfosV2() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		queryOpt := dal.ResourceContainersQuery()

		clusterKey, _ := param.QueryString(r, "cluster_key")
		if clusterKey != "" {
			queryOpt.WithCluster(clusterKey)
		}

		namespace, _ := param.QueryString(r, "namespace")
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
		//imageInfos, err := resSvc.GetImageInfosV2(ctx, queryOpt)
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
		problems := make(map[string]struct{})
		for _, i := range images {
			for _, q := range i.SecurityIssue {
				problems[q.Value] = struct{}{}
			}
		}

		var resp []string
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

type GetRawContainers struct {
	Limit          int      `in:"query" name:"limit"`
	Offset         int      `in:"query" name:"offset"`
	ClusterKey     string   `in:"query" name:"cluster_key"`
	NodeNames      []string `in:"query" name:"node_name"`
	Namespaces     []string `in:"query" name:"namespace"`
	PodNames       []string `in:"query" name:"pod_name"`
	ContainerNames []string `in:"query" name:"container_name"`
	K8sManaged     *bool    `in:"query" name:"k8s_managed"`
	Status         []int    `in:"query" name:"status"`
	ResourceNames  []string `in:"query" name:"resource_name"`
	UseRedis       bool     `in:"-"`
}

func (req *GetRawContainers) Render(r *http.Request) error {
	limit, offset, err := getLimitAndOffset(r)
	if err != nil {
		return errors.New("no limit or offset given in params")
	}
	req.Limit = limit
	req.Offset = offset

	req.ClusterKey, _ = param.QueryString(r, "cluster_key")
	req.NodeNames, _ = param.QueryStringArray(r, "node_name")
	req.Namespaces, _ = param.QueryStringArray(r, "namespace")
	req.PodNames, _ = param.QueryStringArray(r, "pod_name")
	req.ContainerNames, _ = param.QueryStringArray(r, "container_name")
	isK8sManaged, err := param.QueryBool(r, "k8s_managed")
	if err == nil {
		req.K8sManaged = &isK8sManaged
	}
	req.Status, _ = param.QueryIntArray(r, "status")
	req.ResourceNames, _ = param.QueryStringArray(r, "resource_name")
	return nil
}

func (req *GetRawContainers) Execute(ctx context.Context) ([]*model.TensorRawContainer, int64, error) {
	query := dal.RawContainersQuery()
	if req.K8sManaged != nil {
		query.WithK8sManaged(*req.K8sManaged)
	}
	if len(req.Status) > 0 {
		query.WithInConditionCustom("status", req.Status)
	}
	if req.ClusterKey != "" {
		query = query.WithCluster(req.ClusterKey)
	}
	if len(req.NodeNames) != 0 {
		query = query.WithColumnMultiQuery("node_name", req.NodeNames)
	}
	if len(req.Namespaces) != 0 {
		query = query.WithColumnMultiQuery("namespace", req.Namespaces)
	}
	if len(req.PodNames) != 0 {
		query = query.WithColumnMultiQuery("pod_name", req.PodNames)
	}
	if len(req.ContainerNames) != 0 {
		query = query.WithColumnMultiQuery("name", req.ContainerNames)
	}
	if len(req.ResourceNames) != 0 {
		query = query.WithColumnMultiQuery("resource_name", req.ResourceNames)
	}

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, errors.New("service instance get error")
	}

	var (
		containers []*model.TensorRawContainer
		totalCnt   int64
		err        error
	)

	if req.UseRedis {
		containers, totalCnt, err = resSvc.ListRawContainerWithRedis(ctx, query, req.Offset, req.Limit)
	} else {
		containers, totalCnt, err = resSvc.ListRawContainer(ctx, query, req.Offset, req.Limit)
	}

	return containers, totalCnt, err
}

func (api *api) getRawContainersWithFramework() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &GetRawContainersWithFramework{UseRedis: true}

		err := req.Render(r)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, err))
			return
		}
		containers, totalCnt, err := req.Execute(ctx)
		if err != nil {
			logging.Get().Err(err).Msg("get raw container error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			var objIdList []string
			for _, con := range containers {
				objIdList = append(objIdList, con.ContainerID)
			}

			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_container, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query resource's tags failed")
				response.Ok(w, response.WithItems(containers),
					response.WithTotalItems(totalCnt),
					response.WithStartIndex(int64(req.Offset+len(containers))),
				)
				return
			}
			for _, item := range containers {
				item.Tags = tagsMapByAssetsIds[item.ContainerID]
				item.Tags = append(item.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_container]...)
			}
		}

		response.Ok(w, response.WithItems(containers),
			response.WithTotalItems(totalCnt),
			response.WithStartIndex(int64(req.Offset+len(containers))),
		)
	}
}

type GetRawContainersWithFramework struct {
	Limit            int      `in:"query" name:"limit"`
	Offset           int      `in:"query" name:"offset"`
	ClusterKey       string   `in:"query" name:"cluster_key"`
	NodeNames        []string `in:"query" name:"node_name"`
	Namespaces       []string `in:"query" name:"namespace"`
	PodNames         []string `in:"query" name:"pod_name"`
	ContainerName    string   `in:"query" name:"container_name"`
	K8sManaged       *bool    `in:"query" name:"k8s_managed"`
	Status           []int    `in:"query" name:"status"`
	ResourceNames    []string `in:"query" name:"resource_name"`
	UseRedis         bool     `in:"-"`
	FrameworkName    string   `in:"query" name:"framework_name"`
	FrameworkVersion string   `in:"query" name:"framework_version"`
	ContainerIds     []string `in:"query" name:"container_ids"`
}

func (req *GetRawContainersWithFramework) Render(r *http.Request) error {
	limit, offset, err := getLimitAndOffset(r)
	if err != nil {
		return errors.New("no limit or offset given in params")
	}
	req.Limit = limit
	req.Offset = offset

	req.ClusterKey, _ = param.QueryString(r, "cluster_key")
	req.FrameworkName, _ = param.QueryString(r, "framework_name")
	req.FrameworkVersion, _ = param.QueryString(r, "framework_version")
	req.NodeNames, _ = param.QueryStringArray(r, "node_name")
	req.Namespaces, _ = param.QueryStringArray(r, "namespace")
	req.PodNames, _ = param.QueryStringArray(r, "pod_name")
	req.ContainerName, _ = param.QueryString(r, "container_name")
	isK8sManaged, err := param.QueryBool(r, "k8s_managed")
	if err == nil {
		req.K8sManaged = &isK8sManaged
	}
	req.Status, _ = param.QueryIntArray(r, "status")
	req.ResourceNames, _ = param.QueryStringArray(r, "resource_name")
	containerIds, _ := param.QueryString(r, "container_ids")
	if len(containerIds) > 0 {
		req.ContainerIds = strings.Split(containerIds, ",")
	}
	return nil
}

func (req *GetRawContainersWithFramework) Execute(ctx context.Context) ([]*dal.RawContainerWithFrameworkStr, int64, error) {
	query := dal.RawContainersWithFrameworkQuery()
	if req.K8sManaged != nil {
		query.WithK8sManaged(*req.K8sManaged)
	}
	if len(req.Status) > 0 {
		query.WithInConditionCustom("ivan_assets_raw_containers.status", req.Status)
	}
	if req.ClusterKey != "" {
		query.WithCluster(req.ClusterKey)
	}
	if len(req.NodeNames) != 0 {
		query.WithColumnMultiQuery("node_name", req.NodeNames)
	}
	if len(req.Namespaces) != 0 {
		query.WithColumnMultiQuery("namespace", req.Namespaces)
	}
	if len(req.PodNames) != 0 {
		query.WithColumnMultiQuery("pod_name", req.PodNames)
	}
	if len(req.ContainerIds) != 0 {
		query.WithInConditionCustom("id", req.ContainerIds)
	}
	if len(req.ContainerName) != 0 {
		query.WithColumnQuery("name", req.ContainerName)
	}
	if len(req.ResourceNames) != 0 {
		query.WithColumnMultiQuery("resource_name", req.ResourceNames)
	}

	// framewrok
	if len(req.FrameworkName) != 0 {
		query.WhereFrameworkLikeCondition["framework_name"] = req.FrameworkName
	}
	if len(req.FrameworkVersion) != 0 {
		query.WhereFrameworkLikeCondition["framework_version"] = req.FrameworkVersion
	}

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, errors.New("service instance get error")
	}

	var (
		containers []*dal.RawContainerWithFrameworkStr
		totalCnt   int64
		err        error
	)
	if req.UseRedis {
		containers, totalCnt, err = resSvc.ListRawContainerWithFrameworkWithRedis(ctx, query, req.Offset, req.Limit)
	} else {
		containers, totalCnt, err = resSvc.ListRawContainerWithFramework(ctx, query, req.Offset, req.Limit)
	}

	return containers, totalCnt, err
}

type GetRawContainersByPod struct {
	ClusterKey   string `in:"query" name:"cluster_key"`
	Namespace    string `in:"query" name:"namespace"`
	PodName      string `in:"query" name:"pod_name"`
	Status       []int  `in:"query" name:"status"`
	ResourceName string `in:"query" name:"resource_name"`
	Limit        int    `in:"query" name:"limit"`
	Offset       int    `in:"query" name:"offset"`
}

func (req *GetRawContainersByPod) Render(r *http.Request) error {
	limit, offset, err := getLimitAndOffset(r)
	if err != nil {
		return errors.New("no limit or offset given in params")
	}
	req.Limit = limit
	req.Offset = offset
	req.ClusterKey, _ = param.QueryString(r, "cluster_key")
	req.Namespace, _ = param.QueryString(r, "namespace")
	req.PodName, _ = param.QueryString(r, "pod_name")
	req.Status, _ = param.QueryIntArray(r, "status")
	req.ResourceName, _ = param.QueryString(r, "resource_name")
	return nil
}
func (req *GetRawContainersByPod) Execute(ctx context.Context) ([]*model.TensorRawContainer, int64, error) {
	query := dal.RawContainersQuery()
	if len(req.Status) > 0 {
		query.WithInConditionCustom("status", req.Status)
	}
	if req.ClusterKey != "" {
		query = query.WithCluster(req.ClusterKey)
	}
	if req.Namespace != "" {
		query = query.WithNamespace(req.Namespace)
	}
	if req.PodName != "" {
		query = query.WithPodName(req.PodName)
	}
	if req.ResourceName != "" {
		query = query.WithResourceName(req.ResourceName)
	}

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, errors.New("service instance get error")
	}

	var (
		containers []*model.TensorRawContainer
		totalCnt   int64
		err        error
	)

	containers, totalCnt, err = resSvc.ListRawContainer(ctx, query, req.Offset, req.Limit)
	return containers, totalCnt, err
}

func (api *api) getRawContainersByPod() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &GetRawContainersByPod{}

		err := req.Render(r)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, err))
			return
		}
		containers, totalCnt, err := req.Execute(ctx)
		if err != nil {
			logging.Get().Err(err).Msg("get raw container error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w, response.WithItems(containers),
			response.WithTotalItems(totalCnt),
			response.WithStartIndex(int64(req.Offset+len(containers))),
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
			//RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("param:cluster_key is empty")))
			//return
		}
		containerID := chi.URLParam(r, "containerID")
		containerIdIsPrefix := len(containerID) == 12
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		contain, err := resSvc.GetRawContainerWithFramework(ctx, clusterKey, containerID, containerIdIsPrefix)
		if err != nil {
			logging.Get().Err(err).Msgf("get raw container error.")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, func(ev *response.HTTPEnvelope) {
			data, err := json.Marshal(contain)
			if err != nil {
				ev.EnvelopeError = fmt.Sprintf("Failed to marshal item to json: %v", err)
			} else {
				ev.Data.Item = data
			}
		})
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
		//  添加status条件
		query.WithInConditionCustom("status", []int{assetsPkg.Running, assetsPkg.Created})

		totalCnt, err := resSvc.CountRawContainer(ctx, query)
		if err != nil {
			logging.Get().Err(err).Msg("count raw container error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItem(countResp{Count: totalCnt}))
	}
}

func (api *api) getRuleVersion() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

		ruleVersions, cnt, err := resSvc.GetRuleVersions(ctx, offset, limit)
		if err != nil {
			logging.Get().Err(err).Msg("get rule versions error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(ruleVersions), response.WithTotalItems(cnt))
	}
}

// @Summary
// @Description get detail of namespace in given cluster
// @Produce json
// @Method GET
// @Router /api/v2/platform/assets/cluster/{cluster_key}/namespaces/{name}
func (api *api) getNamespace() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		clusterKey := getNormalizedURLParam(r, "cluster_key")
		name := getNormalizedURLParam(r, "name")

		if clusterKey == "" || name == "" {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid cluster or name for namespace")))
			return
		}

		query := dal.NamespaceQuery()
		query.WithCluster(clusterKey)
		query.WithName(name)
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		namespaces, _, err := resSvc.GetNamespacesWithOption(ctx, query, 0, 1)
		if err != nil {
			logging.Get().Err(err).Msg("getNamespaces error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		var ns *assets.NamespaceView
		if len(namespaces) > 0 {
			ns = namespaces[0]
		}
		response.Ok(w, func(ev *response.HTTPEnvelope) {
			data, err := json.Marshal(ns)
			if err != nil {
				ev.EnvelopeError = fmt.Sprintf("Failed to marshal item to json: %v", err)
			} else {
				ev.Data.Item = data
			}
		})
	}
}

// @Summary
// @Description get detail of one resource(workload)
// @Produce json
// @Method GET
// @Router /api/v2/platform/assets/cluster/{cluster_key}/namespace/{namespace}/kind/{kind}/resources/{name}
func (api *api) getResource() http.HandlerFunc {
	type resource struct {
		ResourceID  uint32    `json:"resource_id"`
		Cluster     string    `json:"cluster"`
		Namespace   string    `json:"namespace"`
		Kind        string    `json:"kind"`
		Name        string    `json:"name"`
		UID         string    `json:"uid"`
		Alias       string    `json:"alias"`
		Managers    []string  `json:"managers"`
		Authority   string    `json:"authority"`
		CreatedTime time.Time `json:"createdTime"`
	}
	modelToResource := func(rm *model.TensorResource) *resource {
		r := new(resource)
		r.ResourceID = rm.ID
		r.Cluster = rm.ClusterKey
		r.Namespace = rm.Namespace
		r.Kind = rm.Kind
		r.Name = rm.Name
		r.UID = rm.UID
		r.Alias = rm.Alias
		r.Managers = rm.Managers
		r.Authority = rm.Authority
		r.CreatedTime = rm.CreatedAt
		return r
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		clusterKey := getNormalizedURLParam(r, "cluster_key")
		namespace := getNormalizedURLParam(r, "namespace")
		kind := getNormalizedURLParam(r, "kind")
		name := getNormalizedURLParam(r, "name")
		if clusterKey == "" || namespace == "" || kind == "" || name == "" {
			RespAndLog(w, ctx, NewAnError(http.StatusNotFound, errors.New("invalid params for resource")))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		rQuery := dal.ResourcesQuery()
		rQuery = rQuery.WithCluster(clusterKey)
		rQuery = rQuery.WithNamespace(namespace)
		rQuery = rQuery.WithResourceKind(assetsPkg.ResourceKind(kind))
		rQuery = rQuery.WithResourceName(name)

		resources, _, err := resSvc.GetResources(ctx, rQuery, 0, 1)
		if err != nil {
			logging.Get().Err(err).Msgf("query: %+v. offset: %d, limit: %d. get resources error", rQuery, 0, 1)
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resources error")))
			return
		}

		var item *resource
		if len(resources) > 0 {
			item = modelToResource(resources[0])
		}
		response.Ok(w, func(ev *response.HTTPEnvelope) {
			data, err := json.Marshal(item)
			if err != nil {
				ev.EnvelopeError = fmt.Sprintf("Failed to marshal item to json: %v", err)
			} else {
				ev.Data.Item = data
			}
		})
	}
}

// @Summary
// @Description get detail of one pod
// @Produce json
// @Method GET
// @Router /api/v2/platform/assets/cluster/{cluster_key}/namespace/{namespace}/pods/{name}
func (api *api) getPod() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		queryOpt := dal.ResourcePodssQuery()
		clusterKey := getNormalizedURLParam(r, "cluster_key")
		namespace := getNormalizedURLParam(r, "namespace")
		name := getNormalizedURLParam(r, "name")
		if clusterKey == "" || namespace == "" || name == "" {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid params for pod")))
			return
		}

		queryOpt.WithCluster(clusterKey)
		queryOpt.WithNamespace(namespace)
		queryOpt.WithName(name)

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get resource service err")))
			return
		}

		pods, _, err := resSvc.GetResourcePods(ctx, queryOpt, 0, 1)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, fmt.Errorf("get resource pod err: %v", err)))
			return
		}
		var pod *model.PodResourceRelation
		if len(pods) > 0 {
			pod = pods[0]
		}
		response.Ok(w, func(ev *response.HTTPEnvelope) {
			data, err := json.Marshal(pod)
			if err != nil {
				ev.EnvelopeError = fmt.Sprintf("Failed to marshal item to json: %v", err)
			} else {
				ev.Data.Item = data
			}
		})
	}
}

// @Summary
// @Description get detail of one node
// @Produce json
// @Method GET
// @Router /api/v2/platform/assets/cluster/{cluster_key}/nodes/{name}
func (api *api) getNode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		clusterKey := chi.URLParam(r, "cluster_key")
		name := chi.URLParam(r, "name")
		if clusterKey == "" || name == "" {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		queryOpt := dal.NodeQuery()
		queryOpt.WithCluster(clusterKey)
		queryOpt.WithNodeName(name)

		nodes, err := resSvc.GetNodes(ctx, queryOpt, 0, 1)
		if err != nil {
			logging.Get().Err(err).Msg("getNodes error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		var node *model.TensorNode
		if len(nodes) > 0 {
			node = nodes[0]
		}
		response.Ok(w, func(ev *response.HTTPEnvelope) {
			data, err := json.Marshal(node)
			if err != nil {
				ev.EnvelopeError = fmt.Sprintf("Failed to marshal item to json: %v", err)
			} else {
				ev.Data.Item = data
			}
		})
	}
}

type NodeDetail struct {
	*model.TensorNode
	*assets.NodeExtraCount
}

func (api *api) getNodeWithCount() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		clusterKey := chi.URLParam(r, "cluster_key")
		name := chi.URLParam(r, "name")
		if clusterKey == "" || name == "" {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		queryOpt := dal.NodeQuery()
		queryOpt.WithCluster(clusterKey)
		queryOpt.WithNodeName(name)

		nodes, err := resSvc.GetNodes(ctx, queryOpt, 0, 1)
		if err != nil {
			logging.Get().Err(err).Msg("getNodes error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		var detail NodeDetail
		if len(nodes) > 0 {
			detail.TensorNode = nodes[0]
			detail.NodeExtraCount = resSvc.GetNodeCount(ctx, clusterKey, name, detail.TensorNode.NodeIP)
		}

		response.Ok(w, func(ev *response.HTTPEnvelope) {
			data, err := json.Marshal(detail)
			if err != nil {
				ev.EnvelopeError = fmt.Sprintf("Failed to marshal item to json: %v", err)
			} else {
				ev.Data.Item = data
			}
		})
	}
}

func (api *api) getApplications() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		appType, _ := param.QueryString(r, "app_type")
		if appType == "" {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid app type param")))
			return
		}

		clusterKey, _ := param.QueryString(r, "cluster_key")
		targetName, _ := param.QueryString(r, "app_target")
		version, _ := param.QueryString(r, "app_version")
		resName, _ := param.QueryString(r, "resource_name")

		query := dal.AppQuery()
		query.WithAppType(appType)
		if clusterKey != "" {
			query.WithCluster(clusterKey)
		}
		if targetName != "" {
			query.WithApaTargetName(targetName)
		}
		if version != "" {
			query.WithAppTargetVer(version)
		}
		if resName != "" {
			query.WithFuzzyResourceName(resName)
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		apps, totalCnt, err := resSvc.GetAppWithType(ctx, query, offset, limit)
		if err != nil {
			logging.Get().Err(err).Msg("count raw container error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(apps),
			response.WithTotalItems(totalCnt),
			response.WithStartIndex(int64(offset+len(apps))),
		)
	}
}

func (api *api) countApplications() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		appType, _ := param.QueryString(r, "app_type")
		if appType == "" {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid app type param")))
			return
		}

		clusterKey, _ := param.QueryString(r, "cluster_key")
		targetName, _ := param.QueryString(r, "app_target")
		version, _ := param.QueryString(r, "app_version")
		resName, _ := param.QueryString(r, "resource_name")

		query := dal.AppQuery()
		query.WithAppType(appType)
		if clusterKey != "" {
			query.WithCluster(clusterKey)
		}
		if targetName != "" {
			query.WithApaTargetName(targetName)
		}
		if version != "" {
			query.WithAppTargetVer(version)
		}
		if resName != "" {
			query.WithFuzzyResourceName(resName)
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		totalCnt, err := resSvc.CountAppWithType(ctx, query)
		if err != nil {
			logging.Get().Err(err).Msg("count raw container error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItem(&countResp{Count: totalCnt}))
	}
}

func (api *api) getApplicationTypes() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		clusterKey, _ := param.QueryString(r, "cluster_key")
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		appTypes, err := resSvc.GetAppTypes(ctx, clusterKey)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, fmt.Errorf(" get app types error: %v", err)))
			return
		}
		response.Ok(w, response.WithItems(appTypes), response.WithTotalItems(int64(len(appTypes))))
	}
}

func (api *api) getApplicationVersions() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		clusterKey, _ := param.QueryString(r, "cluster_key")
		appType, _ := param.QueryString(r, "app_type")

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		appVersions, err := resSvc.GetAppVersions(ctx, clusterKey, appType)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, fmt.Errorf(" get app versions error: %v", err)))
			return
		}
		response.Ok(w, response.WithItems(appVersions), response.WithTotalItems(int64(len(appVersions))))
	}
}

func (api *api) getApplicationTargets() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		clusterKey, _ := param.QueryString(r, "cluster_key")
		appType, _ := param.QueryString(r, "app_type")

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		appTargets, err := resSvc.GetAppTargets(ctx, clusterKey, appType)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, fmt.Errorf(" get app versions error: %v", err)))
			return
		}
		response.Ok(w, response.WithItems(appTargets), response.WithTotalItems(int64(len(appTargets))))
	}
}

type GetIngresses struct {
	ingressName string
	namespace   string
	clusterKey  string
	idList      []string
	start       time.Time
	end         time.Time
	limit       int
	offset      int
}

func (req *GetIngresses) Render(r *http.Request) error {
	req.limit, req.offset = getLimitAndOffsetWithDefault(r)
	req.ingressName = getNormalizedQueryParam(r, "name")
	req.clusterKey = getNormalizedQueryParam(r, "cluster_key")
	req.namespace = getNormalizedQueryParam(r, "namespace")
	idList, _ := param.QueryString(r, "idList")
	if idList != "" {
		req.idList = strings.Split(idList, ",")
	}
	var start, end time.Time
	var err error
	startTime, _ := param.QueryString(r, "start_time")
	if startTime != "" {
		start, err = time.Parse(time.RFC3339, startTime)
		if err != nil {
			logging.Get().Err(err).Msgf("parse start_time failed")
			return err
		}
	}
	endTime, _ := param.QueryString(r, "end_time")
	if endTime != "" {
		end, err = time.Parse(time.RFC3339, endTime)
		if err != nil {
			logging.Get().Err(err).Msgf(" parse end_time failed")
			return err
		}
	}
	req.start = start
	req.end = end
	return nil
}

func (req *GetIngresses) Execute(ctx context.Context) ([]*model.TensorIngress, int64, error) {
	queryOpt := dal.IngressesQuery()

	if req.ingressName != "" {
		queryOpt.WithFuzzName(req.ingressName)
	}
	if req.clusterKey != "" {
		split := strings.Split(req.clusterKey, ",")
		queryOpt.WithClusterList(split)
	}
	if req.namespace != "" {
		queryOpt.WithFuzzNamespace(req.namespace)
	}
	if len(req.idList) > 0 {
		queryOpt.WithIdList(req.idList)
	}
	queryOpt.WithTimeRange(req.start, req.end)
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, errors.New("service instance get error")
	}
	return resSvc.ListIngress(ctx, queryOpt, req.offset, req.limit)
}

type IngressWithTags struct {
	*model.TensorIngress
	Tags []string `json:"tags"`
}

// ingress 列表
func (api *api) getIngresses() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &GetIngresses{}
		err := req.Render(r)
		if err != nil {
			logging.Get().Err(err).Msg("parse req failed.")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, err))
			return
		}
		ingresses, total, err := req.Execute(ctx)

		if err != nil {
			logging.Get().Err(err).Msg("get Ingresses error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			var objIdList []string
			for _, item := range ingresses {
				objIdList = append(objIdList, strconv.Itoa(int(item.ID)))
			}
			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_endpoints, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query ingress's tags failed")
				response.Ok(w, response.WithItems(ingresses), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(ingresses))))
				return
			}
			var withTags []*IngressWithTags
			for _, item := range ingresses {
				tmp := &IngressWithTags{
					TensorIngress: item,
				}
				tmp.Tags = tagsMapByAssetsIds[strconv.Itoa(int(item.ID))]
				tmp.Tags = append(tmp.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_endpoints]...)
				withTags = append(withTags, tmp)
			}
			response.Ok(w, response.WithItems(withTags), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(ingresses))))
			return
		}

		response.Ok(w, response.WithItems(ingresses), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(ingresses))))
	}
}

func (api *api) getIngressBase() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		query := dal.IngressesQuery()
		query.WithCluster(chi.URLParam(r, "cluster_key"))
		query.WithNamespace(chi.URLParam(r, "namespace"))
		query.WithName(chi.URLParam(r, "ingress_name"))

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}
		ingress, err := resSvc.GetIngressBase(ctx, query, 0, 1)

		if err != nil {
			logging.Get().Err(err).Msgf("get ingress error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		ing := &model.TensorIngress{}
		if len(ingress) > 0 {
			ing = ingress[0]
		}
		response.Ok(w, func(ev *response.HTTPEnvelope) {
			data, err := json.Marshal(ing)
			if err != nil {
				ev.EnvelopeError = fmt.Sprintf("Failed to marshal item to json: %v", err)
			} else {
				ev.Data.Item = data
			}
		})
	}

}

func (api *api) getIngressBackendKinds() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		//ingressId := chi.URLParam(r, "ingress_id")
		//ingId, err := strconv.ParseInt(ingressId, 10, 64)
		//if err != nil {
		//	RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("parse ingress_id failed."+ingressId)))
		//	return
		//}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}

		kinds, err := resSvc.GetIngressBackendKinds(ctx)
		if err != nil {
			logging.Get().Err(err).Msgf("get IngressBackendKinds  error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(kinds))
	}
}

type GetIngressRulesReq struct {
	ingressId   int64
	query       string
	backendKind string
	pathType    string
	offset      int
	limit       int
}

func (g *GetIngressRulesReq) Render(r *http.Request) error {
	ingressId := chi.URLParam(r, "ingress_id")
	ingId, err := strconv.ParseInt(ingressId, 10, 64)
	if err != nil {
		return err
	}
	g.ingressId = ingId
	g.backendKind = getNormalizedQueryParam(r, "backendKind")
	g.pathType = getNormalizedQueryParam(r, "pathType")
	g.query = getNormalizedQueryParam(r, "query")
	g.limit, g.offset = getLimitAndOffsetWithDefault(r)
	return nil
}

func (api *api) getIngressRules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &GetIngressRulesReq{}
		err := req.Render(r)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("parse req failed.")))
			return
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}

		opt := dal.NewIngressesRuleQuery()
		opt.WithIngressId(req.ingressId)
		if req.query != "" {
			opt.WithQuery(req.query, []string{"host", "backend_name"})
		}
		if req.backendKind != "" {
			kinds := strings.Split(req.backendKind, ",")
			opt.WithBackendKind(kinds)
		}
		if req.pathType != "" {
			types := strings.Split(req.pathType, ",")
			opt.WithPathType(types)
		}

		ingressRules, total, err := resSvc.ListIngressRule(ctx, opt, req.offset, req.limit)
		if err != nil {
			logging.Get().Err(err).Msg("get Ingresses Rules error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w, response.WithItems(ingressRules),
			response.WithTotalItems(total),
			response.WithStartIndex(int64(req.offset+len(ingressRules))),
		)

	}
}

// service
type GetServicesReq struct {
	name        string
	namespace   string
	clusterIp   string
	serviceType string
	clusterKey  string
	idList      []string
	start       time.Time
	end         time.Time
	limit       int
	offset      int
}

func (req *GetServicesReq) Render(r *http.Request) error {
	req.limit, req.offset = getLimitAndOffsetWithDefault(r)
	req.name = getNormalizedQueryParam(r, "name")
	req.clusterKey = getNormalizedQueryParam(r, "cluster_key")
	req.namespace = getNormalizedQueryParam(r, "namespace")
	req.clusterIp = getNormalizedQueryParam(r, "ip")
	req.serviceType = getNormalizedQueryParam(r, "type")
	idList, _ := param.QueryString(r, "idList")
	if idList != "" {
		req.idList = strings.Split(idList, ",")
	}
	var start, end time.Time
	var err error
	startTime, _ := param.QueryString(r, "start_time")
	if startTime != "" {
		start, err = time.Parse(time.RFC3339, startTime)
		if err != nil {
			logging.Get().Err(err).Msgf("parse start_time failed")
			return err
		}
	}
	endTime, _ := param.QueryString(r, "end_time")
	if endTime != "" {
		end, err = time.Parse(time.RFC3339, endTime)
		if err != nil {
			logging.Get().Err(err).Msgf(" parse end_time failed")
			return err
		}
	}
	req.start = start
	req.end = end
	return nil
}

type ServiceWithTags struct {
	*model.TensorService
	Tags []string `json:"tags"`
}

func (req *GetServicesReq) Execute(ctx context.Context) ([]*model.TensorService, int64, error) {

	queryOpt := dal.ServicesQuery()

	if req.name != "" {
		queryOpt.WithFuzzName(req.name)
	}
	if req.clusterKey != "" {
		split := strings.Split(req.clusterKey, ",")
		queryOpt.WithClusterList(split)
	}
	if req.namespace != "" {
		queryOpt.WithFuzzNamespace(req.namespace)
	}
	if req.clusterIp != "" {
		queryOpt.WithClusterIp(req.clusterIp)
	}
	if req.serviceType != "" {
		types := strings.Split(req.serviceType, ",")
		queryOpt.WithServiceTypes(types)
	}
	if len(req.idList) > 0 {
		queryOpt.WithIdList(req.idList)
	}
	queryOpt.WithTimeRange(req.start, req.end)
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, errors.New("service instance get error")
	}
	return resSvc.ListService(ctx, queryOpt, req.offset, req.limit)
}

func (api *api) getServices() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &GetServicesReq{}
		err := req.Render(r)
		if err != nil {
			logging.Get().Err(err).Msg("parse req failed.")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, err))
			return
		}
		services, total, err := req.Execute(ctx)
		if err != nil {
			logging.Get().Err(err).Msg("get service error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			var objIdList []string
			for _, service := range services {
				objIdList = append(objIdList, strconv.Itoa(int(service.ID)))
			}
			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_service, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query service's tags failed")
				response.Ok(w, response.WithItems(services), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(services))))
				return
			}
			var serviceWithT []*ServiceWithTags
			for _, item := range services {
				tmp := &ServiceWithTags{
					TensorService: item,
				}
				tmp.Tags = tagsMapByAssetsIds[strconv.Itoa(int(item.ID))]
				tmp.Tags = append(tmp.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_service]...)
				serviceWithT = append(serviceWithT, tmp)
			}
			response.Ok(w, response.WithItems(serviceWithT), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(services))))
			return
		}

		response.Ok(w, response.WithItems(services),
			response.WithTotalItems(total),
			response.WithStartIndex(int64(req.offset+len(services))),
		)
	}
}

type ServiceDetail struct {
	ID         uint32                 `json:"id,omitempty"`
	CreatedAt  time.Time              `json:"CreatedAt,omitempty"`
	UpdatedAt  time.Time              `json:"UpdatedAt,omitempty"`
	Status     int32                  `json:"Status,omitempty"`
	Name       string                 `json:"name"`
	Namespace  string                 `json:"namespace"`
	ClusterKey string                 `json:"clusterKey"`
	UID        string                 `json:"uid"`
	Labels     []Label                `json:"labels"`
	Type       string                 `json:"type"`
	ClusterIp  string                 `json:"clusterIp"`
	PortsStr   string                 `json:"portsStr"`
	Ports      model.ServicePortSlice `json:"ports"`
}
type Label struct {
	LabelName  string
	LabelValue string
}

func (api *api) getService() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		queryOpt := dal.ServicesQuery()

		queryOpt.WithCluster(chi.URLParam(r, "cluster_key"))
		queryOpt.WithNamespace(chi.URLParam(r, "namespace"))
		queryOpt.WithName(chi.URLParam(r, "service_name"))

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.Get().Error().Msg("get resSvc failed.")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get service instence failed.")))
			return
		}

		service, err := resSvc.GetService(ctx, queryOpt, 0, 1)
		if err != nil {
			logging.Get().Err(err).Msg("get service error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		svc := &model.TensorService{}
		finalSvc := &ServiceDetail{}
		if len(service) > 0 {
			svc = service[0]
		}
		// 转换labels格式，前端要求
		err = copier.Copy(finalSvc, svc)
		if err != nil {
			logging.Get().Err(err).Msg("copier failed.")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		for key, v := range svc.Labels {
			finalSvc.Labels = append(finalSvc.Labels, Label{
				LabelName:  key,
				LabelValue: v,
			})
		}
		response.Ok(w, func(ev *response.HTTPEnvelope) {
			data, err := json.Marshal(finalSvc)
			if err != nil {
				ev.EnvelopeError = fmt.Sprintf("Failed to marshal item to json: %v", err)
			} else {
				ev.Data.Item = data
			}
		})
	}
}

// endpoints
type GetEndpoints struct {
	endpointsName string
	serviceName   string
	namespace     string
	clusterKey    string
	idList        []string
	start         time.Time
	end           time.Time
	limit         int
	offset        int
}

func (req *GetEndpoints) Render(r *http.Request) error {
	req.limit, req.offset = getLimitAndOffsetWithDefault(r)
	req.endpointsName = getNormalizedQueryParam(r, "endpoints_name")
	req.serviceName = getNormalizedQueryParam(r, "service_name")
	req.clusterKey = getNormalizedQueryParam(r, "cluster_key")
	req.namespace = getNormalizedQueryParam(r, "namespace")
	idList, _ := param.QueryString(r, "idList")
	if idList != "" {
		req.idList = strings.Split(idList, ",")
	}
	var start, end time.Time
	var err error
	startTime, _ := param.QueryString(r, "start_time")
	if startTime != "" {
		start, err = time.Parse(time.RFC3339, startTime)
		if err != nil {
			logging.Get().Err(err).Msgf("parse start_time failed")
			return err
		}
	}
	endTime, _ := param.QueryString(r, "end_time")
	if endTime != "" {
		end, err = time.Parse(time.RFC3339, endTime)
		if err != nil {
			logging.Get().Err(err).Msgf(" parse end_time failed")
			return err
		}
	}
	req.start = start
	req.end = end
	return nil
}

func (req *GetEndpoints) Execute(ctx context.Context) ([]*model.TensorEndpoints, int64, error) {
	queryOpt := dal.EndpointsQuery()
	if req.endpointsName != "" {
		queryOpt.WhereLikeCondition["name"] = req.endpointsName
	}
	if req.serviceName != "" {
		queryOpt.WhereLikeCondition["service_name"] = req.serviceName
	}
	if req.clusterKey != "" {
		split := strings.Split(req.clusterKey, ",")
		queryOpt.WhereInCondition["cluster_key"] = split
	}
	if req.namespace != "" {
		queryOpt.WhereLikeCondition["namespace"] = req.namespace
	}
	if len(req.idList) > 0 {
		queryOpt.WhereInCondition["id"] = req.idList
	}
	queryOpt.WithTimeRange(req.start, req.end)
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, errors.New("service instance get error")
	}
	return resSvc.ListEndpoint(ctx, queryOpt, req.offset, req.limit)
}

type EndpointsWithTags struct {
	*model.TensorEndpoints
	Tags []string `json:"tags"`
}

// endpoints 列表
func (api *api) getEndpointsList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &GetEndpoints{}
		err := req.Render(r)
		if err != nil {
			logging.Get().Err(err).Msg("parse req failed.")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, err))
			return
		}
		endpoints, total, err := req.Execute(ctx)

		if err != nil {
			logging.Get().Err(err).Msg("get Ingresses error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			var objIdList []string
			for _, item := range endpoints {
				objIdList = append(objIdList, strconv.Itoa(int(item.ID)))
			}
			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_endpoints, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query service's tags failed")
				response.Ok(w, response.WithItems(endpoints), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(endpoints))))
				return
			}
			var withTags []*EndpointsWithTags
			for _, item := range endpoints {
				tmp := &EndpointsWithTags{
					TensorEndpoints: item,
				}
				tmp.Tags = tagsMapByAssetsIds[strconv.Itoa(int(item.ID))]
				tmp.Tags = append(tmp.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_endpoints]...)
				withTags = append(withTags, tmp)
			}
			response.Ok(w, response.WithItems(withTags), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(endpoints))))
			return
		}

		response.Ok(w, response.WithItems(endpoints), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(endpoints))))
	}
}

func (api *api) getEndpointsBase() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		query := dal.EndpointsQuery()

		query.WhereEqCondition["cluster_key"] = chi.URLParam(r, "cluster_key")
		query.WhereEqCondition["namespace"] = chi.URLParam(r, "namespace")
		query.WhereEqCondition["name"] = chi.URLParam(r, "endpoints_name")

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}
		endpoints, err := resSvc.GetEndpointBase(ctx, query, 0, 1)

		if err != nil {
			logging.Get().Err(err).Msgf("get endpoints error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		end := &model.TensorEndpoints{}
		if len(endpoints) > 0 {
			end = endpoints[0]
		}
		response.Ok(w, func(ev *response.HTTPEnvelope) {
			data, err := json.Marshal(end)
			if err != nil {
				ev.EnvelopeError = fmt.Sprintf("Failed to marshal item to json: %v", err)
			} else {
				ev.Data.Item = data
			}
		})
	}

}

func (api *api) getEndpointSubsetKinds() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		//endId := chi.URLParam(r, "endpoints_id")
		//ingId, err := strconv.ParseInt(endId, 10, 64)
		//if err != nil {
		//	RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("parse ingress_id failed."+endId)))
		//	return
		//}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}

		kinds, err := resSvc.GetEndpointSubsetKinds(ctx)
		if err != nil {
			logging.Get().Err(err).Msgf("get GetEndpointSubsetKinds  error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(kinds))
	}
}

type GetEndpointsSubsetsReq struct {
	endpointsId  int
	endpointName string
	nodeName     string
	ip           string
	refKind      string
	addrStatus   string
	offset       int
	limit        int
}

func (g *GetEndpointsSubsetsReq) Render(r *http.Request) error {
	endId := chi.URLParam(r, "endpoints_id")
	ingId, err := strconv.ParseInt(endId, 10, 64)
	if err != nil {
		return err
	}
	g.endpointsId = int(ingId)
	g.endpointName = getNormalizedQueryParam(r, "endpoint_name")
	g.nodeName = getNormalizedQueryParam(r, "node_name")
	g.ip = getNormalizedQueryParam(r, "ip")
	g.refKind = getNormalizedQueryParam(r, "ref_kind")
	g.addrStatus = getNormalizedQueryParam(r, "addr_status")
	g.limit, g.offset = getLimitAndOffsetWithDefault(r)

	return nil
}

func (api *api) getEndpointsSubsets() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &GetEndpointsSubsetsReq{}
		err := req.Render(r)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("parse req failed.")))
			return
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}

		opt := dal.EndpointsSubsetsQuery()
		opt.WhereEqCondition["endpoints_id"] = req.endpointsId
		if req.endpointName != "" {
			opt.WhereLikeCondition["name"] = req.endpointName
		}
		if req.nodeName != "" {
			opt.WhereLikeCondition["node_name"] = req.nodeName
		}
		if req.ip != "" {
			opt.WhereLikeCondition["ip"] = req.ip
		}
		if req.refKind != "" {
			kinds := strings.Split(req.refKind, ",")
			opt.WhereInCondition["target_ref_kind"] = kinds
		}
		if req.addrStatus != "" {
			status := strings.Split(req.addrStatus, ",")
			opt.WhereInCondition["address_status"] = status
		}

		endpointsSubsets, total, err := resSvc.ListEndpointsSubset(ctx, opt, req.offset, req.limit)
		if err != nil {
			logging.Get().Err(err).Msg("get Ingresses Rules error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w, response.WithItems(endpointsSubsets),
			response.WithTotalItems(total),
			response.WithStartIndex(int64(req.offset+len(endpointsSubsets))),
		)
	}
}

type GetSecretsReq struct {
	name       string
	namespace  string
	clusterKey string
	idList     []string
	start      time.Time
	end        time.Time
	offset     int
	limit      int
}

type SecretsView struct {
	*model.TensorSecret
	LabelList []Label
}

type SecretsWithTags struct {
	SecretsView
	Tags []string
}

func (api *api) getSecrets() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &GetSecretsReq{}

		req.name = getNormalizedQueryParam(r, "name")
		req.namespace = getNormalizedQueryParam(r, "namespace")
		req.clusterKey = getNormalizedQueryParam(r, "cluster_key")
		idList, _ := param.QueryString(r, "idList")
		if idList != "" {
			req.idList = strings.Split(idList, ",")
		}
		req.limit, req.offset = getLimitAndOffsetWithDefault(r)

		var start, end time.Time
		var err error
		startTime, _ := param.QueryString(r, "start_time")
		if startTime != "" {
			start, err = time.Parse(time.RFC3339, startTime)
			if err != nil {
				logging.Get().Err(err).Msg("parse startTime error")
				RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
				return
			}
		}
		endTime, _ := param.QueryString(r, "end_time")
		if endTime != "" {
			end, err = time.Parse(time.RFC3339, endTime)
			if err != nil {
				logging.Get().Err(err).Msg("parse endTime error")
				RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
				return
			}
		}
		req.start = start
		req.end = end
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}
		opt := dal.SecretsQuery()
		if req.name != "" {
			opt.WhereLikeCondition["name"] = req.name
		}
		if req.namespace != "" {
			opt.WhereLikeCondition["namespace"] = req.namespace
		}
		if req.clusterKey != "" {
			split := strings.Split(req.clusterKey, ",")
			opt.WhereInCondition["cluster_key"] = split
		}
		if len(req.idList) > 0 {
			opt.WhereInCondition["id"] = req.idList
		}
		opt.WithTimeRange(req.start, req.end)

		secrets, total, err := resSvc.ListSecret(ctx, opt, req.offset, req.limit)
		if err != nil {
			logging.Get().Err(err).Msg("get Ingresses Rules error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		var result []SecretsView
		var objIdList []string
		for _, sec := range secrets {
			objIdList = append(objIdList, strconv.Itoa(int(sec.ID)))
			tmp := SecretsView{TensorSecret: sec}
			for k, v := range sec.Labels {
				tmp.LabelList = append(tmp.LabelList, Label{
					LabelName:  k,
					LabelValue: v,
				})
			}
			tmp.Labels = nil
			result = append(result, tmp)
		}

		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_secret, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query secret's tags failed")
				response.Ok(w, response.WithItems(result), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(secrets))))
				return
			}
			var withTags []*SecretsWithTags
			for _, item := range result {
				tmp := &SecretsWithTags{
					SecretsView: item,
				}
				tmp.Tags = tagsMapByAssetsIds[strconv.Itoa(int(item.ID))]
				tmp.Tags = append(tmp.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_secret]...)
				withTags = append(withTags, tmp)
			}
			response.Ok(w, response.WithItems(withTags), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(secrets))))
			return
		}

		response.Ok(w, response.WithItems(result), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(secrets))))
	}
}

type GetPVsReq struct {
	name                          string
	storageClassName              string
	namespace                     string
	clusterKey                    string
	accessMode                    string // 转换
	volumeMode                    string
	pvStatus                      string
	persistentVolumeReclaimPolicy string
	idList                        []string
	start                         time.Time
	end                           time.Time
	offset                        int
	limit                         int
}

func (g *GetPVsReq) Render(r *http.Request) error {
	g.limit, g.offset = getLimitAndOffsetWithDefault(r)
	g.name = getNormalizedQueryParam(r, "name")
	g.storageClassName = getNormalizedQueryParam(r, "storage_cluass_name")
	g.accessMode = getNormalizedQueryParam(r, "access_mode")
	g.volumeMode = getNormalizedQueryParam(r, "volume_mode")
	g.pvStatus = getNormalizedQueryParam(r, "pv_status")
	g.clusterKey = getNormalizedQueryParam(r, "cluster_key")
	g.persistentVolumeReclaimPolicy = getNormalizedQueryParam(r, "persistent_volume_reclaim_policy")
	idList, _ := param.QueryString(r, "idList")
	if idList != "" {
		g.idList = strings.Split(idList, ",")
	}
	var start, end time.Time
	var err error
	startTime, _ := param.QueryString(r, "start_time")
	if startTime != "" {
		start, err = time.Parse(time.RFC3339, startTime)
		if err != nil {
			logging.Get().Err(err).Msgf("parse start_time failed")
			return err
		}
	}
	endTime, _ := param.QueryString(r, "end_time")
	if endTime != "" {
		end, err = time.Parse(time.RFC3339, endTime)
		if err != nil {
			logging.Get().Err(err).Msgf(" parse end_time failed")
			return err
		}
	}
	g.start = start
	g.end = end
	return nil
}

func (g *GetPVsReq) Execute(ctx context.Context) ([]*model.TensorPV, int64, error) {
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, errors.New("service instance get error")
	}
	pvQuery := dal.PVQuery()
	if g.name != "" {
		pvQuery.WhereLikeCondition["name"] = g.name
	}
	if g.storageClassName != "" {
		pvQuery.WhereLikeCondition["storage_class_name"] = g.storageClassName
	}
	if g.accessMode != "" {
		models := strings.Split(g.accessMode, ",")
		pvQuery.WhererInCondition["access_mode"] = models
	}
	if g.volumeMode != "" {
		models := strings.Split(g.volumeMode, ",")
		pvQuery.WhererInCondition["volume_mode"] = models
	}
	if g.pvStatus != "" {
		models := strings.Split(g.pvStatus, ",")
		pvQuery.WhererInCondition["pv_status"] = models
	}
	if g.persistentVolumeReclaimPolicy != "" {
		models := strings.Split(g.persistentVolumeReclaimPolicy, ",")
		pvQuery.WhererInCondition["persistent_volume_reclaim_policy"] = models
	}
	if g.clusterKey != "" {
		models := strings.Split(g.clusterKey, ",")
		pvQuery.WhererInCondition["cluster_key"] = models
	}
	if len(g.idList) > 0 {
		pvQuery.WhererInCondition["id"] = g.idList
	}
	pvQuery.WithTimeRange(g.start, g.end)

	return resSvc.ListPV(ctx, pvQuery, g.offset, g.limit)
}

type PVWithTags struct {
	*model.TensorPV
	Tags []string `json:"tags"`
}

func (api *api) getPVs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &GetPVsReq{}
		err := req.Render(r)
		if err != nil {
			logging.Get().Err(err).Msg("parse req failed.")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, err))
			return
		}
		pvs, total, err := req.Execute(ctx)
		if err != nil {
			logging.Get().Err(err).Msg("get pv error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			var objIdList []string
			for _, item := range pvs {
				objIdList = append(objIdList, strconv.Itoa(int(item.ID)))
			}
			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_pv, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query pv's tags failed")
				response.Ok(w, response.WithItems(pvs), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(pvs))))
				return
			}
			var withTags []*PVWithTags
			for _, item := range pvs {
				tmp := &PVWithTags{
					TensorPV: item,
				}
				tmp.Tags = tagsMapByAssetsIds[strconv.Itoa(int(item.ID))]
				tmp.Tags = append(tmp.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_pv]...)
				withTags = append(withTags, tmp)
			}
			response.Ok(w, response.WithItems(withTags), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(pvs))))
			return
		}

		response.Ok(w, response.WithItems(pvs), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(pvs))))
	}
}

type GetPVCsReq struct {
	name             string
	storageClassName string
	namespace        string
	clusterKey       string
	accessMode       string // 转换
	volumeMode       string
	pvcStatus        string
	idList           []string
	start            time.Time
	end              time.Time
	offset           int
	limit            int
}

func (g *GetPVCsReq) Render(r *http.Request) error {
	g.limit, g.offset = getLimitAndOffsetWithDefault(r)
	g.name = getNormalizedQueryParam(r, "name")
	g.storageClassName = getNormalizedQueryParam(r, "storage_cluass_name")
	g.namespace = getNormalizedQueryParam(r, "namespace")
	g.accessMode = getNormalizedQueryParam(r, "access_mode")
	g.volumeMode = getNormalizedQueryParam(r, "volume_mode")
	g.pvcStatus = getNormalizedQueryParam(r, "pv_status")
	g.clusterKey = getNormalizedQueryParam(r, "cluster_key")
	idList, _ := param.QueryString(r, "idList")
	if idList != "" {
		g.idList = strings.Split(idList, ",")
	}

	var start, end time.Time
	var err error
	startTime, _ := param.QueryString(r, "start_time")
	if startTime != "" {
		start, err = time.Parse(time.RFC3339, startTime)
		if err != nil {
			logging.Get().Err(err).Msgf("parse start_time failed")
			return err
		}
	}
	endTime, _ := param.QueryString(r, "end_time")
	if endTime != "" {
		end, err = time.Parse(time.RFC3339, endTime)
		if err != nil {
			logging.Get().Err(err).Msgf(" parse end_time failed")
			return err
		}
	}
	g.start = start
	g.end = end
	return nil
}

func (g *GetPVCsReq) Execute(ctx context.Context) ([]*model.TensorPVC, int64, error) {
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, errors.New("service instance get error")
	}
	pvQuery := dal.PVCQuery()
	if g.name != "" {
		pvQuery.WhereLikeCondition["name"] = g.name
	}
	if g.storageClassName != "" {
		pvQuery.WhereLikeCondition["storage_class_name"] = g.storageClassName
	}
	if g.namespace != "" {
		pvQuery.WhereLikeCondition["namespace"] = g.namespace
	}
	if g.accessMode != "" {
		models := strings.Split(g.accessMode, ",")
		pvQuery.WhereInCondition["access_mode"] = models
	}
	if g.volumeMode != "" {
		models := strings.Split(g.volumeMode, ",")
		pvQuery.WhereInCondition["volume_mode"] = models
	}
	if g.pvcStatus != "" {
		models := strings.Split(g.pvcStatus, ",")
		pvQuery.WhereInCondition["pvc_status"] = models
	}

	if g.clusterKey != "" {
		models := strings.Split(g.clusterKey, ",")
		pvQuery.WhereInCondition["cluster_key"] = models
	}
	if len(g.idList) > 0 {
		pvQuery.WhereInCondition["id"] = g.idList
	}
	pvQuery.WithTimeRange(g.start, g.end)

	return resSvc.ListPVC(ctx, pvQuery, g.offset, g.limit)
}

type PVCWithTags struct {
	*model.TensorPVC
	Tags []string `json:"tags"`
}

func (api *api) getPVCs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &GetPVCsReq{}
		err := req.Render(r)
		if err != nil {
			logging.Get().Err(err).Msg("parse req failed.")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, err))
			return
		}
		pvcs, total, err := req.Execute(ctx)

		if err != nil {
			logging.Get().Err(err).Msg("get Ingresses error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			var objIdList []string
			for _, item := range pvcs {
				objIdList = append(objIdList, strconv.Itoa(int(item.ID)))
			}
			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_pvc, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query pv's tags failed")
				response.Ok(w, response.WithItems(pvcs), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(pvcs))))
				return
			}
			var withTags []*PVCWithTags
			for _, item := range pvcs {
				tmp := &PVCWithTags{
					TensorPVC: item,
				}
				tmp.Tags = tagsMapByAssetsIds[strconv.Itoa(int(item.ID))]
				tmp.Tags = append(tmp.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_pvc]...)
				withTags = append(withTags, tmp)
			}
			response.Ok(w, response.WithItems(withTags), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(pvcs))))
			return
		}

		response.Ok(w, response.WithItems(pvcs), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(pvcs))))
	}
}

type getNamespaceLabels struct {
	namespace  string
	clusterKey string
	start      time.Time
	end        time.Time
	offset     int
	limit      int
}

func (g *getNamespaceLabels) Render(r *http.Request) error {
	g.limit, g.offset = getLimitAndOffsetWithDefault(r)
	g.namespace = getNormalizedQueryParam(r, "namespace")
	g.clusterKey = getNormalizedQueryParam(r, "cluster_key")
	var start, end time.Time
	var err error
	startTime, _ := param.QueryString(r, "start_time")
	if startTime != "" {
		start, err = time.Parse(time.RFC3339, startTime)
		if err != nil {
			logging.Get().Err(err).Msgf("parse start_time failed")
			return err
		}
	}
	endTime, _ := param.QueryString(r, "end_time")
	if endTime != "" {
		end, err = time.Parse(time.RFC3339, endTime)
		if err != nil {
			logging.Get().Err(err).Msgf(" parse end_time failed")
			return err
		}
	}
	g.start = start
	g.end = end
	return nil
}

func (g *getNamespaceLabels) Execute(ctx context.Context) ([]*model.TensorNamespaceLabel, int64, error) {
	query := dal.NamespaceLabelQuery()
	if g.namespace != "" {
		query.WhereLikeCondition["namespace"] = g.namespace
	}
	if g.clusterKey != "" {
		split := strings.Split(g.clusterKey, ",")
		query.WhereInCondition["cluster_key"] = split
	}
	query.WithTimeRange(g.start, g.end)

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, errors.New("service instance get error")
	}
	return resSvc.ListNamespaceLabel(ctx, query, g.offset, g.limit)

}

type LabelsWithTags struct {
	*model.TensorNamespaceLabel
	Tags []string `json:"tags"`
}

func (api *api) getNamespaceLabels() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &getNamespaceLabels{}
		err := req.Render(r)
		if err != nil {
			logging.Get().Err(err).Msg("parse req failed.")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, err))
			return
		}
		labels, total, err := req.Execute(ctx)

		if err != nil {
			logging.Get().Err(err).Msg("get Ingresses error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			var result []*LabelsWithTags
			for _, label := range labels {
				item := LabelsWithTags{
					TensorNamespaceLabel: label,
					Tags:                 []string{dal.BuiltInTag_k8s},
				}
				result = append(result, &item)
			}
			response.Ok(w, response.WithItems(result), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(labels))))
			return
		}
		response.Ok(w, response.WithItems(labels), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(labels))))
	}
}

func (api *api) addNamespaceLabel() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var data assets.NamespaceLabel
		err := util.DecodeJSONBody(w, r, &data)
		if err != nil {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		//校验 labelName 格式: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
		matched, err := regexp.MatchString(`^[a-zA-Z0-9_.-/]+$`, data.LabelName)
		if err != nil || matched == false {
			RespAndLog(w, ctx, NewAnErrorWithErrMsg(http.StatusBadRequest, errors.New(`标签名不合法，只能由英文字符，数字，和"-","_","." 组成`)))
			return
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}
		err = resSvc.AddNamespaceLabel(ctx, data)
		if err != nil {
			logging.Get().Err(err).Msgf("namespaceLabes: AddNamespaceLabel failed.")
			RespAndLog(w, ctx, NewAnErrorWithErrMsg(http.StatusBadRequest, err))
			return
		}
		response.Ok(w)
	}
}

func (api *api) updateNamespaceLabel() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		labelIdStr := chi.URLParam(r, "label_id")
		labelId, err := strconv.ParseInt(labelIdStr, 10, 64)
		if err != nil {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("update:failed to parse labelId: %w", err)))
			return
		}
		type data struct {
			LabelValue string `json:"label_value"`
		}
		var d data
		err = util.DecodeJSONBody(w, r, &d)
		if err != nil {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnErrorWithErrMsg(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}
		err = resSvc.UpdateNamespaceLabel(ctx, labelId, d.LabelValue)
		if err != nil {
			logging.Get().Err(err).Msgf("namespaceLabes: updateNamespaceLabel failed.")
			RespAndLog(w, ctx, NewAnErrorWithErrMsg(http.StatusBadRequest, errors.New("更新失败")))
			return
		}
		response.Ok(w)
	}
}

func (api *api) deleteNamespaceLabels() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		labelIdStr := chi.URLParam(r, "label_id")
		labelId, err := strconv.ParseInt(labelIdStr, 10, 64)
		if err != nil {
			RespAndLog(w, ctx, NewInvalidArgError(http.StatusBadRequest, fmt.Errorf("delete:failed to parse labelId: %w", err)))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnErrorWithErrMsg(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}
		err = resSvc.DeleteNamespaceLabel(ctx, labelId)
		if err != nil {
			logging.Get().Err(err).Msgf("namespaceLabes: deleteNamespaceLabels  failed.")
			RespAndLog(w, ctx, NewAnErrorWithErrMsg(http.StatusBadRequest, errors.New("删除失败")))
			return
		}
		response.Ok(w)
	}
}

type BusiServiceReq struct {
	containerName string
	svcNameList   []string
	svcVersion    string
	svcTypeList   []string
	userList      []string
	idList        []string
	limit         int
	offset        int
}

func (g *BusiServiceReq) Render(r *http.Request) {
	g.limit, g.offset = getLimitAndOffsetWithDefault(r)
	g.containerName = getNormalizedQueryParam(r, "containerName")
	svcNames := getNormalizedQueryParam(r, "svcName")
	if svcNames != "" {
		g.svcNameList = strings.Split(svcNames, ",")
	}
	g.svcVersion = getNormalizedQueryParam(r, "svcVersion")
	svcTypes := getNormalizedQueryParam(r, "svcType")
	if svcTypes != "" {
		g.svcTypeList = strings.Split(svcTypes, ",")
	}
	users := getNormalizedQueryParam(r, "user")
	if users != "" {
		g.userList = strings.Split(users, ",")
	}
	idList := getNormalizedQueryParam(r, "idList")
	if idList != "" {
		g.idList = strings.Split(idList, ",")
	}
}

func (g *BusiServiceReq) Execute(ctx context.Context) ([]*dal.PodBusiSvcBase, int64, error) {
	query := dal.GetBusiSvcQueryOption()
	if g.containerName != "" {
		query.ContainerName = g.containerName
	}
	if g.svcVersion != "" {
		query.WhereLikeCondition["svc_version"] = g.svcVersion
	}
	if len(g.svcNameList) > 0 {
		query.WhereInCondition["svc_name"] = g.svcNameList
	}
	if len(g.svcTypeList) > 0 {
		query.WhereInCondition["svc_type"] = g.svcTypeList
	}
	if len(g.userList) > 0 {
		query.WhereInCondition["ivan_assets_raw_containers_svcs.user"] = g.userList
	}
	if len(g.idList) > 0 {
		query.WhereInCondition["ivan_assets_raw_containers_svcs.id"] = g.idList
	}

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, errors.New("service instance get error")
	}
	return resSvc.ListBusiSvc(ctx, query, g.offset, g.limit)
}

type BusiSvcWithTags struct {
	*dal.PodBusiSvcBase
	Tags []string `json:"tags"`
}

func (api *api) getBusiServices() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &BusiServiceReq{}
		req.Render(r)
		svcBases, total, err := req.Execute(ctx)

		if err != nil {
			logging.Get().Err(err).Msg("get Ingresses error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			var objIdList []string
			for _, item := range svcBases {
				objIdList = append(objIdList, strconv.Itoa(int(item.Id)))
			}
			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_app, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query app's tags failed")
				response.Ok(w, response.WithItems(svcBases), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(svcBases))))
				return
			}
			var withTags []*BusiSvcWithTags
			for _, item := range svcBases {
				tmp := &BusiSvcWithTags{
					PodBusiSvcBase: item,
				}
				tmp.Tags = tagsMapByAssetsIds[strconv.Itoa(int(item.Id))]
				tmp.Tags = append(tmp.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_app]...)
				withTags = append(withTags, tmp)
			}
			response.Ok(w, response.WithItems(withTags), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(svcBases))))
			return
		}

		response.Ok(w, response.WithItems(svcBases), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(svcBases))))
	}
}

func (api *api) getWebBusiServices() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &BusiServiceReq{}
		req.Render(r)
		req.svcTypeList = []string{assetsPkg.BusiSvcTypeWebEn}
		svcBases, total, err := req.Execute(ctx)
		if err != nil {
			logging.Get().Err(err).Msg("get Ingresses error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			var objIdList []string
			for _, item := range svcBases {
				objIdList = append(objIdList, strconv.Itoa(int(item.Id)))
			}
			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_webApp, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query app_db's tags failed")
				response.Ok(w, response.WithItems(svcBases), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(svcBases))))
				return
			}
			var withTags []*BusiSvcWithTags
			for _, item := range svcBases {
				tmp := &BusiSvcWithTags{
					PodBusiSvcBase: item,
				}
				tmp.Tags = tagsMapByAssetsIds[strconv.Itoa(int(item.Id))]
				tmp.Tags = append(tmp.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_webApp]...)
				withTags = append(withTags, tmp)
			}
			response.Ok(w, response.WithItems(withTags), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(svcBases))))
			return
		}

		response.Ok(w, response.WithItems(svcBases), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(svcBases))))
	}
}

func (api *api) getBusiStartUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		buisi := getNormalizedQueryParam(r, "busiType")

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		if buisi != "" {
			_, isOK := busiServiceTypeMap[buisi]
			if isOK == false {
				RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("not support type:"+buisi)))
			}
		}
		users, err := resSvc.GetBusiStartUser(ctx, buisi)
		if err != nil {
			logging.Get().Err(err).Msg("getBusiStartUser failed.")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("get user failed")))
			return
		}
		response.Ok(w, response.WithItems(users))
	}
}

func (api *api) getDbBusiServices() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &BusiServiceReq{}
		req.Render(r)
		req.svcTypeList = []string{assetsPkg.BusiSvcTypeDbEn}
		svcBases, total, err := req.Execute(ctx)
		if err != nil {
			logging.Get().Err(err).Msg("get Ingresses error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			var objIdList []string
			for _, item := range svcBases {
				objIdList = append(objIdList, strconv.Itoa(int(item.Id)))
			}
			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_dbApp, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query app's tags failed")
				response.Ok(w, response.WithItems(svcBases), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(svcBases))))
				return
			}
			var withTags []*BusiSvcWithTags
			for _, item := range svcBases {
				tmp := &BusiSvcWithTags{
					PodBusiSvcBase: item,
				}
				tmp.Tags = tagsMapByAssetsIds[strconv.Itoa(int(item.Id))]
				tmp.Tags = append(tmp.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_dbApp]...)
				withTags = append(withTags, tmp)
			}
			response.Ok(w, response.WithItems(withTags), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(svcBases))))
			return
		}

		response.Ok(w, response.WithItems(svcBases), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(svcBases))))
	}
}

func (api *api) getBusiService() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		id := chi.URLParam(r, "id")
		parseInt, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("parse id error.id:"+id)))
			return
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}
		detail, err := resSvc.GetBusiSvcDetail(ctx, uint32(parseInt))
		if err != nil {
			logging.Get().Err(err).Msg("get Ingresses error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		// zh en
		if !isEnglish(r) {
			detail.SvcType = busiServiceTypeMap[detail.SvcType]
		}
		response.Ok(w, func(ev *response.HTTPEnvelope) {
			data, err := json.Marshal(detail)
			if err != nil {
				ev.EnvelopeError = fmt.Sprintf("Failed to marshal item to json: %v", err)
			} else {
				ev.Data.Item = data
			}
		})
	}
}

func (api *api) getBusiServicesKind() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var busiServiceKind = append(busiServiceWebKind, busiServiceDbKind...)
		busiServiceKind = append(busiServiceKind, pkgAssets.BusiSvcGrafana)
		response.Ok(w, response.WithItems(busiServiceKind))
	}
}

func isEnglish(r *http.Request) bool {
	lang := r.Header.Get("Accept-Language")
	if lang == "" {
		lang = "zh"
	}
	return lang == "en"
}

//var busiServiceType = []string{pkgAssets.BusiSvcTypeWeb, pkgAssets.BusiSvcTypeDb, pkgAssets.BusiSvcTypeMonitor}

type BusiSvcTypeItem struct {
	En string `json:"en"`
	Zh string `json:"zh"`
}

var busiServiceTypeList = []BusiSvcTypeItem{
	{En: pkgAssets.BusiSvcTypeWebEn, Zh: pkgAssets.BusiSvcTypeWeb},
	{En: pkgAssets.BusiSvcTypeDbEn, Zh: pkgAssets.BusiSvcTypeDb},
	{En: pkgAssets.BusiSvcTypeMonitorEn, Zh: pkgAssets.BusiSvcTypeMonitor},
}
var busiServiceTypeMap = map[string]string{
	pkgAssets.BusiSvcTypeWebEn:     pkgAssets.BusiSvcTypeWeb,
	pkgAssets.BusiSvcTypeDbEn:      pkgAssets.BusiSvcTypeDb,
	pkgAssets.BusiSvcTypeMonitorEn: pkgAssets.BusiSvcTypeMonitor,
}

func (api *api) getBusiServicesType() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response.Ok(w, response.WithItems(busiServiceTypeList))
	}
}

var busiServiceWebKind = []string{
	pkgAssets.BusiSvcTomcat,
	pkgAssets.BusiSvcAppache,
	pkgAssets.BusiSvcNginx,
	pkgAssets.BusiSvcWeblogic,
	pkgAssets.BusiSvcWildfly,
	pkgAssets.BusiSvcWebSphere,
	pkgAssets.BusiSvcOpenResty,
}

func (api *api) getBusiServiceWebKind() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response.Ok(w, response.WithItems(busiServiceWebKind))
	}
}

var busiServiceDbKind = []string{
	pkgAssets.BusiSvcRedis,
	pkgAssets.BusiSvcMysql,
	pkgAssets.BusiSvcPostgreSQL,
	pkgAssets.BusiSvcMogoDB,
	pkgAssets.BusiSvcRsyslog,
}

func (api *api) getBusiServiceDbKind() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response.Ok(w, response.WithItems(busiServiceDbKind))
	}
}

type ExposeHostReq struct {
	webDesc  string
	protocol []string
	hosts    []string
	limit    int
	offset   int
	//Ip            string //?
	//ContainerName string
	//SvcName       string
}

func (e *ExposeHostReq) Render(r *http.Request) {
	e.limit, e.offset = getLimitAndOffsetWithDefault(r)
	e.webDesc = getNormalizedQueryParam(r, "webDesc")
	protocol := getNormalizedQueryParam(r, "protocol")
	idList := getNormalizedQueryParam(r, "idList")
	if protocol != "" {
		e.protocol = strings.Split(protocol, ",")
	}
	if idList != "" {
		e.hosts = strings.Split(idList, ",")
	}
}

func (g *ExposeHostReq) Execute(ctx context.Context) ([]*dal.ExposeHostItem, int64, error) {

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, 0, errors.New("service instance get error")
	}
	return resSvc.ListExposeHost(ctx, g.webDesc, g.protocol, g.hosts, g.offset, g.limit)
}

func (api *api) getExposeHosts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := &ExposeHostReq{}
		req.Render(r)
		hostItems, total, err := req.Execute(ctx)

		if err != nil {
			logging.Get().Err(err).Msg("get getExposeHosts error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		hideTags, _ := param.QueryBool(r, "hideTags")
		if !hideTags {
			var objIdList []string
			for _, item := range hostItems {
				objIdList = append(objIdList, item.Host)
			}
			resSvc, _ := assets.GetResourcesService(ctx)
			tagsMapByAssetsIds, err := resSvc.GetTagsMapByAssetsIds(ctx, model.ObjType_webSit, objIdList)
			if err != nil {
				logging.Get().Err(err).Msg("query pv's tags failed")
				response.Ok(w, response.WithItems(hostItems), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(hostItems))))
				return
			}
			for _, item := range hostItems {
				item.Tags = tagsMapByAssetsIds[item.Host]
				item.Tags = append(item.Tags, dal.ObjTypeBuiltInTagMap[model.ObjType_webSit]...)
			}
		}

		response.Ok(w, response.WithItems(hostItems), response.WithTotalItems(total), response.WithStartIndex(int64(req.offset+len(hostItems))))
	}
}

func (api *api) getExposeHostDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		id := chi.URLParam(r, "id")
		parseInt, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("parse id error.id:"+id)))
			return
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
			return
		}
		detail, err := resSvc.GetExposeHostDetail(ctx, parseInt)

		if err != nil {
			logging.Get().Err(err).Msg("get getExposeHosts error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, func(ev *response.HTTPEnvelope) {
			data, err := json.Marshal(detail)
			if err != nil {
				ev.EnvelopeError = fmt.Sprintf("Failed to marshal item to json: %v", err)
			} else {
				ev.Data.Item = data
			}
		})
	}
}
