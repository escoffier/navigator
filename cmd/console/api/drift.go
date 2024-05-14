package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/security-rd/go-pkg/sdk/palace"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/drift"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	assetsPkg "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) drift() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/resources", api.driftResources())
		r.Post("/policy/create", api.driftCreatePolicy())
		r.Post("/policy/update", api.driftUpdatePolicy())
		r.Post("/policy/delete", api.driftDeletePolicy())
		r.Get("/policy/list", api.driftListPolicy())
		r.Get("/policy/detail", api.driftPolicyDetail())
		r.Get("/policy/{policyID}", api.driftPolicyByID())
		r.Get("/container", api.driftContainerByID())
		r.Get("/policy/abnormal", api.driftPolicyAbnormal())
		r.Get("/policy", api.driftAllPolicy())
		r.Get("/namespaces", api.driftNamespace())
		r.Post("/whitelist", api.driftCreateGlobalWhitelist())
		r.Put("/whitelist/{whitelistID}", api.driftUpdateGlobalWhitelist())
		r.Delete("/whitelist/{whitelistID}", api.driftDelGlobalWhitelist())
		r.Get("/whitelists", api.driftListGlobalWhitelist())
		r.Get("/whitelist/{whitelistID}", api.driftListGlobalWhitelistById())
		r.Get("/default/whitelist", api.driftPolicyImageWhitelist())
		r.Get("/resource/stats", api.driftResourceStats())
		r.Get("/policy/stats/top", api.driftPolicyStatsTop())
		r.Post("/policy/batch/create", api.driftCreateBatchPolicy())
		r.Put("/policy/batch/update", api.driftUpdateBatchPolicy())
	}
}

func isPath(path string) bool {
	if len(path) < 1 {
		return false
	}
	fPath := filepath.Join("", path)
	if path != fPath {
		return false
	}
	return path[0] == os.PathSeparator

}

func reasonStr2OSList(reasonStr string) (string, error) {
	var osList string
	var reasonList []model.ReasonItem
	err := json.Unmarshal([]byte(reasonStr), &reasonList)
	if err != nil {
		// adapt old version reason
		return reasonStr, err
	}
	osMap := make(map[string]struct{})
	for _, reason := range reasonList {
		if _, ok := osMap[reason.OS]; ok {
			continue
		}
		if reason.IsSupportDrift {
			continue
		}
		if len(osList) > 0 {

			osList = strings.Join([]string{osList, reason.OS}, ",")
		} else {
			osList = reason.OS
		}
		osMap[reason.OS] = struct{}{}
	}

	return osList, nil

}

func getSpecialNameSpaces() map[string]struct{} {

	workerNs := os.Getenv("MY_POD_NAMESPACE")
	return map[string]struct{}{
		"kube-system":                           {},
		"kube-public":                           {},
		"kube-node-lease":                       {},
		"kube-node-lease-renewer":               {},
		"kube-node-lease-maintenance":           {},
		"kube-node-lease-reclaim":               {},
		"kube-node-lease-preemptor":             {},
		"kube-node-lease-preemptor-maintenance": {},
		"kube-node-lease-preemptor-renewer":     {},
		"kube-node-lease-preemptor-reclaim":     {},
		workerNs:                                {},
	}
}

// @Summary get can build policy resource
// @Description get can build policy resource
// @Tags drift
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Router /api/v2/platform/drift/resource [get]
func (api *api) driftResources() http.HandlerFunc {
	type resource struct {
		Cluster        string `json:"cluster"`
		Namespace      string `json:"namespace"`
		Kind           string `json:"kind"`
		Name           string `json:"name"`
		IsSupportDrift bool   `json:"is_support_drift"`
		Reason         string `json:"reason"`
		IsExist        int    `json:"is_exist"`
		ScannerStatus  int8   `json:"scanner_status"`
	}
	modelToResource := func(rm *model.TensorResource) resource {
		r := resource{}
		reasonOS, err := reasonStr2OSList(rm.Reason)
		if err != nil {
			logging.GetLogger().Err(err).Msg("get resource reason os list failed")
		}
		r.Cluster = rm.ClusterKey
		r.Namespace = rm.Namespace
		r.Kind = rm.Kind
		r.Name = rm.Name
		r.IsSupportDrift = rm.IsSupportDrift
		r.Reason = reasonOS
		r.IsExist = 0
		r.ScannerStatus = rm.ScannerStatus
		return r
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		_, offset, err := getLimitAndOffset(r)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, err))
			return
		}

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil || clusterKey == "" {
			logging.GetLogger().Error().Err(err).Msg("get cluster_key fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get cluster_key fail")))
			return
		}
		namespace, err := param.QueryString(r, "namespace")
		if err != nil || namespace == "" {
			logging.GetLogger().Error().Err(err).Msg("get namespace fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get namespace fail")))
			return
		}
		excludeNamespaces := getSpecialNameSpaces()
		if _, ok := excludeNamespaces[namespace]; ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("namespace is invalid")))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("get drift service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get drift service fail")))
			return
		}

		query := dal.ResourcesQuery()
		query = query.WithCluster(clusterKey)
		query = query.WithNamespace(namespace)

		resources, _, err := resSvc.GetResources(ctx, query, 0, math.MaxInt)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resources fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get resources fail")))
			return
		}

		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("get drift service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get drift service fail")))
			return
		}

		// get drift policy
		policyData, err := driSvc.GetAllPoliciesFromDB(ctx, clusterKey)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get drift policies fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get drift policies fail")))
			return
		}

		var policyMap = make(map[string]struct{})
		for _, policy := range policyData {
			if policy.Namespace != namespace {
				continue
			}
			policyMap[policy.ResourceKind+policy.Resource] = struct{}{}
		}

		rawContainersUUID, err := runningContainersUUID(ctx, clusterKey, []string{namespace})
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get containers uuid error")
		}

		items := []resource{}
		for _, resource := range resources {
			if resource.Status != 0 {
				continue
			}

			tmpItem := modelToResource(resource)
			if _, ok := policyMap[resource.Kind+resource.Name]; ok {
				tmpItem.IsExist = 1
			}

			uuid := util.GenerateUUID(resource.ClusterKey, resource.Namespace, resource.Kind, resource.Name)
			if _, ok := rawContainersUUID[uuid]; !ok {
				tmpItem.IsSupportDrift = false
				tmpItem.Reason = "noRunningContainers"
				// continue
			}

			items = append(items, tmpItem)
		}

		response.Ok(w, response.WithItems(items), response.WithTotalItems(int64(len(items))), response.WithStartIndex(int64(offset+len(items))))
	}
}

// @Summary get drift policy stats top
// @Description get drift policy stats top
// @Tags drift
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Router /api/v2/platform/drift/policy/stats/top [get]
func (api *api) driftPolicyStatsTop() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		type topRankItem struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		}

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get cluster_key fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get cluster_key fail")))
			return
		}

		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		policyData, err := driSvc.GetAllPoliciesFromDB(ctx, clusterKey)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get all policies fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get all policies fail")))
			return
		}

		if len(policyData) == 0 {
			response.Ok(w, response.WithItems([]topRankItem{}))
			return
		}

		var topRank []topRankItem
		for _, p := range policyData {

			signals, err := driSvc.GetAbnormal(ctx, p, 3000, "", "")
			if err != nil {
				logging.GetLogger().Error().Err(err).Interface("policy", p).Msg("get abnormal fail")
				continue
			}

			rankItem := topRankItem{
				Name:  p.Namespace + "/" + p.Resource,
				Count: len(filterAbnormalInPolicy(p, signals)),
			}
			topRank = append(topRank, rankItem)
		}
		sort.SliceStable(topRank, func(i, j int) bool {
			return topRank[i].Count > topRank[j].Count
		})
		topN := len(topRank)
		if topN > 5 {
			topN = 5
		}
		response.Ok(w, response.WithItems(topRank[:topN]))
	}
}

func runningContainersUUID(ctx context.Context, clusterKey string, namespaces []string) (map[uint32]struct{}, error) {

	startTime := time.Now()
	logging.GetLogger().Debug().Str("runningContainersUUID-start", fmt.Sprintf("%d", startTime.UnixNano())).Msg("start")
	req := &GetRawContainers{
		ClusterKey: clusterKey,
		Namespaces: namespaces,
		Status:     []int{0},
		Offset:     0,
		Limit:      math.MaxInt,
		UseRedis:   false,
	}

	containers, totalCnt, err := req.Execute(ctx)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("get containers fail")
		return nil, err
	}

	containersUUID := make(map[uint32]struct{})
	for _, container := range containers {
		uuid := util.GenerateUUID(container.ClusterKey, container.Namespace, container.ResourceKind, container.ResourceName)
		containersUUID[uuid] = struct{}{}
	}

	if totalCnt > int64(len(containersUUID)) {
		logging.GetLogger().Warn().Msg("get containers count not match")
	}

	logging.GetLogger().Debug().Str("runningContainersUUID-end", fmt.Sprintf("%d", time.Since(startTime).Nanoseconds())).Int("size", len(containers)).Msg("end")
	return containersUUID, nil
}

// @Summary get drift support stats
// @Description get drift support stats
// @Tags drift
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Router /api/v2/platform/drift/resource/stats [get]
func (api *api) driftResourceStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		type stats struct {
			Total     int64 `json:"total"`
			Used      int64 `json:"used"`
			CanCreate int64 `json:"can_create"`
		}

		startTime := time.Now()
		logging.GetLogger().Debug().Str("driftResourceStats-start", fmt.Sprintf("%d", startTime.Nanosecond())).Msg("start")

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get cluster_key error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get cluster_key error")))
			return
		}

		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		policyData, err := driSvc.GetAllPoliciesFromDB(ctx, clusterKey)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get all policies error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get all policies error")))
			return
		}

		var policyMap = make(map[uint32]struct{})
		for _, policy := range policyData {
			uuid := util.GenerateUUID(policy.ClusterKey, policy.Namespace, policy.ResourceKind, policy.Resource)
			policyMap[uuid] = struct{}{}
		}

		excludeNS := getSpecialNameSpaces()
		excludeNSStr := make([]string, 0, len(excludeNS))
		for k := range excludeNS {
			excludeNSStr = append(excludeNSStr, k)
		}
		supportRes, err := driSvc.GetSupportResources(ctx, clusterKey, excludeNSStr)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get support resource count error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get support resource count error")))
			return
		}

		var total int64 = 0

		// containersUUID, err := runningContainersUUID(ctx, clusterKey, []string{})
		// if err != nil {
		// 	logging.GetLogger().Err(err).Msgf("get containers uuid error")
		// 	apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get containers uuid error")))
		// 	return
		// }

		canCreateCount := 0
		for _, res := range supportRes {
			// if _, ok := excludeNS[res.Namespace]; ok {
			// 	continue
			// }
			// if _, ok := containersUUID[res.ID]; !ok {
			// 	logging.GetLogger().Debug().Interface("res", res).Msg("resource not running")
			// 	continue
			// }
			total += 1
			if _, ok := policyMap[res.ID]; !ok {
				canCreateCount += 1
			}
		}

		res := stats{
			Total:     int64(len(policyData) + canCreateCount),
			Used:      int64(len(policyData)),
			CanCreate: int64(canCreateCount),
		}

		logging.GetLogger().Debug().Str("driftResourceStats-end", fmt.Sprintf("%d", time.Since(startTime).Nanoseconds())).Msg("end")
		response.Ok(w, response.WithItem(res))

	}
}

// @Summary Get drift policy default image whitelist
// @Description Get drift policy default image whitelist
// @Tags drift
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Router /api/v2/platform/drift/default/whitelist [get]
func (api *api) driftPolicyImageWhitelist() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		policyID, err := param.QueryInt64(r, "policy_id")
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get policy_id fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get policy_id fail")))
			return
		}

		offset, err := param.QueryInt(r, "offset")
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get offset fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get offset fail")))
			return

		}
		limit, err := param.QueryInt(r, "limit")
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get limit fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get limit fail")))
			return
		}

		searchStr := ""
		searchStr, err = param.QueryString(r, "search")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get search fail")
			searchStr = ""
		}

		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		policy, err := driSvc.GetPolicyByID(ctx, policyID)
		if err != nil {
			logging.GetLogger().Err(err).Msg("get GetPolicyByID error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get GetPolicyByID error")))
			return
		}

		containers, err := driSvc.PolicyDetailRawContainers(ctx, policy)
		if err != nil {
			logging.GetLogger().Err(err).Msg("get containers error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get containers error")))
			return
		}

		imageTags := []string{}
		imageDigests := []string{}
		for _, container := range containers {
			imageTag := container.ImageName
			if !strings.Contains(container.ImageName, ":") {
				imageTag = container.ImageName + ":latest"
			}
			imageTags = append(imageTags, imageTag)
			imageDigests = append(imageDigests, container.ImageDigest)
		}

		logging.GetLogger().Debug().Interface("imageTags", imageTags).Msg("imageTags")

		whitelist, count, err := driSvc.GetDefaultWhitelist(ctx, offset, limit, imageTags, imageDigests, searchStr)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("Get default whitelist error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("Get default whitelist error")))
			return
		}
		response.Ok(w, response.WithItems(whitelist),
			response.WithStartIndex(int64(offset)),
			response.WithItemsPerPage(int64(limit)),
			response.WithTotalItems(count))

	}
}

// @Summary Create whitelist
// @Description Create whitelist
// @ID v2-whitelist-create
// @Produce json
// @Accept json
// @Success 200 {object} model.DriftGlobalWhitelistItem
// @Param path body string true "path"
// @Router /api/v2/platform/drift/whitelist [post]

func (api *api) driftCreateGlobalWhitelist() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		type tmp struct {
			ID uint64 `json:"id"`
		}
		whitelistItem := model.DriftGlobalWhitelistItem{}
		err := util.DecodeJSONBody(w, r, &whitelistItem)
		// TODO: field security check

		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		if !isPath(whitelistItem.Path) {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("path illegal"),
					apperror.Suberror{Location: "dataType", Message: "path illegal"}))
			return
		}
		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		nowTimestamp := time.Now().UnixMilli()
		if whitelistItem.ExpireAt < nowTimestamp && !whitelistItem.IsForever {
			logging.GetLogger().Err(fmt.Errorf("expire time can't before now")).Msg("")
			apperror.RespAndLog(w, ctx, apperror.NewDriftGlobalWhitelistTimestampError(http.StatusInternalServerError, errors.New("expire time can't before now"),
				apperror.Suberror{
					Location: "timestamp",
					Message:  "expire time before now",
				}))
			return
		}
		tmpWhitelist := model.DriftGlobalWhitelistItem{Path: strings.Trim(whitelistItem.Path, " "),
			Creator:   request.GetAccountFromContext(r.Context()),
			Updater:   request.GetAccountFromContext(r.Context()),
			CreatedAt: nowTimestamp,
			UpdatedAt: nowTimestamp,
			ExpireAt:  whitelistItem.ExpireAt,
			IsForever: whitelistItem.IsForever}
		id, err := driSvc.CreateGlobalWhitelist(ctx, tmpWhitelist)
		if err != nil {
			if strings.Contains(err.Error(), "same path") {
				logging.GetLogger().Err(err).Msg("Create Same path")
				apperror.RespAndLog(w, ctx, apperror.NewDriftGlobalWhitelistError(http.StatusInternalServerError, errors.New("create same whitelist")))
			} else {
				logging.GetLogger().Err(err).Msg("Create whitelist error")
				apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("create whitelist error")))
			}
			return
		}
		respTmp := tmp{ID: id}
		response.Ok(w, response.WithItem(respTmp), response.WithTarget(&response.TargetRef{ID: fmt.Sprintf("%d", respTmp.ID), Name: whitelistItem.Path}))
	}
}

func (api *api) driftUpdateGlobalWhitelist() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		whitelistItemUpdate := model.DriftGlobalWhitelistItem{}

		idStr := chi.URLParam(r, "whitelistID")
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get id fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		err = util.DecodeJSONBody(w, r, &whitelistItemUpdate)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		whitelistItemUpdate.Updater = request.GetAccountFromContext(r.Context())

		if !isPath(whitelistItemUpdate.Path) {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("path illegal"),
					apperror.Suberror{Location: "dataType", Message: "path illegal"}))
			return
		}
		nowTimestamp := time.Now().UnixMilli()
		if whitelistItemUpdate.ExpireAt < nowTimestamp && !whitelistItemUpdate.IsForever {
			logging.GetLogger().Error().Int64("expired_at", whitelistItemUpdate.ExpireAt).Int64("now", nowTimestamp).Msg("expire time can't before now")
			apperror.RespAndLog(w, ctx, apperror.NewDriftGlobalWhitelistTimestampError(http.StatusInternalServerError, errors.New("expire time can't before now"),
				apperror.Suberror{
					Location: "timestamp",
					Message:  "expire time before now",
				}))
			return
		}

		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		whitelistItemUpdate.UpdatedAt = nowTimestamp
		whitelistItemUpdate.ID = id
		whitelist, err := driSvc.UpdateGlobalWhitelist(ctx, whitelistItemUpdate)
		if err != nil {
			logging.GetLogger().Err(err).Msg("Update whitelist error")
			if strings.Contains(err.Error(), "Duplicate entry") {
				apperror.RespAndLog(w, ctx, apperror.
					NewDriftGlobalWhitelistError(http.StatusInternalServerError, errors.New("update same whitelist")))
			} else {

				apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("update whitelist error")))
			}
			return
		}
		response.Ok(w, response.WithItem(whitelist), response.WithTarget(&response.TargetRef{ID: fmt.Sprintf("%d", whitelist.ID), Name: whitelist.Path}))
	}
}

func (api *api) driftDelGlobalWhitelist() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		idStr := chi.URLParam(r, "whitelistID")
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get id fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		whitelist, err := driSvc.DelGlobalWhitelist(ctx, id)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("Delete whitelist %v error", id)
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("delete whitelist error")))
			return
		}

		response.Ok(w, response.WithItem(whitelist), response.WithTarget(&response.TargetRef{ID: fmt.Sprintf("%d", whitelist.ID), Name: whitelist.Path}))
	}
}

func (api *api) driftListGlobalWhitelist() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		offset, err := param.QueryInt(r, "offset")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get offset error\n")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get offset error")))
			return
		}

		limit, err := param.QueryInt(r, "limit")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit error\n")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get limit error")))
			return
		}
		search, err := param.QueryString(r, "search")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("get search nil")
		}
		startTime, err := param.QueryInt64(r, "start")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("not start time")
			startTime = 0
		}
		endTime, err := param.QueryInt64(r, "end")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("not end time")
			endTime = 0
		}

		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		whitelist, count, err := driSvc.ListGlobalWhitelist(ctx, limit, offset, "", search, startTime, endTime)
		if err != nil {
			logging.GetLogger().Err(err).Msg("List whitelist error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("list whitelist error")))

			return
		}
		// the ID for frontend should be string; because the int64 might be larger than the max of the js number
		for i := range whitelist {
			whitelist[i].IDForFrontend = strconv.FormatUint(whitelist[i].ID, 10)
		}

		response.Ok(w, response.WithItems(whitelist), response.WithTotalItems(count))
	}
}

func (api *api) driftListGlobalWhitelistById() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		idStr := chi.URLParam(r, "whitelistID")
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get id fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		whitelist, err := driSvc.GetGlobalWhitelistById(ctx, id)
		if err != nil {
			logging.GetLogger().Err(err).Msg("get whitelist error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get whitelist error")))

			return
		}
		response.Ok(w, response.WithItem(whitelist))
	}
}

func (api *api) driftNamespace() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit or offset query error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.GetLogger().Err(err).Msg("get cluster_key param error.")
			clusterKey = ""
		}
		query, err := param.QueryString(r, "query")
		if err != nil {
			query = ""
		}
		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		namespaces, totalCnt, err := resSvc.GetNamespaces(ctx, clusterKey, query, offset, limit)
		if err != nil {
			logging.GetLogger().Err(err).Msg("getNamespaces error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}
		namespacesDefault := getSpecialNameSpaces()
		var res []*model.TensorNamespace
		for _, v := range namespaces {
			if _, ok := namespacesDefault[v.Name]; !ok {
				res = append(res, v)
			}
		}
		response.Ok(w, response.WithItems(res),
			response.WithTotalItems(totalCnt),
			response.WithStartIndex(int64(offset+len(namespaces))),
		)
	}
}

func getVersionFromPolicies(policies []model.DriftPolicy) int64 {
	version := int64(0)
	for _, p := range policies {
		stamp := p.UpdatedAt.UnixMilli()
		if stamp > version {
			version = stamp
		}
	}
	return version
}
func getVersionFromWhitelist(list []model.DriftGlobalWhitelistItem) int64 {
	version := int64(0)
	for _, p := range list {
		if p.UpdatedAt > version {
			version = p.UpdatedAt
		}
	}
	return version
}

func (api *api) driftAllPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("get cluster_key error")
			clusterKey = ""
		}
		policiesVersion, err := param.QueryInt64(r, "policies_version")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("get policies_version error")
			policiesVersion = 0
		}
		wlistVersion, err := param.QueryInt64(r, "wlist_version")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("get wlist_version error")
			wlistVersion = 0
		}

		clusterPolicies, err := driSvc.GetAllPolicies(ctx, clusterKey)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GetAllPolicies error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("GetAllPolicies error")))
			return
		}
		var policies []model.DriftPolicy
		if policiesVersion == 0 {
			policies = clusterPolicies.Policies
		} else {
			if clusterPolicies.VersionStamp != policiesVersion {
				policies = clusterPolicies.Policies
			} else {
				clusterPolicies.Policies = nil
			}
		}

		whitelist, err := driSvc.GetAllGlobalWhitelist(ctx)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GetAll whitelist error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("GetAll whitelist error")))
			return
		}
		if wlistVersion != 0 && whitelist.VersionStamp == wlistVersion {
			whitelist.Whitelist = nil
		}

		// TODO tmp don't repeat data
		clusterPolicies.Policies = nil
		response.Ok(w, response.WithItems(policies),
			response.WithTotalItems(int64(len(policies))),
			response.WithCustomField("g_whitelist", whitelist),
			response.WithCustomField("policies", clusterPolicies),
		)
	}
}

func (api *api) driftCreatePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		type tmp struct {
			PolicyID int64 `json:"policy_id"`
		}
		policy := model.DriftPolicyCreate{}
		err := util.DecodeJSONBody(w, r, &policy)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		tmpPolicy := model.DriftPolicy{Enable: policy.Enable, Mode: policy.Mode, Creator: request.GetAccountFromContext(r.Context()), ClusterKey: policy.ClusterKey,
			Namespace: policy.Namespace, Resource: policy.Resource, ResourceKind: policy.ResourceKind}
		tmpPolicy.ResourceUUID = util.GenerateUUID(policy.ClusterKey, policy.Namespace, policy.ResourceKind, policy.Resource)
		id, err := driSvc.CreatePolicy(ctx, tmpPolicy)
		if err != nil {
			if strings.Contains(err.Error(), "same uuid") {
				logging.GetLogger().Err(err).Msg("Create Same policy")
				apperror.RespAndLog(w, ctx, apperror.NewDriftPolicyError(http.StatusInternalServerError, errors.New("Create Same policy")))
			} else {
				logging.GetLogger().Err(err).Msg("CreatePolicy error")
				apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("CreatePolicy error")))
			}
			return
		}
		respTmp := tmp{PolicyID: id}
		clusterManager, ok := k8s.GetClusterManager()
		policyName := policy.ClusterKey
		if ok {
			policyName, err = clusterManager.GetClusterName(policy.ClusterKey)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("GetClusterName error")
				policyName = policy.ClusterKey
			}
		}
		response.Ok(w, response.WithItem(respTmp), response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(id)), Name: fmt.Sprintf("%s/%s/%s(%s)", policyName, policy.Namespace, policy.Resource, policy.ResourceKind)}))
	}
}

func (api *api) driftCreateBatchPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		type tmpReq struct {
			Data []model.DriftPolicyCreate `json:"data"`
		}

		var reqData tmpReq

		err := util.DecodeJSONBody(w, r, &reqData)

		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		if len(reqData.Data) == 0 {
			logging.GetLogger().Warn().Msg("data is empty")
			apperror.RespAndLog(w, ctx,
				apperror.NewDriftPolicyCreateNullError(http.StatusBadRequest,
					fmt.Errorf("data is empty")))
			return
		}

		policyItems := reqData.Data
		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		existPolicies, err := driSvc.GetAllPoliciesFromDB(ctx, "")
		if err != nil {
			logging.GetLogger().Warn().Msg("GetAllPolicies error")
		}
		creator := request.GetAccountFromContext(r.Context())

		var insertItems []model.DriftPolicy
		for _, item := range policyItems {
			tmpPolicy := model.DriftPolicy{Enable: item.Enable, Mode: item.Mode, Creator: creator, ClusterKey: item.ClusterKey,
				Namespace: item.Namespace, Resource: item.Resource, ResourceKind: item.ResourceKind}
			tmpPolicy.ResourceUUID = util.GenerateUUID(item.ClusterKey, item.Namespace, item.ResourceKind, item.Resource)
			if len(existPolicies) > 0 {
				for _, existPolicy := range existPolicies {
					if existPolicy.ResourceUUID == tmpPolicy.ResourceUUID {
						logging.GetLogger().Warn().Uint32("policy ResourceUUID", tmpPolicy.ResourceUUID).Msg("policy already exist")
						continue
					}
				}
			}
			insertItems = append(insertItems, tmpPolicy)
		}
		resp, err := driSvc.CreatePolicies(ctx, insertItems)
		if err != nil {
			logging.GetLogger().Err(err).Msg("CreatePolicies error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("CreatePolicies error")))
			return
		}
		response.Ok(w, response.WithItems(resp), response.WithTotalItems(int64(len(resp))))
	}
}

func (api *api) driftDeletePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		policyIDS, err := param.QueryString(r, "policy_id")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get policy id error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get policy id error")))
			return
		}
		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		policyID, err := strconv.ParseInt(policyIDS, 10, 64)
		if err != nil {
			logging.GetLogger().Err(err).Msg("policy ID not int")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("policy ID not int")))
			return
		}
		policy, err := driSvc.DeletePolicy(ctx, policyID)
		if err == drift.ErrPolicyEnabledCannotDelete {
			logging.GetLogger().Warn().Err(err).Int64("policyID", policyID).Msg("Policy is not disabled. cannot be deleted")
			apperror.RespAndLog(w, ctx, apperror.NewDriftPolicyDeletionNotDisabledWarn(err))
			return
		} else if err != nil {
			logging.GetLogger().Err(err).Msg("DeletePolicy error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("DeletePolicy error")))
			return
		}
		clusterManager, ok := k8s.GetClusterManager()
		policyName := policy.ClusterKey
		if ok {
			policyName, err = clusterManager.GetClusterName(policy.ClusterKey)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("GetClusterName error")
				policyName = policy.ClusterKey
			}
		}
		response.Ok(w, response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(policyID)), Name: fmt.Sprintf("%s/%s/%s(%s)", policyName, policy.Namespace, policy.Resource, policy.ResourceKind)}))
	}
}

func (api *api) driftUpdatePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		policyUpdate := model.DriftPolicyUpdate{}
		err := util.DecodeJSONBody(w, r, &policyUpdate)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		policyUpdate.Updater = request.GetAccountFromContext(r.Context())

		policy, err := driSvc.UpdatePolicy(ctx, policyUpdate)
		if err != nil {
			logging.GetLogger().Err(err).Msg("UpdatePolicy error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("UpdatePolicy error")))
			return
		}
		clusterManager, ok := k8s.GetClusterManager()
		policyName := policy.ClusterKey
		if ok {
			policyName, err = clusterManager.GetClusterName(policy.ClusterKey)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("GetClusterName error")
				policyName = policy.ClusterKey
			}
		}
		response.Ok(w, response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(policyUpdate.PolicyID)), Name: fmt.Sprintf("%s/%s/%s(%s)", policyName, policy.Namespace, policy.Resource, policy.ResourceKind)}))
	}
}

func (api *api) driftUpdateBatchPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		type tmpReqData struct {
			Data []model.DriftPolicyUpdate `json:"data"`
		}
		reqData := tmpReqData{}
		err := util.DecodeJSONBody(w, r, &reqData)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		updater := request.GetAccountFromContext(r.Context())
		for i := range reqData.Data {
			reqData.Data[i].Updater = updater
		}

		_, errs := driSvc.UpdatePolicies(ctx, reqData.Data)
		if len(errs) > 0 {
			retErrs := make([]apperror.Suberror, 0)
			for _, err := range errs {
				logging.GetLogger().Err(err).Msg("UpdatePolicies error")
				retErrs = append(retErrs, apperror.Suberror{
					Location: "UpdatePolicies",
					Message:  err.Error(),
				})
			}
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("UpdatePolicies error"), retErrs...))
			return
		}
		response.Ok(w)
	}
}

func (api *api) driftPolicyByID() http.HandlerFunc {
	type RespData struct {
		model.DriftPolicy
		ScannerStatus int8 `json:"scanner_status"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		idStr := chi.URLParam(r, "policyID")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("idStr:", idStr).Msg("get id fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		policy, err := driSvc.GetPolicyByID(ctx, id)
		if err != nil {
			logging.GetLogger().Err(err).Msg("get policy error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get policy error")))
			return
		}

		resp := RespData{policy, 0}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("get drift service fail")
		} else {
			query := dal.ResourcesQuery()
			query = query.WithCluster(policy.ClusterKey)
			query = query.WithNamespace(policy.Namespace)
			query = query.WithResourceKind(assetsPkg.ResourceKind(policy.ResourceKind))
			query = query.WithResourceName(policy.Resource)

			resources, resCnt, err := resSvc.GetResources(ctx, query, 0, 1)
			if err != nil || resCnt == 0 || len(resources) == 0 {
				logging.GetLogger().Error().Err(err).
					Str("resource_info: ", fmt.Sprintf("cluster: %s namespace: %s name: %s", policy.ClusterKey, policy.Namespace, policy.Resource)).
					Msg("get resources fail")
			}

			if len(resources) > 0 {
				resp.ScannerStatus = resources[0].ScannerStatus
			}
		}

		response.Ok(w, response.WithItem(resp))
	}
}

func filterAbnormalInPolicy(policy model.DriftPolicy, signals []*palace.Signal) []model.DriftPolicyAbnormal {
	policyCreateTimestamp := policy.CreatedAt.UnixMilli()
	res := []model.DriftPolicyAbnormal{}
	for _, v := range signals {
		if policyCreateTimestamp > v.CreatedAt {
			// logging.GetLogger().Warn().Msgf("signal:%v happend before policy:%v created", v, policy)
			continue
		}
		tmpRes := model.DriftPolicyAbnormal{HappendTime: v.CreatedAt}
		if ct, ok := (*v.Scope)["container"]; ok {
			tmpRes.ContainerID = ct.ID
		} else {
			logging.GetLogger().Error().Msgf("container not found in scope:%v", v.Scope)
			continue
		}

		if pod, ok := (*v.Scope)["pod"]; ok {
			tmpRes.PodName = pod.Name
		} else {
			logging.GetLogger().Error().Msgf("pod not found in scope:%v", v.Scope)
			continue
		}

		if filePath, ok := v.Context["file_path"].(string); !ok {
			logging.GetLogger().Error().Msgf("file_path not found in context:%v", v.Context)
			continue
		} else {
			tmpRes.FilePath = filePath
		}

		if action, ok := v.Context["action"].(string); !ok {
			logging.GetLogger().Error().Msgf("action not found in context:%v", v.Context)
			continue
		} else {
			if action == "hit_whitelist" {
				tmpRes.IsInGlobalWhitelist = true
			} else {
				tmpRes.IsInGlobalWhitelist = false
			}
			tmpRes.Action = action
		}
		tmpRes.ID = v.ID

		res = append(res, tmpRes)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].HappendTime > res[j].HappendTime })
	return res
}

func (api *api) driftListPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get cluster_key error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get cluster_key error")))
			return
		}

		offset, err := param.QueryInt(r, "offset")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get offset error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get offset error")))
			return
		}

		limit, err := param.QueryInt(r, "limit")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get limit error")))
			return
		}

		resource, err := param.QueryString(r, "resource_type")
		var resources []string
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("get resource error")
		} else {
			resources = strings.Split(resource, ",")
		}
		namespace, err := param.QueryString(r, "namespace")
		var namespaces []string
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("get namespace error")
		} else {
			namespaces = strings.Split(namespace, ",")
		}

		enable, err := param.QueryString(r, "enable")
		var enables []string
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("get enable error")
		} else {
			enables = strings.Split(enable, ",")
		}

		status, err := param.QueryString(r, "status")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("get status error")
			status = ""
		}

		mode, err := param.QueryString(r, "mode")
		var modes []string
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("get mode error")
		} else {
			modes = strings.Split(mode, ",")
		}
		search, err := param.QueryString(r, "search")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("get search error")
		}
		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		policies, _, err := driSvc.ListPolicy(ctx, math.MaxInt, 0, clusterKey, resources, namespaces, enables, modes, search)
		if err != nil {
			logging.GetLogger().Error().Msg("ListPolicy error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("ListPolicy error")))
			return
		}
		if len(policies) == 0 {
			logging.GetLogger().Warn().Msg("policies is empty")
			response.Ok(w, response.WithItems([]model.DriftListPolicyResp{}), response.WithTotalItems(0))
			return
		}

		resSvc, ok := assets.GetResourcesService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("get drift service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get drift service fail")))
			return
		}

		res := []model.DriftListPolicyResp{}
		for _, v := range policies {

			query := dal.ResourcesQuery()
			query = query.WithCluster(v.ClusterKey)
			query = query.WithNamespace(v.Namespace)
			query = query.WithResourceKind(assetsPkg.ResourceKind(v.ResourceKind))
			query = query.WithResourceName(v.Resource)

			resources, resCnt, err := resSvc.GetResources(ctx, query, 0, 1)
			if err != nil || resCnt == 0 || len(resources) == 0 {
				logging.GetLogger().Error().Err(err).
					Str("resource_info: ", fmt.Sprintf("cluster: %s namespace: %s name: %s", v.ClusterKey, v.Namespace, v.Resource)).
					Msg("get resources fail")
			}
			if status == "1" && len(resources) != 0 && resources[0].ScannerStatus > 1 {
				continue
			}
			if enable != "" && (len(resources) == 0 || resources[0].ScannerStatus <= 1) {
				continue
			}
			tmpResp := model.DriftListPolicyResp{ClusterKey: v.ClusterKey, Namespace: v.Namespace, Enable: v.Enable, Mode: v.Mode, Resource: v.Resource, ResourceKind: v.ResourceKind, PolicyID: v.ID}
			if len(resources) > 0 {
				tmpResp.ScannerStatus = resources[0].ScannerStatus
			} else {
				tmpResp.ScannerStatus = 0
			}
			signals, err := driSvc.GetAbnormal(ctx, v, 3000, "", "")
			if err != nil {
				logging.GetLogger().Err(err).Msgf("GetAbnormal error")
				continue
			}
			tmpResp.AbnormalNum = len(filterAbnormalInPolicy(v, signals))
			res = append(res, tmpResp)
		}
		// 程序中分页
		start := int(offset)
		end := int(offset + limit)
		cnt := len(res)
		if len(res) <= start {
			res = make([]model.DriftListPolicyResp, 0)
		} else {
			res = res[start:util.MinInt(end, len(res))]
		}

		response.Ok(w, response.WithItems(res), response.WithTotalItems(int64(cnt)))
	}
}

func (api *api) driftPolicyDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		policyID, err := param.QueryInt64(r, "policy_id")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get policy_id error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get policy_id error")))
			return
		}
		offset, err := param.QueryInt(r, "offset")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get offset error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get offset error")))
			return
		}

		limit, err := param.QueryInt(r, "limit")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get limit error")))
			return
		}

		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		policy, err := driSvc.GetPolicyByID(ctx, policyID)
		if err != nil {
			logging.GetLogger().Err(err).Msg("get GetPolicyByID error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get GetPolicyByID error")))
			return
		}

		containers, err := driSvc.PolicyDetail(ctx, policy, limit, offset)
		if err != nil {
			logging.GetLogger().Err(err).Msg("get containers error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get containers error")))
			return
		}

		rawContainers, err := driSvc.GetRawContainers(ctx, policy)
		if err != nil {
			logging.GetLogger().Err(err).Msg("get raw containers error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get raw containers error")))
			return
		}

		res := []model.DriftPolicyDetailResp{}
		for _, tensorC := range containers {
			if tensorC.Status != 0 {
				logging.GetLogger().Warn().Msgf("container status is not 0 %d", tensorC.Status)
				continue
			}
			ids, err := driSvc.GetImageID(ctx, tensorC.ImageUUID)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("get image id error %d", tensorC.ImageUUID)
				continue
			}
			tmpResp := model.DriftPolicyDetailResp{}
			tmpResp.ContainerID = tensorC.ID
			tmpResp.ContainerName = tensorC.Name
			tmpResp.Image = tensorC.Image
			if len(ids) > 0 {
				tmpResp.ImageID = ids[0]
			}

			matchStr := fmt.Sprintf("k8s_%s_", tensorC.Name)
			logging.GetLogger().Debug().Msgf("matchStr:%v", matchStr)
			fullNames := make(map[string]struct{}, 0)
			for _, rawC := range rawContainers {
				logging.GetLogger().Debug().Msgf("rawC.Name:%v", rawC.Name)
				if strings.HasPrefix(rawC.Name, matchStr) || tensorC.Name == rawC.Name {
					if _, ok := fullNames[rawC.Name]; !ok {
						fullNames[rawC.Name] = struct{}{}
					}
				}
			}
			for k := range fullNames {
				tmpResp.ContainerFullNames = append(tmpResp.ContainerFullNames, k)
			}
			res = append(res, tmpResp)
		}
		logging.GetLogger().Debug().Msgf("res:%v", res)
		response.Ok(w, response.WithItems(res))
	}
}

func (api *api) driftContainerByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		containerID, err := param.QueryInt64(r, "container_id")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get container_id error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get container_id error")))
			return
		}

		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		con, err := driSvc.GetContainerByID(ctx, uint32(containerID))
		if err != nil {
			logging.GetLogger().Err(err).Msg("get containers error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get containerserror")))
			return
		}
		res := fromModelToContainer(&con)

		response.Ok(w, response.WithItem(res))
	}
}

func (api *api) driftPolicyAbnormal() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		policyID, err := param.QueryInt64(r, "policy_id")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get policy_id error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get policy_id error")))
			return
		}

		containerName, err := param.QueryString(r, "container_name")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get container_name error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get container_name error")))
			return
		}

		actionTargets, err := param.QueryString(r, "action")
		actionsMap := make(map[string]struct{})
		if err != nil {
			logging.GetLogger().Warn().Msgf("get action error")
			actionTargets = ""
		} else {
			for _, v := range strings.Split(actionTargets, ",") {
				actionsMap[v] = struct{}{}
			}
		}

		filePath, err := param.QueryString(r, "file_path")
		if err != nil {
			logging.GetLogger().Warn().Msgf("get file_path fail")
		}

		driSvc, ok := drift.GetDriftService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		policy, err := driSvc.GetPolicyByID(ctx, policyID)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GetPolicyByID error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("GetPolicyByID error")))
			return
		}

		logging.GetLogger().Info().Msgf("container_name :%v filePath:%v", containerName, filePath)
		signals, err := driSvc.GetAbnormal(ctx, policy, 3000, containerName, filePath)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GetAbnormal error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("GetAbnormal error")))
			return
		}
		tmpSignals := []*palace.Signal{}
		logging.GetLogger().Debug().Msgf("signals :%v, len: %v", signals, len(signals))
		if actionTargets != "" {
			for _, v := range signals {
				action, ok := v.Context["action"].(string)
				if !ok {
					logging.GetLogger().Error().Msgf("action not found in context:%v", v.Context)
					continue
				}
				if _, ok := actionsMap[action]; ok {
					tmpSignals = append(tmpSignals, v)
				}
			}
		} else {
			tmpSignals = signals
		}
		logging.GetLogger().Debug().Msgf("tmpSignals :%v, len: %v", tmpSignals, len(tmpSignals))

		res := filterAbnormalInPolicy(policy, tmpSignals)
		response.Ok(w, response.WithItems(res))
	}
}
