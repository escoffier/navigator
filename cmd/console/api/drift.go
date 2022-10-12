package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/drift"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) drift() func(chi.Router) {
	return func(r chi.Router) {
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
		//TODO: field security check

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
			Creator:   whitelistItem.Creator,
			Updater:   whitelistItem.Creator,
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
		workerNs := os.Getenv("MY_POD_NAMESPACE")
		namespacesDefault := map[string]struct{}{
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
		tmpPolicy := model.DriftPolicy{Enable: policy.Enable, Mode: policy.Mode, Creator: policy.Creator, ClusterKey: policy.ClusterKey,
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
		if err != nil {
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

func (api *api) driftPolicyByID() http.HandlerFunc {
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

		response.Ok(w, response.WithItem(policy))
	}
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

		policys, count, err := driSvc.ListPolicy(ctx, limit, offset, clusterKey, resources, namespaces, enables, modes, search)
		if err != nil {
			logging.GetLogger().Error().Msg("ListPolicy error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("ListPolicy error")))
			return
		}
		res := []model.DriftListPolicyResp{}
		for _, v := range policys {
			signals, err := driSvc.GetAbnormal(ctx, v, 3000, "", "")
			if err != nil {
				logging.GetLogger().Err(err).Msgf("GetAbnormal error")
				continue
			}
			tmpResp := model.DriftListPolicyResp{ClusterKey: v.ClusterKey, Namespace: v.Namespace, Enable: v.Enable, Mode: v.Mode, Resource: v.Resource, ResourceKind: v.ResourceKind, PolicyID: v.ID}
			tmpResp.AbnormalNum = len(signals)
			res = append(res, tmpResp)
		}
		response.Ok(w, response.WithItems(res), response.WithTotalItems(count))
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
		res := []model.DriftPolicyDetailResp{}
		for _, v := range containers {
			ids, err := driSvc.GetImageID(ctx, v.ImageUUID)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("get image id error %d", v.ImageUUID)
				continue
			}
			tmpResp := model.DriftPolicyDetailResp{}
			tmpResp.ContainerID = v.ID
			tmpResp.ContainerName = v.Name
			tmpResp.Image = v.Image
			if len(ids) > 0 {
				tmpResp.ImageID = ids[0]
			}
			res = append(res, tmpResp)
		}
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

		filePath, err := param.QueryString(r, "file_path")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get file_path error")
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

		res := []model.DriftPolicyAbnormal{}
		for _, v := range signals {
			tmpres := model.DriftPolicyAbnormal{HappendTime: v.CreatedAt}
			if ct, ok := (*v.Scope)["container"]; ok {
				tmpres.ContainerID = ct.ID
			} else {
				continue
			}

			if pod, ok := (*v.Scope)["pod"]; ok {
				tmpres.PodName = pod.Name
			} else {
				continue
			}

			if tmpres.FilePath, ok = v.Context["filePath"].(string); !ok {
				continue
			}

			if action, ok := v.Context["action"].(string); !ok {
				continue
			} else {
				if action == "hit_whitelist" {
					tmpres.IsInGlobalWhitelist = true
				} else {
					tmpres.IsInGlobalWhitelist = false
				}
			}
			tmpres.ID = v.ID

			res = append(res, tmpres)
		}
		sort.Slice(res, func(i, j int) bool { return res[i].HappendTime > res[j].HappendTime })
		response.Ok(w, response.WithItems(res))
	}
}
