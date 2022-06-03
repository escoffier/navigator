package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/drift"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
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
		r.Get("/container", api.driftContainerByID())
		r.Get("/policy/abnormal", api.driftPolicyAbnormal())
		r.Get("/policy", api.driftAllPolicy())
		r.Get("/namespaces", api.driftNamespace())
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

		_, err := param.QueryInt64(r, "last_time")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get lastTime error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get lastTime error")))
			return
		}

		// if driSvc.Cache.LastTime == 0 {
		policies, err := driSvc.GetAllPolicies(ctx)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GetAllPolicies error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("GetAllPolicies error")))
			return
		}
		response.Ok(w, response.WithItems(policies), response.WithTotalItems(int64(len(policies))))
		// } else {
		// 	if lastTime < driSvc.Cache.LastTime {
		// 		policies := driSvc.Cache.Policies
		// 		response.Ok(w, response.WithItems(policies), response.WithTotalItems(int64(len(policies))))
		// 	} else {
		// 		response.Ok(w, response.WithTotalItems(-1))
		// 	}
		// }
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
			logging.GetLogger().Err(err).Msg("CreatePolicy error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("CreatePolicy error")))
			return
		}
		respTmp := tmp{PolicyID: id}
		response.Ok(w, response.WithItem(respTmp))
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
		err = driSvc.DeletePolicy(ctx, policyID)
		if err != nil {
			logging.GetLogger().Err(err).Msg("DeletePolicy error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("DeletePolicy error")))
			return
		}
		response.Ok(w)
	}
}

func (api *api) driftUpdatePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		policy := model.DriftPolicyUpdate{}
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
		err = driSvc.UpdatePolicy(ctx, policy)
		if err != nil {
			logging.GetLogger().Err(err).Msg("UpdatePolicy error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("UpdatePolicy error")))
			return
		}
		response.Ok(w)
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
		enable, err := param.QueryString(r, "enable")
		var enables []string
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("get namespace error")
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

		policys, err := driSvc.ListPolicy(ctx, limit, offset, clusterKey, resources, enables, modes, search)
		if err != nil {
			logging.GetLogger().Error().Msg("ListPolicy error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("ListPolicy error")))
			return
		}
		res := []model.DriftListPolicyResp{}
		for _, v := range policys {
			signals, err := driSvc.GetAbnormal(ctx, v, 3000, "", "", "")
			if err != nil {
				logging.GetLogger().Err(err).Msgf("GetAbnormal error")
				continue
			}
			tmpResp := model.DriftListPolicyResp{ClusterKey: v.ClusterKey, Namespace: v.Namespace, Enable: v.Enable, Mode: v.Mode, Resource: v.Resource, ResourceKind: v.ResourceKind, PolicyID: v.ID}
			tmpResp.AbnormalNum = len(signals)
			res = append(res, tmpResp)
		}
		response.Ok(w, response.WithItems(res))
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
		signals, err := driSvc.GetAbnormal(ctx, policy, 3000, "", containerName, filePath)
		if err != nil {
			logging.GetLogger().Err(err).Msg("GetAbnormal error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("GetAbnormal error")))
			return
		}

		res := []model.DriftPolicyAbnormal{}
		for _, v := range signals {
			flag := true
			tmpres := model.DriftPolicyAbnormal{}
			for _, vv := range v.CustomKV {
				if kv, ok := vv.KVHash["en"]; ok {
					if kv.Key == "containerId" {
						tmpres.ContainerID = kv.Value
					}
					if kv.Key == "filePath" {
						if filePath != "" && !strings.Contains(kv.Value, filePath) {
							flag = false
						}
						tmpres.FilePath = kv.Value
					}
				}
			}
			if flag {
				tmpres.PodName = v.PodName
				tmpres.HappendTime = v.Timestamp
				res = append(res, tmpres)
			}
		}
		sort.Slice(res, func(i, j int) bool { return res[i].HappendTime > res[j].HappendTime })
		response.Ok(w, response.WithItems(res))
	}
}
