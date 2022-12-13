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
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) driftOpen() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/policy/create", api.driftCreatePolicyOpen())
		r.Post("/policy/update", api.driftUpdatePolicyOpen())
		r.Post("/policy/delete", api.driftDeletePolicyOpen())
		r.Get("/policy/list", api.driftListPolicyOpen())
		r.Get("/policy/detail", api.driftPolicyDetailOpen())
		r.Get("/container", api.driftContainerByIDOpen())
		r.Get("/policy/abnormal", api.driftPolicyAbnormalOpen())
		r.Get("/namespaces", api.driftNamespaceOpen())
	}
}

func (api *api) driftNamespaceOpen() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit or offset query error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		clusterKey, err := param.QueryString(r, "clusterKey")
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

func (api *api) driftCreatePolicyOpen() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		type tmp struct {
			PolicyID int64 `json:"policyId"`
		}
		policy := model.OpenDriftPolicyCreate{}
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

func (api *api) driftDeletePolicyOpen() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		policyIDS, err := param.QueryString(r, "policyId")
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
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("DeletePolicy error")))
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

func (api *api) driftUpdatePolicyOpen() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		policyUpdate := model.OpenDriftPolicyUpdate{}
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
		oldUpdate := model.DriftPolicyUpdate{
			PolicyID: policyUpdate.PolicyID,
			Enable:   policyUpdate.Enable,
			Mode:     policyUpdate.Mode,
			Updater:  policyUpdate.Updater,
		}
		policy, err := driSvc.UpdatePolicy(ctx, oldUpdate)
		if err != nil {
			logging.GetLogger().Err(err).Msg("UpdatePolicy error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("UpdatePolicy error")))
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

func (api *api) driftListPolicyOpen() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		clusterKey, err := param.QueryString(r, "clusterKey")
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

		resource, err := param.QueryString(r, "resourceType")
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
		res := []model.OpenDriftListPolicyResp{}
		for _, v := range policys {
			signals, err := driSvc.GetAbnormal(ctx, v, 3000, "", "")
			if err != nil {
				logging.GetLogger().Err(err).Msgf("GetAbnormal error")
				continue
			}
			tmpResp := model.OpenDriftListPolicyResp{ClusterKey: v.ClusterKey, Namespace: v.Namespace, Enable: v.Enable, Mode: v.Mode, Resource: v.Resource, ResourceKind: v.ResourceKind, PolicyID: v.ID}
			tmpResp.AbnormalNum = len(signals)
			res = append(res, tmpResp)
		}
		response.Ok(w, response.WithItems(res), response.WithTotalItems(count))
	}
}

func (api *api) driftPolicyDetailOpen() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		policyID, err := param.QueryInt64(r, "policyId")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get policyId error")
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
		res := []model.OpenDriftPolicyDetailResp{}
		for _, v := range containers {
			ids, err := driSvc.GetImageID(ctx, v.ImageUUID)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("get image id error %d", v.ImageUUID)
				continue
			}
			tmpResp := model.OpenDriftPolicyDetailResp{}
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

func (api *api) driftContainerByIDOpen() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		containerID, err := param.QueryInt64(r, "containerId")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get containerId error")
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
		oldContainer := fromModelToContainer(&con)
		res := fromOldToNewContainer(oldContainer)
		response.Ok(w, response.WithItem(res))
	}
}
func fromOldToNewContainer(cm *container) *model.OpenDriftContainer {
	return &model.OpenDriftContainer{
		Cluster:       cm.Cluster,
		Namespace:     cm.Namespace,
		ResourceKind:  cm.ResourceKind,
		ResourceName:  cm.ResourceName,
		Name:          cm.Name,
		WorkingDir:    cm.WorkingDir,
		Command:       cm.Command,
		Type:          cm.Type,
		ImageRepo:     cm.ImageRepo,
		ImageTag:      cm.ImageTag,
		ImageName:     cm.ImageName,
		Ports:         cm.Ports,
		Envs:          cm.Envs,
		FrameWorkInfo: cm.FrameWorkInfo,
		VolumeMounts:  cm.VolumeMounts,
	}
}
func (api *api) driftPolicyAbnormalOpen() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()
		policyID, err := param.QueryInt64(r, "policyId")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get policyId error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get policyId error")))
			return
		}

		containerName, err := param.QueryString(r, "containerName")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get container_name error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("get containerName error")))
			return
		}

		filePath, err := param.QueryString(r, "filePath")
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get filePath error")
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

		res := []model.DriftPolicyAbnormalOpen{}
		for _, v := range signals {
			tmpres := model.DriftPolicyAbnormalOpen{HappendTime: v.CreatedAt}
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

			res = append(res, tmpres)
		}
		sort.Slice(res, func(i, j int) bool { return res[i].HappendTime > res[j].HappendTime })
		response.Ok(w, response.WithItems(res))
	}
}
