package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"

	bl "gitlab.com/piccolo_su/vegeta/cmd/console/service/behavioral-learn"

	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) behavioralLearn() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/start", api.startLearning())
		r.Get("/status", api.getLearningStatus())
		r.Post("/stop", api.stopLearning())
		r.Get("/resource/basic", api.getLearningBasicInfo())
		r.Post("/model/config", api.behavioralLearnModelConfig())
		r.Get("/model/file", api.getLearningResourceModelFile())
		r.Get("/model/command", api.behavioralLearnModelCommand())
		r.Get("/model/network", api.behavioralLearnModelNetwork())
		r.Post("/model/file", api.behavioralLearnModelUpdateFile())
		r.Post("/model/command", api.behavioralLearnModelUpdateCommand())
		r.Post("/model/network", api.behavioralLearnModelUpdateNetwork())
		r.Delete("/model/file", api.behavioralLearnModelDeleteFile())
		r.Delete("/model/command", api.behavioralLearnModelDeleteCommand())
		r.Delete("/model/network", api.behavioralLearnModelDeleteNetwork())
		r.Put("/model/file", api.behavioralLearnModelAddFile())
		r.Put("/model/command", api.behavioralLearnModelAddCommand())
		r.Put("/model/network", api.behavioralLearnModelAddNetwork())
		r.Get("/model/log", api.behavioralLearnModelLogGet())
		r.Put("/global/command/whitelist", api.behavioralLearnGlobalCommandWhitelistAdd())
		r.Post("/global/command/whitelist", api.behavioralLearnGlobalCommandWhitelistUpdate())
		r.Get("/global/command/whitelist", api.behavioralLearnGlobalCommandWhitelistGet())
		r.Delete("/global/command/whitelist", api.behavioralLearnGlobalCommandWhitelistDelete())
		r.Put("/global/file/whitelist", api.behavioralLearnGlobalFileWhitelistAdd())
		r.Post("/global/file/whitelist", api.behavioralLearnGlobalFileWhitelistUpdate())
		r.Get("/global/file/whitelist", api.behavioralLearnGlobalFileWhitelistGet())
		r.Delete("/global/file/whitelist", api.behavioralLearnGlobalFileWhitelistDelete())
		r.Put("/global/network/whitelist", api.behavioralLearnGlobalNetworkWhitelistAdd())
		r.Post("/global/network/whitelist", api.behavioralLearnGlobalNetworkWhitelistUpdate())
		r.Get("/global/network/whitelist", api.behavioralLearnGlobalNetworkWhitelistGet())
		r.Delete("/global/network/whitelist", api.behavioralLearnGlobalNetworkWhitelistDelete())
		r.Post("/global/config", api.behavioralLearnGlobalConfigSet())
		r.Get("/global/config", api.behavioralLearnGlobalConfigGet())
		r.Put("/onekey/learn", api.behavioralLearnOneKeyLearn())
		r.Put("/model/onekey/enabled", api.behavioralLearnOneKeyEnabled())
		r.Post("/model/out/file", api.behavioralLearnModelAddFileFromOutSide())
		r.Post("/model/out/command", api.behavioralLearnModelAddCommandFromOutSide())
		r.Post("/model/out/network", api.behavioralLearnModelAddNetworkFromOutSide())
	}
}

func (api *api) startLearning() http.HandlerFunc {
	type reqResourceItem struct {
		ResourceUUID uint32 `json:"resource_id"`
		Time         int64  `json:"time,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var reqData []reqResourceItem
		logging.GetLogger().Info().Msgf("request body: %v", r.Body)

		err := util.DecodeJSONBody(w, r, &reqData)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode json body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewLearnTaskCreateNullError(http.StatusBadRequest,
					err))
			return
		}
		if len(reqData) == 0 {
			logging.GetLogger().Warn().Msg("data is empty")
			apperror.RespAndLog(w, ctx,
				apperror.NewDriftPolicyCreateNullError(http.StatusBadRequest,
					fmt.Errorf("data is empty")))
			return
		}

		uuids := make([]uint32, 0)
		tasks := make([]model.BehavioralLearnTaskItem, 0)
		for _, d := range reqData {
			if d.Time > 1800 {
				logging.GetLogger().Warn().Msg("learn time is too long")
				d.Time = 1800
			}
			tasks = append(tasks, model.BehavioralLearnTaskItem{
				ResourceUUID: d.ResourceUUID,
				LearnTime:    d.Time,
			})
			uuids = append(uuids, d.ResourceUUID)
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		res, err := blSvc.BehavioralLearnStart(ctx, tasks)
		if err != nil {
			if errors.Is(err, bl.AlreadyLearningError) {
				apperror.RespAndLog(w, ctx, apperror.BehavioralLearnStartError(http.StatusInternalServerError, err))
				return
			}

			logging.GetLogger().Error().Err(err).Msg("start behavioral learn fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("start behavioral learn fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		blSvc.LogModelOperations(ctx, uuids, userName, "START", "learn")
		targetRef := &response.TargetRef{}
		if len(res) > 0 {
			idStr := fmt.Sprintf("%d", res[0].ID)
			nameStr := fmt.Sprintf("%s/%s/%s(%s)", res[0].ClusterKey, res[0].Namespace, res[0].Name, res[0].Kind)
			for _, r := range res[1:] {
				idStr += fmt.Sprintf(",%d", r.ID)
				nameStr += fmt.Sprintf(",%s/%s/%s(%s)", r.ClusterKey, r.Namespace, r.Name, r.Kind)
			}
			targetRef.ID = idStr
			targetRef.Name = nameStr
		}

		response.Ok(w, response.WithTotalItems(int64(len(reqData))), response.WithTarget(targetRef))
	}
}

func (api *api) getLearningStatus() http.HandlerFunc {
	type respResourceItem struct {
		ResourceUUID uint32   `json:"resource_id"`
		Cluster      string   `json:"cluster"`
		Namespace    string   `json:"namespace"`
		Kind         string   `json:"kind"`
		Name         string   `json:"name"`
		StartTime    int64    `json:"start_time"`
		LearnTime    int64    `json:"learn_time"`
		Images       []string `json:"images"`
		IsCanLearn   bool     `json:"is_can_learn"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get limit and offset fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, err))
			return
		}

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get cluster_key fail")
		}
		clusterKeyList := make([]string, 0)
		for _, s := range strings.Split(clusterKey, ",") {
			if s == "" {
				continue
			}
			clusterKeyList = append(clusterKeyList, s)
		}

		resourceKind, err := param.QueryString(r, "resource_kind")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get resource_kind fail")
		}
		resourceKindList := make([]string, 0)

		for _, s := range strings.Split(resourceKind, ",") {
			if s == "" {
				continue
			}
			resourceKindList = append(resourceKindList, s)
		}

		startTime := int64(0)
		// endTime max int64
		endTime := int64(0)

		startTimeReq, err := param.QueryInt64(r, "start_time")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get start_time fail")
		} else {
			startTime = startTimeReq
		}

		endTimeReq, err := param.QueryInt64(r, "end_time")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get end_time fail")
		} else {
			endTime = endTimeReq
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get namespace fail")
		}

		imageName, err := param.QueryString(r, "image_name")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get image_name fail")
		}

		resourceName, err := param.QueryString(r, "resource_name")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get resource_name fail")
		}

		learnStatusStr, err := param.QueryString(r, "learn_status")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get learn_status fail")
		}

		statusList := strings.Split(learnStatusStr, ",")

		learnStatus := make([]int8, 0)
		for _, s := range statusList {
			if s == "" {
				continue
			}
			i, err := strconv.Atoi(s)
			if err != nil {
				logging.GetLogger().Warn().Err(err).Msg("get learn_status fail")
				continue
			}
			learnStatus = append(learnStatus, int8(i))
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}
		// 前端组件时间精度是毫秒，记录精度是秒，需要损失部分精度
		resources, size, err := blSvc.GetResourcesStatus(ctx, namespace, resourceName, imageName, clusterKeyList, resourceKindList,
			startTime/1000, endTime/1000, limit, offset, learnStatus)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource status fail")
		}
		resp := resources
		response.Ok(w,
			response.WithItems(resp),
			response.WithTotalItems(size),
			response.WithStartIndex(int64(offset)),
			response.WithItemsPerPage(int64(limit)),
		)
	}
}

func (api *api) stopLearning() http.HandlerFunc {

	type reqResourceItem struct {
		ResourceUUID uint32 `json:"resource_id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var reqData reqResourceItem
		err := util.DecodeJSONBody(w, r, &reqData)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode json body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		task := model.BehavioralLearnTaskItem{
			ResourceUUID: reqData.ResourceUUID,
			LearnTime:    0,
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		res, err := blSvc.BehavioralLearnStop(ctx, task)
		if err != nil {
			if errors.Is(err, bl.AlreadyNotLearningError) {
				apperror.RespAndLog(w, ctx, apperror.BehavioralLearnStopError(http.StatusInternalServerError, err))
				return
			}

			logging.GetLogger().Error().Err(err).Msg("stop behavioral learn fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("stop behavioral learn fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		blSvc.LogModelOperations(ctx, []uint32{reqData.ResourceUUID}, userName, "STOP", "learn")
		targetRef := &response.TargetRef{}
		if len(res) > 0 {
			idStr := fmt.Sprintf("%d", res[0].ID)
			nameStr := fmt.Sprintf("%s/%s/%s(%s)", res[0].ClusterKey, res[0].Namespace, res[0].Name, res[0].Kind)
			for _, r := range res[1:] {
				idStr += fmt.Sprintf(",%d", r.ID)
				nameStr += fmt.Sprintf(",%s/%s/%s(%s)", r.ClusterKey, r.Namespace, r.Name, r.Kind)
			}
			targetRef.ID = idStr
			targetRef.Name = nameStr
		}

		response.Ok(w, response.WithTarget(targetRef))
	}
}

func (api *api) getLearningBasicInfo() http.HandlerFunc {
	type bhrespContainer struct {
		ContainerID string `json:"container_id"`
		Image       string `json:"image"`
		Name        string `json:"name"`
	}
	type respResourceItem struct {
		ResourceUUID uint32            `json:"resource_id"`
		Cluster      string            `json:"cluster"`
		Namespace    string            `json:"namespace"`
		Kind         string            `json:"kind"`
		Name         string            `json:"name"`
		LearnStatus  int8              `json:"learn_status"`
		StartTime    int64             `json:"start_time"`
		LearnTime    int64             `json:"learn_time"`
		Containers   []bhrespContainer `json:"containers"`
		IsCanLearn   bool              `json:"is_can_learn"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		resourceUUID, err := param.QueryUint32(r, "resource_id")
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource_id fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get resource_id fail")))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		resource, err := blSvc.GetResourceBasicInfo(ctx, resourceUUID)
		if err != nil || resource == nil {
			logging.GetLogger().Error().Err(err).Msg("get resource basic info fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get resource basic info fail")))
			return
		}

		containers, err := blSvc.GetResourceContainerInfo(ctx, resource.ClusterKey, resource.Namespace, resource.Kind, resource.Name)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource container info fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get resource container info fail")))
			return
		}
		isCanLearn := false
		respContainers := make([]bhrespContainer, 0)
		for _, c := range containers {
			if c.Status == 0 {
				isCanLearn = true
			}
			respContainers = append(respContainers, bhrespContainer{
				ContainerID: c.ContainerID,
				Image:       c.Image,
				Name:        c.Name,
			})
		}
		resp := respResourceItem{
			ResourceUUID: resource.ID,
			Cluster:      resource.ClusterKey,
			Namespace:    resource.Namespace,
			Kind:         resource.Kind,
			Name:         resource.Name,
			StartTime:    resource.BehavioralLearnStartTime,
			LearnTime:    resource.BehavioralLearnTime,
			LearnStatus:  resource.BehavioralLearnStatus,
			Containers:   respContainers,
			IsCanLearn:   isCanLearn,
		}

		response.Ok(w, response.WithItem(resp))
	}
}

func (api *api) behavioralLearnModelConfig() http.HandlerFunc {

	type reqData []model.BehavioralLearnModelConfig

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var reqData reqData
		err := util.DecodeJSONBody(w, r, &reqData)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode json body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		res, n, err := blSvc.BehavioralLearnModelConfig(ctx, reqData, userName)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("set behavioral learn model config fail")
			if errors.Is(err, bl.AlreadyEnabledError) {
				apperror.RespAndLog(w, ctx, apperror.BehavioralLearnEnableError(http.StatusInternalServerError, err))
				return
			}
			if errors.Is(err, bl.AlreadyDisabledError) {
				apperror.RespAndLog(w, ctx, apperror.BehavioralLearnDisableError(http.StatusInternalServerError, err))
				return
			}
			if errors.Is(err, bl.ErrEnabledInLearning) {
				apperror.RespAndLog(w, ctx, apperror.BehavioralLearnEnableInLearningError(http.StatusInternalServerError, err))
				return
			}
			if errors.Is(err, bl.ErrDisabledInLearning) {
				apperror.RespAndLog(w, ctx, apperror.BehavioralLearnDisableInLearningError(http.StatusInternalServerError, err))
				return
			}

			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("set behavioral learn model config fail")))
			return
		}
		targetRef := &response.TargetRef{}
		if len(res) > 0 {
			idStr := fmt.Sprintf("%d", res[0].ID)
			nameStr := fmt.Sprintf("%s/%s/%s(%s)", res[0].ClusterKey, res[0].Namespace, res[0].Name, res[0].Kind)
			for _, r := range res[1:] {
				idStr += fmt.Sprintf(",%d", r.ID)
				nameStr += fmt.Sprintf(",%s/%s/%s(%s)", r.ClusterKey, r.Namespace, r.Name, r.Kind)
			}
			targetRef.ID = idStr
			targetRef.Name = nameStr
		}

		response.Ok(w, response.WithTotalItems(int64(n)), response.WithTarget(targetRef))

	}
}

func (api *api) getLearningResourceModelFile() http.HandlerFunc {
	type fileModel struct {
		Id            string `json:"id"`
		Name          string `json:"name"`
		Path          string `json:"file_path"`
		Permission    int    `json:"permission"`
		EventID       string `json:"event_id"`
		UpdatedAt     int64  `json:"updated_at"`
		IsInModel     bool   `json:"is_in_model"`
		ContainerName string `json:"container_name"`
		CanAddModel   bool   `json:"can_add_model"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		resourceUUID, err := param.QueryUint32(r, "resource_id")
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource_id fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get resource_id fail")))
			return
		}

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get limit and offset fail")
			limit = 10
			offset = 0
		}

		searchStr, err := param.QueryString(r, "search_str")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get search_str fail")
		}

		permission, err := param.QueryInt(r, "permission")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get permission fail")
		}

		isInModel, err := param.QueryBool(r, "is_in_model")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get is_in_model fail")
		}

		startID, err := param.QueryUint64(r, "start_id")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get start_id fail")
			startID = 0
		}

		// cidStr, err := param.QueryString(r, "cids")
		// if err != nil {
		// 	logging.GetLogger().Warn().Err(err).Msg("get cids fail")
		// }

		// cids := strings.Split(cidStr, ",")

		cNameStr, err := param.QueryString(r, "cname")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get cname fail")
		}
		var cNames []string
		for _, cName := range strings.Split(cNameStr, ",") {
			if cName == "" {
				continue
			}
			cNames = append(cNames, cName)
		}

		allContainer, err := param.QueryBool(r, "all_container")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get all_container fail")
			allContainer = true
		}

		if !allContainer && len(cNames) == 0 {
			logging.GetLogger().Warn().Msg("get cids fail")
			response.Ok(w, response.WithItems([]fileModel{}),
				response.WithTotalItems(0),
				response.WithStartIndex(0),
				response.WithCustomField("next_id", 0),
				response.WithItemsPerPage(int64(limit)),
			)
			return
		}

		if allContainer {
			// cids = make([]string, 0)
			cNames = make([]string, 0)
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		fileModels, size, err := blSvc.GetResourcesFileModel(ctx, resourceUUID, searchStr, permission, isInModel, limit, offset, startID, cNames)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get file model fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get file model fail")))
			return
		}

		fileModelsExistMap := make(map[string]struct{})
		if !isInModel {
			inModelFileModel, _, err := blSvc.GetResourcesFileModel(ctx, resourceUUID, searchStr, permission, true, 0, 0, 0, cNames)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("get file model fail")
				apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get file model fail")))
				return
			}
			for _, f := range inModelFileModel {
				fileModelsExistMap[f.Path+fmt.Sprintf("%d", f.Permission)] = struct{}{}
			}
		}

		resp := make([]*fileModel, 0)
		for _, f := range fileModels {
			idStr := strconv.FormatUint(f.Id, 10)
			resp = append(resp, &fileModel{
				Id:            idStr,
				Name:          f.Name,
				Path:          f.Path,
				Permission:    f.Permission,
				UpdatedAt:     f.UpdatedAt,
				IsInModel:     f.IsInModel,
				ContainerName: f.ContainerName,
			})
			if f.IsInModel {
				continue
			}
			resp[len(resp)-1].CanAddModel = true
			if _, ok := fileModelsExistMap[f.Path+fmt.Sprintf("%d", f.Permission)]; ok {
				resp[len(resp)-1].CanAddModel = false
			}

			// get outside of model info
			signals, err := blSvc.GetFileModelFromEs(ctx, resourceUUID, f.Path, 0, 1)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("get file model from es fail")
				continue
			}
			if len(signals) == 0 {
				continue
			}
			resp[len(resp)-1].EventID = signals[0].ID
		}
		var nextID string = "0"
		if len(resp) > 0 {
			nextID = resp[len(resp)-1].Id
		}

		response.Ok(w, response.WithItems(resp),
			response.WithTotalItems(size),
			response.WithStartIndex(int64(offset)),
			response.WithCustomField("next_id", nextID),
			response.WithItemsPerPage(int64(limit)),
		)

	}
}

func (api *api) behavioralLearnModelCommand() http.HandlerFunc {
	type commandModel struct {
		Id            string `json:"id"`
		Command       string `json:"command"`
		UpdatedAt     int64  `json:"updated_at"`
		User          string `json:"user"`
		Path          string `json:"path"`
		IsInModel     bool   `json:"is_in_model"`
		EventID       string `json:"event_id"`
		ContainerName string `json:"container_name"`
		CanAddModel   bool   `json:"can_add_model"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		resourceUUID, err := param.QueryUint32(r, "resource_id")
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource_id fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get resource_id fail")))
			return
		}

		isInModel, err := param.QueryBool(r, "is_in_model")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get is_in_model fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get is_in_model fail")))
			return
		}

		searchStr, err := param.QueryString(r, "search_str")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get search_str fail")
		}

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get limit and offset fail")
			limit = 10
			offset = 0
		}

		startID, err := param.QueryUint64(r, "start_id")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get start_id fail")
			startID = 0
		}

		// cidStr, err := param.QueryString(r, "cids")
		// if err != nil {
		// 	logging.GetLogger().Warn().Err(err).Msg("get cids fail")
		// }

		// cids := strings.Split(cidStr, ",")

		cNameStr, err := param.QueryString(r, "cname")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get cname fail")
		}
		var cNames []string
		for _, cName := range strings.Split(cNameStr, ",") {
			if cName == "" {
				continue
			}
			cNames = append(cNames, cName)
		}

		allContainer, err := param.QueryBool(r, "all_container")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get all_container fail")
			// apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get all_container fail")))
			allContainer = true
		}

		if !allContainer && len(cNames) == 0 {
			logging.GetLogger().Warn().Msg("get cids fail")
			response.Ok(w, response.WithItems([]commandModel{}),
				response.WithTotalItems(0),
				response.WithStartIndex(0),
				response.WithCustomField("next_id", 0),
				response.WithItemsPerPage(int64(limit)),
			)
			return
		}

		if allContainer {
			// cids = make([]string, 0)
			cNames = make([]string, 0)
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		commands, size, err := blSvc.GetResourcesCommandModel(ctx, resourceUUID, searchStr, isInModel, limit, offset, startID, cNames)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get command model fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get command model fail")))
			return
		}

		var commandModelsExistMap = make(map[string]struct{})
		if !isInModel {
			inModelCommandModel, _, err := blSvc.GetResourcesCommandModel(ctx, resourceUUID, searchStr, true, 0, 0, 0, cNames)
			if err != nil {
				logging.GetLogger().Warn().Err(err).Msg("get command model fail")
			}
			for _, c := range inModelCommandModel {
				commandModelsExistMap[c.Path+c.Command+c.User] = struct{}{}
			}
		}

		resp := make([]*commandModel, 0)
		for _, c := range commands {
			idStr := strconv.FormatUint(c.Id, 10)
			resp = append(resp, &commandModel{
				Id:            idStr,
				Command:       c.Command,
				UpdatedAt:     c.UpdatedAt,
				User:          c.User,
				Path:          c.Path,
				IsInModel:     c.IsInModel,
				ContainerName: c.ContainerName,
			})
			if c.IsInModel {
				continue
			}
			resp[len(resp)-1].CanAddModel = true

			if _, ok := commandModelsExistMap[c.Path+c.Command+c.User]; ok {
				resp[len(resp)-1].CanAddModel = false
			}

			// get outside of model info
			signals, err := blSvc.GetCommandModelFromEs(ctx, resourceUUID, c.Path, c.Command, 0, 1)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("get command model from es fail")
				continue
			}
			if len(signals) == 0 {
				continue
			}
			resp[len(resp)-1].EventID = signals[0].ID
		}
		var nextID string = "0"
		if len(resp) > 0 {
			nextID = resp[len(resp)-1].Id
		}
		response.Ok(w, response.WithItems(resp),
			response.WithTotalItems(size),
			response.WithStartIndex(int64(offset)),
			response.WithCustomField("next_id", nextID),
			response.WithItemsPerPage(int64(limit)),
		)
	}
}

func (api *api) behavioralLearnModelNetwork() http.HandlerFunc {
	type networkModel struct {
		Id                string `json:"id"`
		Port              int    `json:"port"`
		UpdatedAt         int64  `json:"updated_at"`
		StreamDirection   int    `json:"stream_direction"`
		IsInModel         bool   `json:"is_in_model"`
		ClusterKey        string `json:"cluster_key"`
		ResourceNamespace string `json:"namespace"`
		ResourceKind      string `json:"kind"`
		ResourceName      string `json:"resource_name"`
		Name              string `json:"name"`
		EventID           string `json:"event_id"`
		ContainerName     string `json:"container_name"`
		CanAddModel       bool   `json:"can_add_model"`
		ProcessName       string `json:"process_name"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		resourceUUID, err := param.QueryUint32(r, "resource_id")
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource_id fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get resource_id fail")))
			return
		}

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get limit and offset fail")
			limit = 10
			offset = 0
		}

		isInModel, err := param.QueryBool(r, "is_in_model")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get is_in_model fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get is_in_model fail")))
			return
		}

		streamDir, err := param.QueryInt(r, "stream_direction")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get stream_direction fail")

		}

		port, err := param.QueryInt(r, "port")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get port fail")
			port = 0
		}

		searchStr, err := param.QueryString(r, "search_str")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get search_str fail")
		}

		startID, err := param.QueryUint64(r, "start_id")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get start_id fail")
			startID = 0
		}

		cNameStr, err := param.QueryString(r, "cname")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get cname fail")
		}
		var cNames []string
		for _, cName := range strings.Split(cNameStr, ",") {
			if cName == "" {
				continue
			}
			cNames = append(cNames, cName)
		}

		allContainer, err := param.QueryBool(r, "all_container")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get all_container fail")
			allContainer = true
		}

		if !allContainer && len(cNames) == 0 {
			logging.GetLogger().Warn().Msg("get cids fail")
			response.Ok(w, response.WithItems([]networkModel{}),
				response.WithTotalItems(0),
				response.WithStartIndex(0),
				response.WithCustomField("next_id", 0),
				response.WithItemsPerPage(int64(limit)),
			)
			return
		}

		if allContainer {
			cNames = make([]string, 0)
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		networkModels, size, err := blSvc.GetResourcesNetworkModel(ctx, resourceUUID, streamDir, port, searchStr, isInModel, limit, offset, startID, cNames)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get file model fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get file model fail")))
			return
		}

		var networkModelsExistMap = make(map[string]struct{})
		if !isInModel {
			inModelNetworkModel, _, err := blSvc.GetResourcesNetworkModel(ctx, resourceUUID, streamDir, port, searchStr, true, 0, 0, 0, cNames)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("get file model fail")
				apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get file model fail")))
				return
			}
			for _, n := range inModelNetworkModel {
				networkModelsExistMap[n.ClusterKey+n.ResourceNamespace+n.ResourceKind+n.ResourceName+fmt.Sprintf("%d_%d", n.StreamDirection, n.Port)] = struct{}{}
			}
		}

		resp := make([]*networkModel, 0)
		for _, n := range networkModels {
			idStr := strconv.FormatUint(n.Id, 10)
			resp = append(resp, &networkModel{
				Id:                idStr,
				Port:              n.Port,
				UpdatedAt:         n.UpdatedAt,
				StreamDirection:   n.StreamDirection,
				IsInModel:         n.IsInModel,
				ClusterKey:        n.ClusterKey,
				ResourceNamespace: n.ResourceNamespace,
				ResourceKind:      n.ResourceKind,
				ResourceName:      n.ResourceName,
				Name:              n.ResourceName,
				ContainerName:     n.ContainerName,
				ProcessName:       n.ProcessName,
			})
			if n.IsInModel {
				continue
			}
			resp[len(resp)-1].CanAddModel = true
			if _, ok := networkModelsExistMap[n.ClusterKey+n.ResourceNamespace+n.ResourceKind+n.ResourceName+fmt.Sprintf("%d_%d", n.StreamDirection, n.Port)]; ok {
				resp[len(resp)-1].CanAddModel = false
			}
			streamStr := ""
			if n.StreamDirection == 1 {
				streamStr = "out"
			} else if n.StreamDirection == 2 {
				streamStr = "in"
			}
			// get outside of model info
			signals, err := blSvc.GetNetworkModelFromEs(ctx, n.ResourceUUID, n.Port, n.DestResource, streamStr, n.ProcessName, 0, 1)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("get network model from es fail")
				continue
			}
			if len(signals) == 0 {
				continue
			}
			resp[len(resp)-1].EventID = signals[0].ID
		}
		var nextID string = "0"
		if len(resp) > 0 {
			nextID = resp[len(resp)-1].Id
		}
		response.Ok(w, response.WithItems(resp),
			response.WithTotalItems(size),
			response.WithStartIndex(int64(offset)),
			response.WithCustomField("next_id", nextID),
			response.WithItemsPerPage(int64(limit)),
		)
	}
}

func (api *api) behavioralLearnModelUpdateFile() http.HandlerFunc {
	type reqData struct {
		ResourceUUID  uint32 `json:"resource_id"`
		Id            string `json:"id"`
		Path          string `json:"file_path"`
		Permission    int    `json:"permission"`
		ContainerName string `json:"container_name"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}
		idUint, err := strconv.ParseUint(req.Id, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("parse id fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("parse id fail")))
			return
		}
		updateData := model.BehavioralLearnFileModel{
			Id:           idUint,
			ResourceUUID: req.ResourceUUID,
			Name:         filepath.Base(req.Path),
			Path:         req.Path,
			Permission:   req.Permission,
		}

		res, err := blSvc.UpdateResourcesFileModel(ctx, updateData)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("update file model fail")
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
				apperror.RespAndLog(w, ctx,
					apperror.BehavioralLearnModelExistError(http.StatusInternalServerError,
						errors.New("file model already exist")))
				return
			}
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("update file model fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		blSvc.LogModelOperation(ctx, req.ResourceUUID, userName, "UPDATE", "file", idUint)

		response.Ok(w, response.WithTotalItems(1), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s/%s(%s): %d", res.ClusterKey, res.Namespace, res.Name, res.Kind, updateData.Id),
			ID:   fmt.Sprintf("%d", res.ID),
		}))
	}
}

func (api *api) behavioralLearnModelUpdateCommand() http.HandlerFunc {
	type reqData struct {
		ResourceUUID  uint32 `json:"resource_id"`
		Id            string `json:"id"`
		Command       string `json:"command"`
		Path          string `json:"path"`
		User          string `json:"user"`
		ContainerName string `json:"container_name"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		idUint, err := strconv.ParseUint(req.Id, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("parse id fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("parse id fail")))
			return
		}

		updateData := model.BehavioralLearnCommandModel{
			Id:            idUint,
			ResourceUUID:  req.ResourceUUID,
			Command:       req.Command,
			Path:          req.Path,
			User:          req.User,
			ContainerName: req.ContainerName,
		}

		res, err := blSvc.UpdateResourcesCommandModel(ctx, updateData)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("update command model fail")
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
				apperror.RespAndLog(w, ctx,
					apperror.BehavioralLearnModelExistError(http.StatusInternalServerError,
						errors.New("command model already exist")))
				return
			}
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("update command model fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		blSvc.LogModelOperation(ctx, req.ResourceUUID, userName, "UPDATE", "command", idUint)

		response.Ok(w, response.WithTotalItems(1), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s/%s(%s): %d", res.ClusterKey, res.Namespace, res.Name, res.Kind, updateData.Id),
			ID:   fmt.Sprintf("%d", res.ID),
		}))
	}
}

func (api *api) behavioralLearnModelUpdateNetwork() http.HandlerFunc {
	type reqData struct {
		ResourceUUID       uint32 `json:"resource_id"`
		Id                 string `json:"id"`
		Port               int    `json:"port"`
		StreamDirection    int    `json:"stream_direction"`
		ObjectResourceUUID uint32 `json:"object_resource_id,omitempty"`
		ClusterKey         string `json:"cluster_key"`
		Namespace          string `json:"namespace"`
		Kind               string `json:"kind"`
		ResourceName       string `json:"resource_name"`
		Name               string `json:"name"`
		ContainerName      string `json:"container_name"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		idUint, err := strconv.ParseUint(req.Id, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("parse id fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("parse id fail")))
			return
		}
		if req.Name == "" {
			req.Name = req.ResourceName
		}
		if req.ResourceName == "" {
			req.ResourceName = req.Name
		}

		fillUUID := util.GenerateUUID(req.ClusterKey, req.Namespace, req.Kind, req.Name)
		req.ObjectResourceUUID = fillUUID

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		updateData := model.BehavioralLearnNetworkModel{
			Id:                 idUint,
			ResourceUUID:       req.ResourceUUID,
			Port:               req.Port,
			StreamDirection:    req.StreamDirection,
			ObjectResourceUUID: req.ObjectResourceUUID,
			ClusterKey:         req.ClusterKey,
			ResourceNamespace:  req.Namespace,
			ResourceKind:       req.Kind,
			ResourceName:       req.Name,
			ContainerName:      req.ContainerName,
		}

		if req.Port > 65535 || req.Port < 0 {
			logging.GetLogger().Error().Msg("port out of range")
			apperror.RespAndLog(w, ctx, apperror.BehavioralPortNumError(http.StatusInternalServerError, errors.New("port out of range")))
			return
		}

		res, err := blSvc.UpdateResourcesNetworkModel(ctx, updateData)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("update network model fail")
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
				apperror.RespAndLog(w, ctx,
					apperror.BehavioralLearnModelExistError(http.StatusInternalServerError,
						errors.New("network model already exist")))
				return
			}
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("update network model fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		blSvc.LogModelOperation(ctx, req.ResourceUUID, userName, "UPDATE", "network", idUint)

		response.Ok(w, response.WithTotalItems(1), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s/%s(%s): %d", res.ClusterKey, res.Namespace, res.Name, res.Kind, updateData.Id),
			ID:   fmt.Sprintf("%d", res.ID),
		}))
	}
}

func (api *api) behavioralLearnModelDeleteFile() http.HandlerFunc {
	type reqData struct {
		ResourceUUID uint32 `json:"resource_id"`
		Id           string `json:"id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		idUint, err := strconv.ParseUint(req.Id, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("parse id fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("parse id fail")))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		err = blSvc.DeleteResourcesFileModel(ctx, req.ResourceUUID, idUint)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("delete file model fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("delete file model fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		blSvc.LogModelOperation(ctx, req.ResourceUUID, userName, "DELETE", "file", idUint)

		res, err := blSvc.GetResourceBasicInfo(ctx, req.ResourceUUID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource basic info fail")
		}

		response.Ok(w, response.WithTotalItems(1), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s/%s(%s): %d", res.ClusterKey, res.Namespace, res.Name, res.Kind, idUint),
			ID:   fmt.Sprintf("%d", idUint),
		}))
	}
}

func (api *api) behavioralLearnModelDeleteCommand() http.HandlerFunc {
	type reqData struct {
		ResourceUUID uint32 `json:"resource_id"`
		Id           string `json:"id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		idUint, err := strconv.ParseUint(req.Id, 10, 64)
		if err != nil {
			logging.GetLogger().Err(err).Msg("parse id fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("parse id fail")))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		err = blSvc.DeleteResourcesCommandModel(ctx, req.ResourceUUID, idUint)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("delete command model fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("delete command model fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		blSvc.LogModelOperation(ctx, req.ResourceUUID, userName, "DELETE", "command", idUint)

		res, err := blSvc.GetResourceBasicInfo(ctx, req.ResourceUUID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource basic info fail")
		}

		response.Ok(w, response.WithTotalItems(1), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s/%s(%s): %d", res.ClusterKey, res.Namespace, res.Name, res.Kind, idUint),
			ID:   fmt.Sprintf("%d", idUint),
		}))
	}
}

func (api *api) behavioralLearnModelDeleteNetwork() http.HandlerFunc {
	type reqData struct {
		ResourceUUID uint32 `json:"resource_id"`
		Id           string `json:"id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Err(err).
				Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		idUint, err := strconv.ParseUint(req.Id, 10, 64)
		if err != nil {
			logging.GetLogger().Err(err).Msg("parse id fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("parse id fail")))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("get behavioral learn service fail")))
			return
		}

		err = blSvc.DeleteResourcesNetworkModel(ctx, req.ResourceUUID, idUint)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("delete network model fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("delete network model fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		blSvc.LogModelOperation(ctx, req.ResourceUUID, userName, "DELETE", "network", idUint)

		res, err := blSvc.GetResourceBasicInfo(ctx, req.ResourceUUID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource basic info fail")
		}

		response.Ok(w, response.WithTotalItems(1), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s/%s(%s): %d", res.ClusterKey, res.Namespace, res.Name, res.Kind, idUint),
			ID:   fmt.Sprintf("%d", idUint),
		}))
	}
}

func (api *api) behavioralLearnModelAddFile() http.HandlerFunc {
	type reqData struct {
		ResourceUUID   uint32   `json:"resource_id"`
		Path           string   `json:"file_path"`
		Permission     int      `json:"permission"`
		ContainerNames []string `json:"container_name"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}
		if req.Path == "" {
			logging.GetLogger().Error().Msg("name or path is empty")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusBadRequest,
					errors.New("name or path is empty")))
			return
		}
		if req.ResourceUUID == 0 {
			logging.GetLogger().Error().Msg("resource id is empty")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusBadRequest,
					errors.New("resource id is empty")))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("get behavioral learn service fail")))
			return
		}

		fileModels := []model.BehavioralLearnFileModel{}

		for _, cName := range req.ContainerNames {
			fileModels = append(fileModels, model.BehavioralLearnFileModel{
				ResourceUUID:  req.ResourceUUID,
				Name:          filepath.Base(req.Path),
				Path:          req.Path,
				Permission:    req.Permission,
				IsInModel:     true,
				ContainerName: cName,
			})
		}

		// fileModel := model.BehavioralLearnFileModel{
		// 	ResourceUUID:  req.ResourceUUID,
		// 	Name:          filepath.Base(req.Path),
		// 	Path:          req.Path,
		// 	Permission:    req.Permission,
		// 	IsInModel:     true,
		// }

		retData, err := blSvc.InsertResourcesFileModels(ctx, fileModels)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("add file model fail")
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
				apperror.RespAndLog(w, ctx,
					apperror.BehavioralLearnModelExistError(http.StatusInternalServerError,
						errors.New("file model already exist")))
				return
			}

			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("add file model fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		ids := make([]uint64, 0)
		for _, d := range retData {
			ids = append(ids, d.Id)
		}

		blSvc.LogModelOperationsWithID(ctx, req.ResourceUUID, userName, "ADD", "file", ids)
		idStrList := make([]string, 0)
		for _, id := range ids {
			idStrList = append(idStrList, strconv.FormatUint(id, 10))
		}
		idStr := strings.Join(idStrList, ",")

		res, err := blSvc.GetResourceBasicInfo(ctx, req.ResourceUUID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource basic info fail")
		}

		response.Ok(w, response.WithCustomField("id", idStr), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s/%s(%s): %v", res.ClusterKey, res.Namespace, res.Name, res.Kind, idStr),
			ID:   fmt.Sprintf("%d", res.ID),
		}))
	}
}

func (api *api) behavioralLearnModelAddCommand() http.HandlerFunc {
	type reqData struct {
		ResourceUUID   uint32   `json:"resource_id"`
		Command        string   `json:"command"`
		Path           string   `json:"path"`
		User           string   `json:"user"`
		ContainerNames []string `json:"container_name"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		if req.Command == "" || req.Path == "" {
			logging.GetLogger().Error().Msg("command or path is empty")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusBadRequest,
					errors.New("command or path is empty")))
			return
		}

		if req.ResourceUUID == 0 {
			logging.GetLogger().Error().Msg("resource id is empty")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusBadRequest,
					errors.New("resource id is empty")))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("get behavioral learn service fail")))
			return
		}

		// commandModel := model.BehavioralLearnCommandModel{
		// 	ResourceUUID:  req.ResourceUUID,
		// 	Command:       req.Command,
		// 	Path:          req.Path,
		// 	User:          req.User,
		// 	IsInModel:     true,
		// 	ContainerName: req.ContainerName,
		// }
		commandModels := make([]model.BehavioralLearnCommandModel, 0)
		for _, cName := range req.ContainerNames {
			commandModel := model.BehavioralLearnCommandModel{
				ResourceUUID:  req.ResourceUUID,
				Command:       req.Command,
				Path:          req.Path,
				User:          req.User,
				IsInModel:     true,
				ContainerName: cName,
			}
			commandModels = append(commandModels, commandModel)
		}

		retData, err := blSvc.InsertResourcesCommandModels(ctx, commandModels)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
				logging.GetLogger().Error().Err(err).
					Msg("command model already exist")
				apperror.RespAndLog(w, ctx,
					apperror.BehavioralLearnModelExistError(http.StatusInternalServerError,
						errors.New("command model already exist")))
				return
			}
			logging.GetLogger().Error().Err(err).
				Msg("add command model fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("add command model fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		ids := make([]uint64, 0)

		for _, d := range retData {
			ids = append(ids, d.Id)
		}

		blSvc.LogModelOperationsWithID(ctx, req.ResourceUUID, userName, "ADD", "command", ids)
		idStrList := make([]string, 0)
		for _, id := range ids {
			idStrList = append(idStrList, strconv.FormatUint(id, 10))
		}
		idStr := strings.Join(idStrList, ",")

		res, err := blSvc.GetResourceBasicInfo(ctx, req.ResourceUUID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource basic info fail")
		}

		response.Ok(w, response.WithCustomField("id", idStr), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s/%s(%s): %v", res.ClusterKey, res.Namespace, res.Name, res.Kind, idStr),
			ID:   fmt.Sprintf("%d", res.ID),
		}))
	}
}

func (api *api) behavioralLearnModelAddNetwork() http.HandlerFunc {
	type reqData struct {
		ResourceUUID      uint32   `json:"resource_id"`
		Port              int      `json:"port"`
		StreamDirection   int      `json:"stream_direction"`
		FillResourceUUID  uint32   `json:"fill_resource_id,omitempty"`
		ClusterKey        string   `json:"cluster_key"`
		ResourceNamespace string   `json:"namespace"`
		ResourceKind      string   `json:"kind"`
		Name              string   `json:"name"`
		ResourceName      string   `json:"resource_name"`
		ContainerNames    []string `json:"container_name"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}
		if req.Name == "" {
			req.Name = req.ResourceName
		}
		if req.ResourceName == "" {
			req.ResourceName = req.Name
		}

		if req.Port == 0 {
			logging.GetLogger().Error().Msg("port is empty")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusBadRequest,
					errors.New("port is empty")))
			return
		}
		if req.ResourceUUID == 0 {
			logging.GetLogger().Error().Msg("resource id is empty")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusBadRequest,
					errors.New("resource id is empty")))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("get behavioral learn service fail")))
			return
		}

		fillUUID := util.GenerateUUID(req.ClusterKey, req.ResourceNamespace,
			req.ResourceKind, req.ResourceName)
		req.FillResourceUUID = fillUUID

		networkModels := make([]model.BehavioralLearnNetworkModel, 0)
		for _, cName := range req.ContainerNames {
			networkModel := model.BehavioralLearnNetworkModel{
				ResourceUUID:       req.ResourceUUID,
				Port:               req.Port,
				StreamDirection:    req.StreamDirection,
				ObjectResourceUUID: req.FillResourceUUID,
				ClusterKey:         req.ClusterKey,
				ResourceNamespace:  req.ResourceNamespace,
				ResourceKind:       req.ResourceKind,
				ResourceName:       req.ResourceName,
				IsInModel:          true,
				ContainerName:      cName,
			}
			networkModels = append(networkModels, networkModel)
		}

		if req.Port > 65535 || req.Port < 0 {
			logging.GetLogger().Error().Msg("port out of range")
			apperror.RespAndLog(w, ctx, apperror.BehavioralPortNumError(http.StatusInternalServerError, errors.New("port out of range")))
			return
		}

		retData, err := blSvc.InsertResourcesNetworkModels(ctx, networkModels)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
				logging.GetLogger().Error().Err(err).
					Msg("network model already exist")
				apperror.RespAndLog(w, ctx,
					apperror.BehavioralLearnModelExistError(http.StatusInternalServerError,
						errors.New("network model already exist")))
				return
			}
			logging.GetLogger().Error().Err(err).
				Msg("add network model fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("add network model fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		ids := make([]uint64, 0)

		for _, d := range retData {
			ids = append(ids, d.Id)
		}

		blSvc.LogModelOperationsWithID(ctx, req.ResourceUUID, userName, "ADD", "network", ids)
		idStrList := make([]string, 0)
		for _, id := range ids {
			idStrList = append(idStrList, strconv.FormatUint(id, 10))
		}
		idStr := strings.Join(idStrList, ",")

		res, err := blSvc.GetResourceBasicInfo(ctx, req.ResourceUUID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource basic info fail")
		}

		response.Ok(w, response.WithCustomField("id", idStr), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s/%s(%s): %v", res.ClusterKey, res.Namespace, res.Name, res.Kind, idStr),
			ID:   fmt.Sprintf("%d", res.ID),
		}))
	}
}

func (api *api) behavioralLearnModelReset() http.HandlerFunc {
	type reqData struct {
		ResourceUUID uint32 `json:"resource_id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}
		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}
		response.Ok(w, response.WithTotalItems(1))
	}
}

func (api *api) behavioralLearnModelLogGet() http.HandlerFunc {
	type respData struct {
		ResourceUUID uint32 `json:"resource_id"`
		User         string `json:"user"`
		Action       string `json:"action"`
		CreatedAt    int64  `json:"created_at"`
		ID           string `json:"id"`
		ModelType    string `json:"model_type"`
	}
	respModel := func(l []model.BehavioralLearnModelOperationLog) []respData {
		resp := make([]respData, 0)
		for _, v := range l {
			idStr := strconv.FormatUint(v.ID, 10)
			resp = append(resp, respData{
				ResourceUUID: v.ResourceUUID,
				User:         v.User,
				Action:       v.Action,
				CreatedAt:    v.CreatedAt,
				ID:           idStr,
				ModelType:    v.ModelType,
			})
		}
		return resp
	}
	return func(w http.ResponseWriter, r *http.Request) {
		_, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		resourceUUID, err := param.QueryUint32(r, "resource_id")
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource_id fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get resource_id fail")))
			return
		}

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get limit and offset fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusBadRequest, err))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		logs, size, err := blSvc.GetModelOperationLog(r.Context(), resourceUUID, limit, offset)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get model operation log fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get model operation log fail")))
			return
		}
		respModelList := respModel(logs)

		response.Ok(w,
			response.WithItems(respModelList),
			response.WithTotalItems(size),
			response.WithStartIndex(int64(offset)),
			response.WithItemsPerPage(int64(limit)),
		)
	}
}

func (api *api) behavioralLearnGlobalCommandWhitelistAdd() http.HandlerFunc {
	type reqData struct {
		Path    string `json:"path"`
		Command string `json:"command"`
		User    string `json:"user"`
		Type    string `json:"type"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("get behavioral learn service fail")))
			return
		}

		commandModel := model.BehavioralLearnCommandModelGlobalWhiteList{
			Path:    req.Path,
			Command: req.Command,
			User:    req.User,
		}

		retData, err := blSvc.InsertGlobalCommandWhitelist(ctx, commandModel)
		if err != nil {
			if errors.Is(err, bl.ErrGlobalWhiteListExist) {
				logging.GetLogger().Error().Err(err).Msg("global command whitelist exist")
				apperror.RespAndLog(w, ctx, apperror.BehavioralLearnWhitelistExistError(http.StatusInternalServerError, err))
				return
			}

			logging.GetLogger().Error().Err(err).Msg("add global command whitelist fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("add global command whitelist fail")))
			return
		}

		response.Ok(w, response.WithCustomField("id", retData.ID), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%d", retData.ID),
			ID:   fmt.Sprintf("%d", retData.ID),
		}))
	}
}

func (api *api) behavioralLearnGlobalCommandWhitelistUpdate() http.HandlerFunc {
	type reqData struct {
		ID      int64  `json:"id"`
		Path    string `json:"path"`
		Command string `json:"command"`
		User    string `json:"user"`
		Type    string `json:"type"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("get behavioral learn service fail")))
			return
		}

		commandModel := model.BehavioralLearnCommandModelGlobalWhiteList{
			ID:      req.ID,
			Path:    req.Path,
			Command: req.Command,
			User:    req.User,
		}

		err = blSvc.UpdateGlobalCommandWhitelist(ctx, commandModel)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("update global command whitelist fail")
			if errors.Is(err, bl.ErrGlobalWhiteListExist) {
				logging.GetLogger().Error().Err(err).Msg("global command whitelist exist")
				apperror.RespAndLog(w, ctx, apperror.BehavioralLearnWhitelistExistError(http.StatusInternalServerError, err))
				return
			}

			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("update global command whitelist fail")))
			return
		}

		response.Ok(w, response.WithTotalItems(1), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%d", req.ID),
			ID:   fmt.Sprintf("%d", req.ID),
		}))

	}
}

func (api *api) behavioralLearnGlobalCommandWhitelistGet() http.HandlerFunc {
	type respData struct {
		Path    string `json:"path"`
		Command string `json:"command"`
		User    string `json:"user"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get limit and offset fail")
			limit = 1000
			offset = 0
		}

		searchStr, err := param.QueryString(r, "search_str")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get search_str fail")
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			limit = 1000
			offset = 0
		}
		logging.GetLogger().Debug().Msgf("limit %v offset %v", limit, offset)
		resp, size, err := blSvc.GetGlobalCommandWhitelist(ctx, limit, offset, searchStr)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get global command whitelist fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get global command whitelist fail")))
			return
		}
		logging.GetLogger().Debug().Msgf("resp %v", resp)
		response.Ok(w,
			response.WithItems(resp),
			response.WithTotalItems(size),
			response.WithStartIndex(int64(offset)),
			response.WithItemsPerPage(int64(limit)),
		)
	}
}

func (api *api) behavioralLearnGlobalCommandWhitelistDelete() http.HandlerFunc {
	type reqData struct {
		Id string `json:"id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		idInt64, err := strconv.ParseInt(req.Id, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("parse id fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("parse id fail")))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		err = blSvc.DeleteGlobalCommandWhitelist(ctx, idInt64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("delete global command whitelist fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("delete global command whitelist fail")))
			return
		}

		response.Ok(w, response.WithTotalItems(1), response.WithTarget(&response.TargetRef{
			Name: req.Id,
			ID:   req.Id,
		}))
	}
}

func (api *api) behavioralLearnGlobalFileWhitelistAdd() http.HandlerFunc {
	type reqData struct {
		Path       string `json:"file_path"`
		Permission int    `json:"permission"`
		Type       string `json:"type"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}
		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		fileModel := model.BehavioralLearnFileModelGlobalWhiteList{
			Name:       filepath.Base(req.Path),
			Path:       req.Path,
			Permission: req.Permission,
		}

		retData, err := blSvc.InsertGlobalFileWhitelist(ctx, fileModel)
		if err != nil {
			if errors.Is(err, bl.ErrGlobalWhiteListExist) {
				apperror.RespAndLog(w, ctx, apperror.BehavioralLearnWhitelistExistError(http.StatusInternalServerError, err))
				return
			}
			logging.GetLogger().Error().Err(err).
				Msg("add global file whitelist fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("add global file whitelist fail")))
			return
		}

		response.Ok(w, response.WithCustomField("id", retData.ID), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%d", retData.ID),
			ID:   fmt.Sprintf("%d", retData.ID),
		}))
	}
}

func (api *api) behavioralLearnGlobalFileWhitelistUpdate() http.HandlerFunc {
	type reqData struct {
		ID         int64  `json:"id"`
		Path       string `json:"file_path"`
		Permission int    `json:"permission"`
		Type       string `json:"type"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		fileModel := model.BehavioralLearnFileModelGlobalWhiteList{
			ID:         req.ID,
			Path:       req.Path,
			Permission: req.Permission,
		}

		err = blSvc.UpdateGlobalFileWhitelist(ctx, fileModel)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("update global file whitelist fail")
			if errors.Is(err, bl.ErrGlobalWhiteListExist) {
				apperror.RespAndLog(w, ctx, apperror.BehavioralLearnWhitelistExistError(http.StatusInternalServerError, err))
				return
			}
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("update global file whitelist fail")))
			return
		}

		response.Ok(w, response.WithTotalItems(1), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%d", req.ID),
			ID:   fmt.Sprintf("%d", req.ID),
		}))
	}
}

func (api *api) behavioralLearnGlobalFileWhitelistGet() http.HandlerFunc {
	type respData struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		Path       string `json:"file_path"`
		Permission int    `json:"permission"`
		UpdatedAt  int64  `json:"updated_at"`
	}
	respFormat := func(fileWls []model.BehavioralLearnFileModelGlobalWhiteList) []respData {
		resp := make([]respData, 0)
		for _, v := range fileWls {
			resp = append(resp, respData{
				ID:         v.ID,
				Name:       v.Name,
				Path:       v.Path,
				Permission: v.Permission,
				UpdatedAt:  v.UpdatedAt,
			})
		}
		return resp
	}
	return func(w http.ResponseWriter, r *http.Request) {
		_, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get limit and offset fail")
			limit = 1000
			offset = 0
		}

		permission, err := param.QueryInt(r, "permission")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get permission fail")
		}
		searchStr, err := param.QueryString(r, "search_str")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get search_str fail")
		}

		blSvc, ok := bl.GetBehavioralLearnService()

		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		resp, size, err := blSvc.GetGlobalFileWhitelist(r.Context(), limit, offset, searchStr, permission)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get global file whitelist fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get global file whitelist fail")))
			return
		}
		respList := respFormat(resp)
		response.Ok(w, response.WithItems(respList),
			response.WithTotalItems(size),
			response.WithStartIndex(int64(offset)),
			response.WithItemsPerPage(int64(limit)),
		)
	}
}

func (api *api) behavioralLearnGlobalFileWhitelistDelete() http.HandlerFunc {
	type reqData struct {
		Id string `json:"id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		idInt64, err := strconv.ParseInt(req.Id, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("parse id fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("parse id fail")))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()

		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		err = blSvc.DeleteGlobalFileWhitelist(ctx, idInt64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("delete global file whitelist fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("delete global file whitelist fail")))
			return
		}

		response.Ok(w, response.WithTotalItems(1), response.WithTarget(&response.TargetRef{
			Name: req.Id,
			ID:   req.Id,
		}))
	}
}

func (api *api) behavioralLearnGlobalNetworkWhitelistAdd() http.HandlerFunc {
	type reqData struct {
		Port               int    `json:"port"`
		StreamDirection    int    `json:"stream_direction"`
		ResourceName       string `json:"resource_name"`
		ObjectResourceUUID uint32 `json:"object_resource_id,omitempty"`
		ClusterKey         string `json:"cluster_key"`
		Namespace          string `json:"namespace"`
		Kind               string `json:"kind"`
		Type               string `json:"type"`
		Name               string `json:"name"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		if req.Name == "" {
			req.Name = req.ResourceName
		}
		if req.ResourceName == "" {
			req.ResourceName = req.Name
		}

		blSvc, ok := bl.GetBehavioralLearnService()

		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		fillUUID := util.GenerateUUID(req.ClusterKey, req.Namespace, req.Kind, req.ResourceName)
		req.ObjectResourceUUID = fillUUID

		networkModel := model.BehavioralLearnNetworkModelGlobalWhiteList{
			Port:               req.Port,
			StreamDirection:    req.StreamDirection,
			ObjectResourceUUID: req.ObjectResourceUUID,
			ClusterKey:         req.ClusterKey,
			Namespace:          req.Namespace,
			Kind:               req.Kind,
			Name:               req.ResourceName,
		}

		if networkModel.Port > 65535 || networkModel.Port < 0 {
			logging.GetLogger().Error().Msg("port is invalid")
			apperror.RespAndLog(w, ctx, apperror.BehavioralPortNumError(http.StatusInternalServerError, errors.New("port is invalid")))
			return
		}

		retData, err := blSvc.InsertGlobalNetworkWhitelist(ctx, networkModel)
		if err != nil {
			if errors.Is(err, bl.ErrGlobalWhiteListExist) {
				logging.GetLogger().Error().Err(err).
					Msg("global network whitelist already exist")
				apperror.RespAndLog(w, ctx, apperror.BehavioralLearnWhitelistExistError(http.StatusInternalServerError, err))
				return
			}
			logging.GetLogger().Error().Err(err).
				Msg("add global network whitelist fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("add global network whitelist fail")))
			return
		}

		response.Ok(w, response.WithCustomField("id", retData.ID), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%d", retData.ID),
			ID:   fmt.Sprintf("%d", retData.ID),
		}))
	}
}

func (api *api) behavioralLearnGlobalNetworkWhitelistUpdate() http.HandlerFunc {
	type reqData struct {
		ID                 int64  `json:"id"`
		Port               int    `json:"port"`
		StreamDirection    int    `json:"stream_direction"`
		ObjectResourceUUID uint32 `json:"object_resource_id,omitempty"`
		ClusterKey         string `json:"cluster_key"`
		Namespace          string `json:"namespace"`
		Kind               string `json:"kind"`
		Name               string `json:"name"`
		ResourceName       string `json:"resource_name"`
		Type               string `json:"type"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		if req.Name == "" {
			req.Name = req.ResourceName
		}
		if req.ResourceName == "" {
			req.ResourceName = req.Name
		}

		blSvc, ok := bl.GetBehavioralLearnService()

		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		fillUUID := util.GenerateUUID(req.ClusterKey, req.Namespace, req.Kind, req.Name)
		req.ObjectResourceUUID = fillUUID

		networkModel := model.BehavioralLearnNetworkModelGlobalWhiteList{
			Port:               req.Port,
			StreamDirection:    req.StreamDirection,
			ObjectResourceUUID: req.ObjectResourceUUID,
			ID:                 req.ID,
			ClusterKey:         req.ClusterKey,
			Namespace:          req.Namespace,
			Kind:               req.Kind,
			Name:               req.Name,
		}

		if networkModel.Port > 65535 || networkModel.Port < 0 {
			logging.GetLogger().Error().Msg("port is invalid")
			apperror.RespAndLog(w, ctx, apperror.BehavioralPortNumError(http.StatusInternalServerError, errors.New("port is invalid")))
		}

		err = blSvc.UpdateGlobalNetworkWhitelist(ctx, networkModel)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("update global network whitelist fail")
			if errors.Is(err, bl.ErrGlobalWhiteListExist) {
				apperror.RespAndLog(w, ctx, apperror.BehavioralLearnWhitelistExistError(http.StatusInternalServerError, err))
				return
			}
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("update global network whitelist fail")))
			return
		}

		response.Ok(w, response.WithTotalItems(1), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%d", req.ID),
			ID:   fmt.Sprintf("%d", req.ID),
		}))
	}
}

func (api *api) behavioralLearnGlobalNetworkWhitelistGet() http.HandlerFunc {
	type respData struct {
		ID              int64  `json:"id"`
		Port            int    `json:"port"`
		StreamDirection int    `json:"stream_direction"`
		ClusterKey      string `json:"cluster_key"`
		Namespace       string `json:"namespace"`
		Kind            string `json:"kind"`
		ResourceName    string `json:"resource_name"`
		Name            string `json:"name"`
		UpdatedAt       int64  `json:"updated_at"`
	}
	respModel := func(l []model.BehavioralLearnNetworkModelGlobalWhiteList) []respData {
		resp := make([]respData, 0)
		for _, v := range l {
			resp = append(resp, respData{
				ID:              v.ID,
				Port:            v.Port,
				StreamDirection: v.StreamDirection,
				ClusterKey:      v.ClusterKey,
				Namespace:       v.Namespace,
				Kind:            v.Kind,
				ResourceName:    v.Name,
				Name:            v.Name,
				UpdatedAt:       v.UpdatedAt,
			})
		}
		return resp
	}
	return func(w http.ResponseWriter, r *http.Request) {
		_, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get limit and offset fail")
			limit = 1000
			offset = 0
		}

		streamDirectionStr, err := param.QueryString(r, "stream_direction")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get stream_direction fail")
		}
		streamDirectionList := strings.Split(streamDirectionStr, ",")
		streamDirection := make([]int, 0)
		for _, v := range streamDirectionList {
			if v == "" {
				continue
			}
			streamDirectionInt, err := strconv.Atoi(v)
			if err != nil {
				logging.GetLogger().Warn().Err(err).Msg("get stream_direction fail")
				continue
			}
			streamDirection = append(streamDirection, streamDirectionInt)
		}
		searchStr, err := param.QueryString(r, "search_str")
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msg("get search_str fail")
		}

		blSvc, ok := bl.GetBehavioralLearnService()

		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		resp, size, err := blSvc.GetGlobalNetworkWhitelist(r.Context(), limit, offset, searchStr, streamDirection)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get global network whitelist fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get global network whitelist fail")))
			return
		}

		respModel := respModel(resp)

		response.Ok(w, response.WithItems(respModel),
			response.WithTotalItems(size),
			response.WithStartIndex(int64(offset)),
			response.WithItemsPerPage(int64(limit)),
		)
	}
}

func (api *api) behavioralLearnGlobalNetworkWhitelistDelete() http.HandlerFunc {
	type reqData struct {
		Id string `json:"id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		idInt64, err := strconv.ParseInt(req.Id, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("parse id fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("parse id fail")))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()

		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		err = blSvc.DeleteGlobalNetworkWhitelist(ctx, idInt64)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("delete global network whitelist fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("delete global network whitelist fail")))
			return
		}

		response.Ok(w, response.WithTotalItems(1), response.WithTarget(&response.TargetRef{
			Name: req.Id,
			ID:   req.Id,
		}))
	}
}

func (api *api) behavioralLearnGlobalConfigGet() http.HandlerFunc {
	type respConfig struct {
		IgnoreKnownAttack bool `json:"ignore_known_attack"`
		LearnTime         int  `json:"learn_time"`
		ShowUnrelatedRes  bool `json:"show_unrelated_res"`
		AutoLearnNewRes   bool `json:"auto_learn_new_res"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		_, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		config, err := blSvc.GetGlobalConfig(r.Context())
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get global config fail")
			apperror.RespAndLog(w, r.Context(), apperror.NewAnError(http.StatusInternalServerError, errors.New("get global config fail")))
			return
		}
		configResp := respConfig{
			IgnoreKnownAttack: config.IgnoreKnownAttack,
			LearnTime:         config.LearnTime / 60,
			ShowUnrelatedRes:  config.ShowUnrelatedRes,
			AutoLearnNewRes:   config.AutoLearnNewRes,
		}
		response.Ok(w, response.WithItem(configResp))
	}
}

func (api *api) behavioralLearnGlobalConfigSet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var reqData model.BehavioralLearnGlobalConfig
		err := util.DecodeJSONBody(w, r, &reqData)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("get behavioral learn service fail")))
			return
		}
		if reqData.LearnTime < 1 {
			reqData.LearnTime = 1
			logging.GetLogger().Error().Msg("learn time is invalid")
		} else if reqData.LearnTime > 30 {
			reqData.LearnTime = 30
			logging.GetLogger().Error().Msg("learn time is valid")
		}
		reqData.LearnTime = reqData.LearnTime * 60

		err = blSvc.SetGlobalConfig(ctx, &reqData)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("set global config fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					errors.New("set global config fail")))
			return
		}

		response.Ok(w, response.WithTotalItems(1))
	}
}

func (api *api) behavioralLearnOneKeyLearn() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		res, n, err := blSvc.BehavioralLearnOneKeyLearn(ctx, userName)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("one key learn fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("one key learn fail")))
			return
		}

		targetRef := &response.TargetRef{}
		if len(res) > 0 {
			idStr := fmt.Sprintf("%d", res[0].ID)
			nameStr := fmt.Sprintf("%s/%s/%s(%s)", res[0].ClusterKey, res[0].Namespace, res[0].Name, res[0].Kind)
			for _, r := range res[1:] {
				idStr += fmt.Sprintf(",%d", r.ID)
				nameStr += fmt.Sprintf(",%s/%s/%s(%s)", r.ClusterKey, r.Namespace, r.Name, r.Kind)
			}
			targetRef.ID = idStr
			targetRef.Name = nameStr
		}

		response.Ok(w, response.WithTotalItems(n), response.WithTarget(targetRef))
	}
}

func (api *api) behavioralLearnOneKeyEnabled() http.HandlerFunc {
	type reqData struct {
		Enabled bool `json:"enabled"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var req reqData
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("decode request body fail")
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					err))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}
		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		n, err := blSvc.BehavioralLearnOneKeyEnabled(ctx, req.Enabled, userName)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("one key enabled fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("one key enabled fail")))
			return
		}

		response.Ok(w, response.WithTotalItems(n))
	}
}

func (api *api) behavioralLearnModelAddFileFromOutSide() http.HandlerFunc {
	type reqItem struct {
		Id string `json:"id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		var req reqItem
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("decode request body fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}

		if req.Id == "" {
			logging.GetLogger().Error().Msg("id is empty")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("id is empty")))
			return
		}

		idUint, err := strconv.ParseUint(req.Id, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("id is invalid")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("id is invalid")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}
		retModel, err := blSvc.AddFileModelFromOutside(ctx, idUint, userName)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("add file model from outside fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("add file model from outside fail")))
			return
		}

		res, err := blSvc.GetResourceBasicInfo(ctx, retModel.ResourceUUID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource basic info fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get resource basic info fail")))
			return
		}

		response.Ok(w, response.WithTotalItems(1), response.WithCustomField("id", req.Id), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s/%s(%s): %s-%s", res.ClusterKey, res.Namespace, res.Name, res.Kind, req.Id, retModel.Path),
			ID:   req.Id,
		}))
	}
}

func (api *api) behavioralLearnModelAddCommandFromOutSide() http.HandlerFunc {
	type reqItem struct {
		Id string `json:"id"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		var req reqItem
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("decode request body fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}

		if req.Id == "" {
			logging.GetLogger().Error().Msg("id is empty")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("id is empty")))
			return
		}
		idUint, err := strconv.ParseUint(req.Id, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("id is invalid")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("id is invalid")))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}

		userName := request.GetAccountFromContext(ctx)
		if userName == "" {
			userName = "system"
		}

		retModel, err := blSvc.AddCommandModelFromOutside(ctx, idUint, userName)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("add network model from outside fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("add network model from outside fail")))
			return
		}

		res, err := blSvc.GetResourceBasicInfo(ctx, retModel.ResourceUUID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource basic info fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get resource basic info fail")))
			return
		}

		response.Ok(w, response.WithTotalItems(1), response.WithCustomField("id", req.Id), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s (%s): %s-%s", res.Namespace, res.Name, res.Kind, req.Id, retModel.Command),
			ID:   req.Id,
		}))
	}

}

func (api *api) behavioralLearnModelAddNetworkFromOutSide() http.HandlerFunc {
	type reqItem struct {
		Id string `json:"id"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		var req reqItem
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("decode request body fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}

		if req.Id == "" {
			logging.GetLogger().Error().Msg("id is empty")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("id is empty")))
			return
		}
		idUint, err := strconv.ParseUint(req.Id, 10, 64)
		if err != nil {
			logging.GetLogger().Error().Err(err).
				Msg("id is invalid")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("id is invalid")))
			return
		}

		blSvc, ok := bl.GetBehavioralLearnService()
		if !ok {
			logging.GetLogger().Error().Msg("get behavioral learn service fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get behavioral learn service fail")))
			return
		}
		retModel, err := blSvc.AddNetworkModelFromOutside(ctx, idUint)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("add network model from outside fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("add network model from outside fail")))
			return
		}

		res, err := blSvc.GetResourceBasicInfo(ctx, retModel.ResourceUUID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get resource basic info fail")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get resource basic info fail")))
			return
		}

		response.Ok(w, response.WithTotalItems(1), response.WithCustomField("id", req.Id), response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%s (%s): %s", res.Namespace, res.Name, res.Kind, req.Id),
			ID:   req.Id,
		}))
	}
}
