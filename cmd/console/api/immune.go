package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/immune"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) immune() func(chi.Router) {
	return func(r chi.Router) {
		// policies
		r.Get("/policies", api.listImmunePolicies())
		r.Get("/policy/{policyID}", api.getPolicy())
		r.Put("/policy", api.createPolicy())
		r.Post("/policy/{policyID}/edit", api.editPolicy())
		r.Post("/policy/{policyID}/enable", api.enablePolicy())
		r.Post("/policy/{policyID}/disable", api.disablePolicy())

		// resources
		r.Get("/resources", api.getImmuneResources())
		r.Put("/resource/{resourceUUID}/learning/kind/{policyKind}/start", api.startImmuneTask())
		// tmp
		r.Get("/resource/{resourceUUID}/learning/state", api.getStateOfResourceTask())
	}
}

func toInt32Array(strArr []string) ([]int32, error) {
	res := make([]int32, len(strArr))
	for i, s := range strArr {
		v, err := strconv.ParseInt(s, 10, 32)
		if err != nil {
			return nil, err
		}
		res[i] = int32(v)
	}
	return res, nil
}

func (api *api) getImmuneResources() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error offset limit")))
			return
		}

		query := dal.ResourcesQuery()

		clusterKey, err := param.QueryString(r, "cluster_key")
		if err == nil && clusterKey != "" {
			query = query.WithCluster(clusterKey)
		}
		queryStr, err := param.QueryString(r, "query")
		if err == nil && queryStr != "" {
			query = query.WithColumnQuery("name", queryStr)
		}

		svc, ok := immune.Get()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("error get service")))
			return
		}
		resources, totalCnt, err := svc.GetResources(ctx, query, offset, limit)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(resources), response.WithTotalItems(totalCnt))
	}
}

func (api *api) startImmuneTask() http.HandlerFunc {
	type req struct {
		DurationSec int64 `json:"durationSec"`
	}
	type resp struct {
		TaskID int64 `json:"taskID"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		rStr := chi.URLParam(r, "resourceUUID")
		if len(rStr) == 0 {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error url param resourceUUID")))
			return
		}
		resourceUUID64, err := strconv.ParseUint(rStr, 10, 32)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error url param resourceUUID")))
			return
		}
		resourceUUID := uint32(resourceUUID64)

		policyKindStr := chi.URLParam(r, "policyKind")
		if len(policyKindStr) == 0 {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error url param policyKind")))
			return
		}
		policyKindI, err := strconv.ParseInt(policyKindStr, 10, 64)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error url param policyKind")))
			return
		}
		policyKind := model.PolicyKind(policyKindI)

		var req req
		err = util.DecodeJSONBody(w, r, &req)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, errors.New("decode req payload err")))
			return
		}

		svc, ok := immune.Get()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("error get service")))
			return
		}
		taskID, err := svc.StartTask(ctx, resourceUUID, policyKind, time.Second*time.Duration(req.DurationSec))
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItem(resp{taskID}))
	}
}

func (api *api) getStateOfResourceTask() http.HandlerFunc {
	type resp struct {
		State model.TaskState `json:"state"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		rStr := chi.URLParam(r, "resourceUUID")
		if len(rStr) == 0 {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error url param resourceUUID")))
			return
		}
		resourceUUID64, err := strconv.ParseUint(rStr, 10, 32)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error url param resourceUUID")))
			return
		}
		resourceUUID := uint32(resourceUUID64)

		svc, ok := immune.Get()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("error get service")))
			return
		}

		state, err := svc.CheckTaskState(ctx, resourceUUID)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItem(resp{state}))
	}
}

func (api *api) listImmunePolicies() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error offset limit")))
			return
		}
		query := dal.NewImmunePoliciesQuery()
		clusterKey, err := param.QueryString(r, "cluster_key")
		if err == nil || clusterKey != "" {
			query = query.WithClusterKey(clusterKey)
		}
		statuses, err := param.QueryInt32Array(r, "status")
		if err == nil && len(statuses) > 0 {
			query = query.WithStatuses(statuses)
		}
		kinds, err := param.QueryInt32Array(r, "kind")
		if err == nil && len(kinds) > 0 {
			query = query.WithKinds(kinds)
		}
		resourceUUID, err := param.QueryUint32(r, "resource_uuid")
		if err == nil && resourceUUID > 0 {
			query = query.WithResourceUUID(resourceUUID)
		}
		queryStr, err := param.QueryString(r, "query")
		if err == nil && len(queryStr) > 0 {
			query = query.WithQuery(queryStr)
		}

		svc, ok := immune.Get()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("error get service")))
			return
		}
		policies, totalCnt, err := svc.ListPolicies(ctx, query, offset, limit)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(policies), response.WithTotalItems(totalCnt))
	}
}

func (api *api) getPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		policyIDStr := chi.URLParam(r, "policyID")
		if len(policyIDStr) == 0 {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error url param policyID")))
			return
		}
		policyID, err := strconv.ParseInt(policyIDStr, 10, 64)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error url param policyID")))
			return
		}

		svc, ok := immune.Get()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("error get service")))
			return
		}
		policyView, err := svc.GetPolicy(ctx, policyID)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItem(policyView))
	}
}

func (api *api) createPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		var policy immune.PolicyView
		err := util.DecodeJSONBody(w, r, &policy)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, err))
			return
		}

		svc, ok := immune.Get()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("error get service")))
			return
		}
		_, err = svc.AddPolicy(ctx, &policy)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w)
	}
}

func (api *api) editPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		policyIDStr := chi.URLParam(r, "policyID")
		if policyIDStr == "" {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error policyID")))
			return
		}
		policyID, err := strconv.ParseInt(policyIDStr, 10, 64)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error policyID")))
			return
		}
		readUpdateStamp, err := param.QueryInt64(r, "read_update_timestamp")
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, err))
			return
		}

		var policy immune.PolicyView
		err = util.DecodeJSONBody(w, r, &policy)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error url param policyID")))
			return
		}
		policy.ID = policyID

		svc, ok := immune.Get()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("error get service")))
			return
		}

		err = svc.EditPolicy(ctx, policyID, &policy, readUpdateStamp)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w)
	}
}

func (api *api) enablePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		policyIDStr := chi.URLParam(r, "policyID")
		if policyIDStr == "" {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error policyID")))
			return
		}
		policyID, err := strconv.ParseInt(policyIDStr, 10, 64)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error policyID")))
			return
		}
		readUpdateStamp, err := param.QueryInt64(r, "read_update_timestamp")
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error read_update_timestamp")))
			return
		}

		svc, ok := immune.Get()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("error get service")))
			return
		}

		err = svc.PolicyStatusAction(ctx, model.StatusEnable, policyID, readUpdateStamp)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w)

	}
}

func (api *api) disablePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		policyIDStr := chi.URLParam(r, "policyID")
		if policyIDStr == "" {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error policyID")))
			return
		}
		policyID, err := strconv.ParseInt(policyIDStr, 10, 64)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error policyID")))
			return
		}
		readUpdateStamp, err := param.QueryInt64(r, "read_update_timestamp")
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error read_update_timestamp")))
			return
		}

		svc, ok := immune.Get()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("error get service")))
			return
		}

		err = svc.PolicyStatusAction(ctx, model.StatusDisable, policyID, readUpdateStamp)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w)
	}
}
