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

		err = svc.EditPolicy(ctx, &policy, readUpdateStamp)
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
