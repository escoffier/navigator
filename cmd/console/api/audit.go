package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/k8saudit"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) audit() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/", api.getAuditLog())
		r.Get("/config", api.getAuditConfig())
		r.Post("/config", api.setAuditConfig())
	}
}

const (
	auditDefaultTimeout  = time.Second * 5
	auditAPIVersion      = "2.0"
	maxAuditLogBatchSize = 100
)

func (api *api) getAuditLog() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), auditDefaultTimeout)
		defer cancel()

		offsetID, err := param.QueryString(r, "offsetID")
		if err != nil {
			offsetID = ""
		}

		limit, err := param.QueryUint(r, "limit")
		if err != nil {
			limit = maxAuditLogBatchSize
		}

		if limit > maxAuditLogBatchSize {
			limit = maxAuditLogBatchSize
		}

		startTimestamp, err := param.QueryInt64(r, "startTimestamp")
		if err != nil {
			startTimestamp = 0
		}

		endTimestamp, err := param.QueryInt64(r, "endTimestamp")
		if err != nil {
			endTimestamp = 0
		}

		if startTimestamp > endTimestamp || startTimestamp < 0 {
			apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(http.StatusBadRequest, fmt.Errorf("invalid time range")))
			return
		}

		sortOrder, err := api.sortOrderFromQuery(r, "desc")
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		var filter map[string]string
		filterStr, err := param.QueryString(r, "filter")
		if err == nil && filterStr != "" {
			logging.GetLogger().Debug().Msgf("filter:%s", filterStr)
			err = json.Unmarshal([]byte(filterStr), &filter)
			if err != nil {
				logging.GetLogger().Warn().Msgf("invalid filter:%s", filterStr)
				apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(http.StatusBadRequest, err))
				return
			}
		}

		service, ok := k8saudit.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		items, err := service.GetAuditLog(ctx, &k8saudit.GetAuditLogArg{
			OffsetID:       offsetID,
			Filter:         filter,
			StartTimestamp: startTimestamp,
			EndTimestamp:   endTimestamp,
			Limit:          int(limit),
			Asc:            sortOrder == "asc",
		})
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w,
			response.WithApiVersion(auditAPIVersion),
			response.WithItems(items))
	}
}

func (api *api) getAuditConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), auditDefaultTimeout)
		defer cancel()
		service, ok := k8saudit.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		conf, err := service.GetAuditConfig(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(auditAPIVersion), response.WithItem(*conf))
	}
}

func (api *api) setAuditConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), auditDefaultTimeout)
		defer cancel()
		var conf model.AuditLogConfig
		err := util.DecodeJSONBody(w, r, &conf)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		service, ok := k8saudit.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		err = service.SetAuditConfig(ctx, &conf)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(auditAPIVersion), response.WithItem(conf))
	}
}
