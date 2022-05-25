package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/naviaudit"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"net/http"
	"time"
)

func (api *api) naviAudit() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/", api.getNaviAuditLog())
	}
}

func (api *api) getNaviAuditLog() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*5)
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

		service, ok := naviaudit.GetService()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		items, err := service.GetAuditLog(ctx, &naviaudit.QueryNaviAuditLogOpt{
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
