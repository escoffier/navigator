package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/k8saudit"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"net/http"
	"os"
	"strconv"
)

func (api *api) auditLogOpenApi() func(chi.Router) {
	rate, err := strconv.Atoi(os.Getenv("OPENAPI_RATE_LIMIT_PER_MIN"))
	if err != nil || rate <= 0 {
		rate = 20
	}

	return func(r chi.Router) {

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/", api.getAuditLogOpenApi())

		exportContainers := os.Getenv("EXPORT_CONTAINERS")
		if exportContainers == "true" {
			r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
				Get("/containers", api.getContainers())
		}
	}
}

func (api *api) getAuditLogOpenApi() http.HandlerFunc {

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

		auditLogs, err := service.GetAuditLog(ctx, &k8saudit.GetAuditLogArg{
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
		var items []KubeAuditLogOpenApi
		for _, auditLog := range auditLogs {
			items = append(items, KubeAuditLogOpenApi{
				ID:                       auditLog.ID,
				SourceIPs:                auditLog.SourceIPs,
				Verb:                     auditLog.Verb,
				Namespace:                auditLog.Namespace,
				ResourceKind:             auditLog.ResourceKind,
				ResourceName:             auditLog.ResourceName,
				ResponseStatusCode:       auditLog.ResponseStatusCode,
				Stage:                    auditLog.Stage,
				StageTimestamp:           auditLog.StageTimestamp,
				Username:                 auditLog.Username,
				Level:                    auditLog.Level,
				RequestReceivedTimestamp: auditLog.RequestReceivedTimestamp,
				UserAgent:                auditLog.UserAgent,
				RequestURI:               auditLog.RequestURI,
				APIVersion:               auditLog.APIVersion,
				AuthorizationDecision:    auditLog.AuthorizationDecision,
				AuthorizationReason:      auditLog.AuthorizationReason,
			})
		}

		response.Ok(w,
			response.WithApiVersion(auditAPIVersion),
			response.WithItems(items))
	}
}
