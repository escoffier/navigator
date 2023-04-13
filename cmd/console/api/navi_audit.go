package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi"
	json "github.com/json-iterator/go"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/naviaudit"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/security-rd/go-pkg/logging"
)

func (api *api) naviAudit() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/", api.getNaviAuditLog())
		r.Post("/exportTask", api.RedirectToAuditExport())
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
		if startTimestamp > 0 && endTimestamp == 0 {
			endTimestamp = time.Now().UnixMilli()
			logging.Get().Info().Msgf("endTimestamp: %d", endTimestamp)
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
			logging.Get().Debug().Msgf("filter:%s", filterStr)
			err = json.Unmarshal([]byte(filterStr), &filter)
			if err != nil {
				logging.Get().Warn().Msgf("invalid filter:%s", filterStr)
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

func (api *api) RedirectToAuditExport() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// /api/v2/platform/naviAudit/exportTask
		// /api/v1/task/naviAudit

		pre := r.URL.String()
		newUrl := fmt.Sprintf("%s%s", api.exportURL,
			strings.Replace(pre, "/api/v2/platform/naviAudit/exportTask", "/api/v1/export/task/naviAudit", 1))

		u, err := url.Parse(newUrl)
		if nil != err {
			apperror.RespAndLog(w, r.Context(), apperror.NewFieldError(http.StatusBadRequest, fmt.Errorf("count not parse the url:%s,error  %w", pre, err)))
			return
		}

		roundTripper := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Minute,
				KeepAlive: 10 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       9 * time.Minute,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		proxy := httputil.ReverseProxy{
			Director: func(request *http.Request) {
				request.URL = u
			},
			Transport: roundTripper,
		}
		proxy.ServeHTTP(w, r)
	}
}
