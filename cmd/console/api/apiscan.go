package api

import (
	"context"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/apiscan"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"net/http"
	"strconv"
	"time"
)

func (api *api) apiScan() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/apis/count", api.countApis())
		r.Get("/clusters/{cluster}/apis", api.listApis())
		r.Get("/clusters/{cluster}/apis/{apiID}", api.getSingleApi())
		r.Post("/clusters/{cluster}/apis/{apiID}/report", api.apiScanStoreResult())
		r.Get("/clusters/{cluster}/apis/{apiID}/report", api.getApiScanResult())
		r.Post("/clusters/{cluster}/apis/{apiID}/scan", api.apiScanLaunchJob())
		r.Get("/clusters/{cluster}/apis/{apiID}/scanstatus", api.getApiScanJobStatus())
	}
}

func (api *api) countApis() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resSvc, ok := apiscan.GetService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}
		cnt, err := resSvc.CountApis(ctx)
		if err != nil {
			logging.GetLogger().Err(err).Msg("count Namespaces error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}

		type resp struct {
			Count int64 `json:"count"`
		}

		response.Ok(w, response.WithItem(resp{Count: cnt}))
	}
}

func (api *api) apiScanStoreResult() http.HandlerFunc {
	type req struct {
		ScanResult string `json:"scanResult"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		apiID := chi.URLParam(r, "apiID")
		apiIDINT, err := strconv.ParseInt(apiID, 10, 64)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to parse api ID: %w", err)))
			return
		}
		var cliReq req
		err = util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		service, ok := apiscan.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		err = service.ApiScanStoreResult(ctx, apiIDINT, cliReq.ScanResult)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w)
	}
}

func (api *api) apiScanLaunchJob() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		cluster := chi.URLParam(r, "cluster")
		apiID := chi.URLParam(r, "apiID")
		apiIDINT, err := strconv.ParseInt(apiID, 10, 64)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to parse api ID: %w", err)))
			return
		}

		service, ok := apiscan.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		err = service.ApiScanLaunchJob(ctx, cluster, apiIDINT)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w)
	}
}

func (api *api) getApiScanJobStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		cluster := chi.URLParam(r, "cluster")
		apiID := chi.URLParam(r, "apiID")

		apiIDINT, err := strconv.ParseInt(apiID, 10, 64)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to parse api ID: %w", err)))
			return
		}

		service, ok := apiscan.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		status, err := service.GetApiScanJobStatus(ctx, apiIDINT)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}
		result := struct {
			ID      int64  `json:"id"`
			Cluster string `json:"cluster"`
			Status  int    `json:"status"`
		}{
			ID:      apiIDINT,
			Cluster: cluster,
			Status:  status,
		}
		response.Ok(w, response.WithItem(result))
	}
}

func (api *api) listApis() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		cluster := chi.URLParam(r, "cluster")
		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get limit or offset query error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		service, ok := apiscan.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		result, totoalItems, err := service.ListApis(ctx, cluster, limit, offset)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}
		response.Ok(w, response.WithItems(result), response.WithTotalItems(totoalItems))
	}
}

func (api *api) getApiScanResult() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		cluster := chi.URLParam(r, "cluster")
		apiID := chi.URLParam(r, "apiID")

		apiIDINT, err := strconv.ParseInt(apiID, 10, 64)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to parse api ID: %w", err)))
			return
		}

		service, ok := apiscan.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		scanResult, err := service.GetApiScanResult(ctx, apiIDINT)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}
		result := struct {
			ID      int64
			Cluster string
			Report  []apiscan.SingleApiScanResult
		}{
			ID:      apiIDINT,
			Cluster: cluster,
			Report:  scanResult,
		}
		response.Ok(w, response.WithItem(result))
	}
}

func (api *api) getSingleApi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		apiID := chi.URLParam(r, "apiID")

		apiIDINT, err := strconv.ParseInt(apiID, 10, 64)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to parse api ID: %w", err)))
			return
		}

		service, ok := apiscan.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		singleApi, err := service.GetSingleApi(ctx, apiIDINT)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItem(singleApi))
	}
}
