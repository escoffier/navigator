package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/data"
	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	dataAPIVersion     = "2.0"
	dataDefaultTimeout = time.Second * 10
)

func (api *api) data() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/gc", api.runGCTask())
		r.Get("/gc/{gcID}", api.getGCTask())
		r.Post("/ttl", api.setDataTTL())
		r.Get("/ttl", api.getDataTTL())
		r.Get("/storage", api.getStorageView())
		r.Get("/waterline", api.getWaterline())
		r.Post("/waterline", api.setWaterline())
	}
}

func (api *api) runGCTask() http.HandlerFunc {
	type req struct {
		DataType   string `json:"dataType"`
		DaysOffset int    `json:"daysOffset"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), dataDefaultTimeout)
		defer cancel()

		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if !checkDataType(cliReq.DataType) {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, def.ErrInvalidDataType, apperror.Suberror{
					Location: "dataType",
					Message:  def.ErrInvalidDataType.Error(),
				}))
			return
		}

		ttlValid, err := api.checkTTL(ctx, cliReq.DataType, cliReq.DaysOffset)
		if err != nil {
			apperror.RespAndLog(w, ctx, fmt.Errorf("couldn't check data tll: %w", err))
			return
		}

		if !ttlValid {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, def.ErrInvalidTTL, apperror.Suberror{
					Location: "daysOffset",
					Message:  def.ErrInvalidTTL.Error(),
				}))
			return
		}

		dataService, ok := data.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		gcTask, err := dataService.RunGC(ctx, cliReq.DataType, cliReq.DaysOffset)
		if err != nil {
			if err == def.ErrTaskConflict {
				apperror.RespAndLog(w, ctx,
					apperror.NewGCTaskInProgressError(http.StatusBadRequest, err, apperror.Suberror{
						Message: err.Error(),
					}))
				return
			}

			apperror.RespAndLog(w, ctx, fmt.Errorf("couldn't run gc Task: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*gcTask), response.WithApiVersion(dataAPIVersion))
	}
}

func (api *api) getGCTask() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), dataDefaultTimeout)
		defer cancel()

		gcTaskID, err := getGCTaskIDFromURL(r)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest,
					def.ErrInvalidTaskID,
					apperror.Suberror{Location: "gcID", Message: ""}))
			return
		}

		dataService, ok := data.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		gcTask, err := dataService.GetGCTask(ctx, gcTaskID)
		if err != nil {
			if err == def.ErrTaskNotFound {
				apperror.RespAndLog(w, ctx,
					apperror.NewInvalidArgError(http.StatusBadRequest,
						err,
						apperror.Suberror{Location: "gcID", Message: err.Error()}))
				return
			}

			apperror.RespAndLog(w, ctx, fmt.Errorf("couldn't get logicGC Task: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*gcTask), response.WithApiVersion(dataAPIVersion))
	}
}

func (api *api) setDataTTL() http.HandlerFunc {
	type req struct {
		DataType string `json:"dataType"`
		TTLDays  int    `json:"ttlDays"`
	}

	type rsp struct {
		TTLDays int `json:"ttlDays"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), dataDefaultTimeout)
		defer cancel()
		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if !checkDataType(cliReq.DataType) {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, def.ErrInvalidDataType, apperror.Suberror{
					Location: "dataType",
					Message:  def.ErrInvalidDataType.Error(),
				}))
			return
		}

		ttlValid, err := api.checkTTL(ctx, cliReq.DataType, cliReq.TTLDays)
		if err != nil {
			apperror.RespAndLog(w, ctx, fmt.Errorf("couldn't check data tll: %w", err))
			return
		}

		if !ttlValid {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, def.ErrInvalidTTL, apperror.Suberror{
					Location: "ttlDays",
					Message:  def.ErrInvalidTTL.Error(),
				}))
			return
		}

		dataService, ok := data.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		err = dataService.SetDataTTL(ctx, cliReq.DataType, cliReq.TTLDays)
		if err != nil {
			apperror.RespAndLog(w, ctx, fmt.Errorf("couldn't set data tll: %w", err))
			return
		}

		response.Ok(w, response.WithItem(rsp{TTLDays: cliReq.TTLDays}), response.WithApiVersion(dataAPIVersion))
	}
}

func (api *api) getDataTTL() http.HandlerFunc {
	type rsp struct {
		TTLDays int `json:"ttlDays"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), dataDefaultTimeout)
		defer cancel()
		dataType, err := api.getDataType(r)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, err, apperror.Suberror{
					Location: "dataType",
					Message:  err.Error(),
				}))
			return
		}

		dataService, ok := data.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		dataTTL, err := dataService.GetDataTTL(ctx, dataType)
		if err != nil {
			apperror.RespAndLog(w, ctx, fmt.Errorf("couldn't get data tll: %w", err))
			return
		}

		response.Ok(w, response.WithItem(rsp{TTLDays: dataTTL}), response.WithApiVersion(dataAPIVersion))
	}
}

func (api *api) getStorageView() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), dataDefaultTimeout)
		defer cancel()
		dataType, err := api.getDataType(r)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, err, apperror.Suberror{
					Location: "dataType",
					Message:  err.Error(),
				}))
			return
		}

		dataService, ok := data.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		storageView, err := dataService.GetStorageView(ctx, dataType)
		if err != nil {
			apperror.RespAndLog(w, ctx, fmt.Errorf("couldn't get storage view: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*storageView), response.WithApiVersion(dataAPIVersion))
	}
}

func (api *api) setWaterline() http.HandlerFunc {
	type req struct {
		Percentage int `json:"percentage"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), dataDefaultTimeout)
		defer cancel()
		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if !checkWaterline(cliReq.Percentage) {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, def.ErrInvalidWaterline, apperror.Suberror{
					Location: "percentage",
					Message:  def.ErrInvalidWaterline.Error(),
				}))
			return
		}

		dataService, ok := data.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		err = dataService.SetDataWaterline(ctx, cliReq.Percentage)
		if err != nil {
			apperror.RespAndLog(w, ctx, fmt.Errorf("couldn't set waterline: %w", err))
			return
		}
		response.Ok(w, response.WithItem(cliReq), response.WithApiVersion(dataAPIVersion))
	}
}

func (api *api) getWaterline() http.HandlerFunc {
	type rsp struct {
		Percentage int `json:"percentage"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), dataDefaultTimeout)
		defer cancel()

		dataService, ok := data.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		percentage, err := dataService.GetDataWaterline(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, fmt.Errorf("couldn't get waterline: %w", err))
			return
		}
		response.Ok(w, response.WithItem(rsp{Percentage: percentage}), response.WithApiVersion(dataAPIVersion))
	}
}

func (api *api) getDataType(r *http.Request) (string, error) {
	dataType, err := param.QueryString(r, "dataType")
	if err != nil {
		return "", err
	}

	if !checkDataType(dataType) {
		return "", def.ErrInvalidDataType
	}

	return dataType, nil
}

func getGCTaskIDFromURL(r *http.Request) (string, error) {
	gcID := chi.URLParam(r, "gcID")
	if gcID == "" {
		return "", errors.New("gcID is not provided")
	}
	return gcID, nil
}

func checkDataType(dataType string) bool {
	return dataType == model.DataTypeHotLogic ||
		dataType == model.DataTypeHotOffline ||
		dataType == model.DataTypeCold
}

func (api *api) checkTTL(ctx context.Context, dataType string, ttl int) (bool, error) {
	if ttl <= 0 {
		return false, nil
	}

	dataService, ok := data.GetService(ctx)
	if !ok {
		return false, ErrServiceNotReady
	}
	if dataType == model.DataTypeCold {
		hotLogicTTL, err := dataService.GetDataTTL(ctx, model.DataTypeHotLogic)
		if err != nil {
			return false, err
		}

		if hotLogicTTL >= ttl {
			return false, nil
		}

		hotOfflineTTL, err := dataService.GetDataTTL(ctx, model.DataTypeHotOffline)
		if err != nil {
			return false, err
		}

		return hotOfflineTTL < ttl, nil
	}

	coldTTL, err := dataService.GetDataTTL(ctx, model.DataTypeCold)
	if err != nil {
		return false, err
	}

	return coldTTL > ttl, nil
}

func checkWaterline(percentage int) bool {
	return percentage >= 1 && percentage <= 100
}
