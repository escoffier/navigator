package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/processingcenter"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	processingCenterDefaultTimeout = time.Second * 5
	processingCenterAPIVersion     = "2.0"
)

var (
	ErrInvalidArgs = errors.New("invalid args")
)

func (api *api) processingCenter() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/record", api.addProcessingRecord())
		r.Get("/record", api.getProcessingRecords())
		r.Post("/record/status", api.updateProcessingRecordStatus())
		r.Post("/record/action", api.addProcessingAction())
		r.Get("/record/detail", api.getProcessingDetail())
	}
}

func (api *api) addProcessingRecord() http.HandlerFunc {
	type req struct {
		EventID int64    `json:"eventID,string"`
		OpType  string   `json:"opType"`
		Action  string   `json:"action"`
		Object  []string `json:"object"`
	}

	type rsp struct {
		ID string `json:"id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), processingCenterDefaultTimeout)
		defer cancel()

		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if len(cliReq.Object) == 0 {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, ErrInvalidArgs))
			return
		}

		service, ok := processingcenter.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		id, partial, err := service.CreateProcessingRecord(ctx, &processingcenter.AddProcessingRecordArg{
			EventID: cliReq.EventID,
			OpType:  cliReq.OpType,
			Action:  cliReq.Action,
			Object:  cliReq.Object,
		})

		if err != nil {
			if err == processingcenter.ErrInvalidPodInfo {
				apperror.RespAndLog(w, ctx,
					apperror.NewInvalidArgError(http.StatusBadRequest, ErrInvalidArgs))
			} else if err == processingcenter.ErrInvalidOp {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"无效的操作", "Invalid operation"))
			} else if err == processingcenter.ErrPodNotExist {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"所有pod均不存在", "None of the pods exist"))
			} else if err == processingcenter.ErrPodIsolated {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"pod已隔离", "Pods are already isolated"))
			} else {
				apperror.RespAndLog(w, ctx, err)
			}
			return
		}

		var status uint8
		if partial {
			status = 1
		}

		names, _ := processingcenter.GenFullPodName(cliReq.Object)
		response.Ok(w, response.WithApiVersion(processingCenterAPIVersion), response.WithItem(rsp{ID: id}),
			response.WithExportFileStatus(status), response.WithTarget(&response.TargetRef{
				Name: names,
				ID:   "",
				Link: "",
			}))
	}
}

const (
	maxRecordBatchSize = 20
	maxPagination      = 10000
)

func (api *api) getProcessingRecords() http.HandlerFunc {
	type item struct {
		ID         string   `json:"id"`
		EventID    int64    `json:"eventID,string"`
		OpType     string   `json:"opType"`
		Status     string   `json:"status"`
		LastOpUser string   `json:"lastOpUser"`
		Object     []string `json:"object"`
		UpdatedAt  int64    `json:"updatedAt"`
	}

	convert := func(record *model.ProcessingRecord) *item {
		return &item{
			ID:         record.ID,
			EventID:    record.EventID,
			OpType:     record.OpType,
			Status:     record.Status,
			LastOpUser: record.LastOpUser,
			Object:     record.Object,
			UpdatedAt:  record.UpdatedAt,
		}
	}

	batchConvert := func(records []*model.ProcessingRecord) []*item {
		result := make([]*item, len(records))
		for i := range records {
			result[i] = convert(records[i])
		}
		return result
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), processingCenterDefaultTimeout)
		defer cancel()
		service, ok := processingcenter.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		id, err := param.QueryString(r, "id")
		//// query by id
		//if err == nil && len(id) > 0 {
		//	record, err := service.GetProcessingRecordByID(ctx, id)
		//	if err != nil && err != processingcenter.ErrRecordNotFound {
		//		apperror.RespAndLog(w, ctx, err)
		//		return
		//	}
		//
		//	if record != nil {
		//		response.Ok(w, response.WithApiVersion(processingCenterAPIVersion), response.WithItems([]*item{convert(record)}), response.WithTotalItems(1))
		//		return
		//	}
		//
		//	response.Ok(w, response.WithApiVersion(processingCenterAPIVersion))
		//	return
		//}
		offset, err := param.QueryUint(r, "offset")
		if err != nil {
			offset = 0
		}

		limit, err := param.QueryUint(r, "limit")
		if err != nil {
			limit = maxRecordBatchSize
		}

		if limit > maxRecordBatchSize {
			limit = maxRecordBatchSize
		}

		if offset+limit > maxPagination {
			apperror.RespAndLog(w, ctx,
				apperror.NewCommonError(http.StatusBadRequest, err,
					"超过分页限制", "Exceed the paging limit"))
			return
		}

		startTimestamp, err := param.QueryInt64(r, "startTimestamp")
		if err != nil {
			startTimestamp = 0
		}

		endTimestamp, err := param.QueryInt64(r, "endTimestamp")
		if err != nil {
			endTimestamp = time.Now().UnixMilli()
		}

		if startTimestamp > endTimestamp || startTimestamp < 0 {
			apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(http.StatusBadRequest, fmt.Errorf("invalid time range")))
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

		total, records, err := service.GetProcessingRecord(ctx, &model.QueryProcessingRecordArg{
			ID:             id,
			Filter:         filter,
			StartTimestamp: startTimestamp,
			EndTimestamp:   endTimestamp,
			Offset:         int(offset),
			Limit:          int(limit),
		})
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(processingCenterAPIVersion), response.WithItems(batchConvert(records)), response.WithTotalItems(total))
	}
}

func (api *api) updateProcessingRecordStatus() http.HandlerFunc {
	type req struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), processingCenterDefaultTimeout)
		defer cancel()

		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if len(cliReq.ID) == 0 {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, ErrInvalidArgs))
			return
		}

		service, ok := processingcenter.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		err = service.UpdateProcessingRecordStatus(ctx, cliReq.ID, cliReq.Status)
		if err != nil {
			if err == processingcenter.ErrInvalidOp {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"无效的操作", "invalid operation"))
			} else if err == processingcenter.ErrUpdateConflict {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"其他人正在操作", "other person is operating"))
			} else if err == processingcenter.ErrRecordNotFound {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"记录不存在", "record not exists"))
			} else {
				apperror.RespAndLog(w, ctx, err)
			}
			return
		}

		response.Ok(w, response.WithApiVersion(processingCenterAPIVersion), response.WithItem(cliReq))
	}
}

func (api *api) addProcessingAction() http.HandlerFunc {
	type req struct {
		ID     string   `json:"id"`
		Object []string `json:"object"`
		Action string   `json:"action"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), processingCenterDefaultTimeout)
		defer cancel()

		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if len(cliReq.ID) == 0 {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, ErrInvalidArgs))
			return
		}

		service, ok := processingcenter.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		action, partial, err := service.AddProcessingAction(ctx, &processingcenter.AddProcessingActionArg{
			RecordID: cliReq.ID,
			Action:   cliReq.Action,
			Object:   cliReq.Object,
		})
		if err != nil {
			if err == processingcenter.ErrInvalidOp {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"无效的操作", "invalid operation"))
			} else if err == processingcenter.ErrUpdateConflict {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"其他人正在操作", "other person is operating"))
			} else if err == processingcenter.ErrRecordNotFound {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"记录不存在", "record not exists"))
			} else {
				apperror.RespAndLog(w, ctx, err)
			}
			return
		}

		var status uint8
		if partial {
			status = 1
		}

		names, _ := processingcenter.GenFullPodName(cliReq.Object)
		response.Ok(w, response.WithApiVersion(processingCenterAPIVersion),
			response.WithTarget(&response.TargetRef{
				Name: names,
				ID:   "",
				Link: "",
			}),
			response.WithItem(*action), response.WithExportFileStatus(status))
	}
}

func (api *api) getProcessingDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), processingCenterDefaultTimeout)
		defer cancel()
		id, err := param.QueryString(r, "id")
		if err != nil || len(id) == 0 {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, ErrInvalidArgs))
			return
		}
		service, ok := processingcenter.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		detail, err := service.GetRecordDetail(ctx, id)
		if err != nil {
			if err == processingcenter.ErrRecordNotFound {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"记录不存在", "record not exists"))
				return
			}

			apperror.RespAndLog(w, ctx, err)
			return
		}
		response.Ok(w, response.WithApiVersion(processingCenterAPIVersion), response.WithItem(*detail))
	}
}
