package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) cleanup() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/gc", api.gc())
		r.Post("/esgc", api.esgc())
		r.Get("/gc/{gcID}", api.getGarbageCollectionTask())
		r.Get("/esgc/{gcID}", api.getESGarbageCollectionTask())
		r.Get("/hotStorage", api.getHotStorageView())
		r.Get("/eshotStorage", api.getEsHotStorageView())
	}
}

// @Summary Get garbage collection task
// @Description Get garbage collection task
// @ID v1-cleanup-gctask-get
// @Produce json
// @Param gcID path string true "gcID"
// @Router /api/v1/cleanup/gc/{gcID} [get]
func (api *api) getGarbageCollectionTask() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		gcTaskID, err := getGCTaskIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read GC Task ID: %w", err),
					Suberror{"gcID", ""}))
			return
		}

		gcTask, err := api.cleanupService.GetGCTask(ctx, gcTaskID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't get GC Task: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*gcTask))
	}
}

// @Summary Get garbage collection task
// @Description Get garbage collection task
// @ID v2-cleanup-gctask-get
// @Produce json
// @Param gcID path string true "gcID"
// @Router /api/v2/platform/cleanup/esgc/{gcID} [get]
func (api *api) getESGarbageCollectionTask() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		gcTaskID, err := getGCTaskIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read ES GC Task ID: %w", err),
					Suberror{"gcID", ""}))
			return
		}

		gcTask, err := api.cleanupService.GetESGCTask(ctx, gcTaskID)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't get ES GC Task: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*gcTask))
	}
}

// @Summary Run hot storage garbage collection
// @Description Run hot storage garbage collection
// @ID v1-cleanup-gc-post
// @Produce json
// @Param hotStorageDays body int true "hotStorageDays"
// @Router /api/v1/cleanup/gc [post]
func (api *api) gc() http.HandlerFunc {
	type param struct {
		DaysOffset int `json:"daysOffset"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Minute*3)
		defer cancel()

		var param param
		err := util.DecodeJSONBody(w, r, &param)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}
		if param.DaysOffset <= 0 {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Invalid param")))
			return
		}

		fromTimestamp := time.Now().AddDate(0, 0, -1*param.DaysOffset)
		gcTask, err := api.cleanupService.CreateGCTask(ctx)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Cannot start GC: %w", err))
			return
		}
		gcCtx, _ := context.WithTimeout(api.ctx, time.Minute*1)
		go api.cleanupService.RunGarbageCollection(gcCtx, fromTimestamp, gcTask)

		response.Ok(w, response.WithItem(*gcTask))
	}
}

// @Summary Get hot storage view
// @Description Get hot storage view
// @ID v1-cleanup-hot-storage-view-get
// @Produce json
// @Router /api/v1/cleanup/hotStorage [get]
func (api *api) getHotStorageView() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		hotStorageView, err := api.cleanupService.GetHotStorageView(ctx)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't get hot storage view: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*hotStorageView))
	}
}

// @Summary Get hot es storage view
// @Description Get es hot storage view
// @ID v1-cleanup-es-hot-storage-view-get
// @Produce json
// @Router /api/v2/platform/cleanup/eshotStorage [get]
func (api *api) getEsHotStorageView() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		hotStorageView, err := api.cleanupService.GetEsHotStorageView(ctx)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't get hot storage view: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*hotStorageView))
	}
}

func getGCTaskIDFromURL(r *http.Request) (primitive.ObjectID, error) {
	gcID := chi.URLParam(r, "gcID")
	if gcID == "" {
		return primitive.NilObjectID, errors.New("gcID is not provided")
	}
	return primitive.ObjectIDFromHex(gcID)
}

// @Summary Run hot es storage garbage collection
// @Description Run hot  es storage garbage collection
// @ID v1-cleanup-es gc-post
// @Produce json
// @Param hotStorageDays body int true "hotStorageDays"
// @Router /api/v2/platform/cleanup/esgc [post]
func (api *api) esgc() http.HandlerFunc {
	type param struct {
		DaysOffset int `json:"daysOffset"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Minute*3)
		defer cancel()

		var param param
		err := util.DecodeJSONBody(w, r, &param)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}
		if param.DaysOffset <= 0 {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Invalid param")))
			return
		}

		esGcTask, err := api.cleanupService.CreateESGCTask(ctx)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Cannot start GC: %w", err))
			return
		}
		gcCtx, _ := context.WithTimeout(api.ctx, time.Minute*1)
		go api.cleanupService.RunGarbageEsCollection(gcCtx, param.DaysOffset, esGcTask)

		response.Ok(w, response.WithItem(*esGcTask))
	}
}
