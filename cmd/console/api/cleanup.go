package api

import (
	"context"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cleanup"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

const (
	cleanupApiVersion = "2.0"
)

func (api *api) cleanup() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/logicGC", api.logicGC())
		r.Post("/offlineGC", api.offlineGC())
		r.Get("/logicGC/{gcID}", api.getLogicGarbageCollectionTask())
		r.Get("/offlineGC/{gcID}", api.getOfflineGarbageCollectionTask())
		r.Get("/logicHotStorage", api.getLogicHotStorageView())
		r.Get("/offlineHotStorage", api.getOfflineHotStorageView())
	}
}

// @Summary Get garbage collection task
// @Description Get garbage collection task
// @ID v2-cleanup-logic-gc-task-get
// @Produce json
// @Param gcID path string true "gcID"
// @Router /api/v2/cleanup/logicGC/{gcID} [get]
func (api *api) getLogicGarbageCollectionTask() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		gcTaskID, err := getGCTaskIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("couldn't read logicGC Task ID: %w", err),
					Suberror{Location: "gcID", Message: ""}))
			return
		}

		gcTask, err := api.cleanupService.GetGCTask(ctx, gcTaskID, cleanup.GCTaskTypeLogic)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("couldn't get logicGC Task: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*gcTask), response.WithApiVersion(cleanupApiVersion))
	}
}

// @Summary Get garbage collection task
// @Description Get garbage collection task
// @ID v2-cleanup-offline-gc-task-get
// @Produce json
// @Param gcID path string true "gcID"
// @Router /api/v2/platform/cleanup/offlineGC/{gcID} [get]
func (api *api) getOfflineGarbageCollectionTask() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		gcTaskID, err := getGCTaskIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("couldn't read offlineGC Task ID: %w", err),
					Suberror{Location: "gcID", Message: ""}))
			return
		}

		gcTask, err := api.cleanupService.GetGCTask(ctx, gcTaskID, cleanup.GCTaskTypeOffline)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("couldn't get offlineGC Task: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*gcTask), response.WithApiVersion(cleanupApiVersion))
	}
}

// @Summary Run hot storage garbage collection
// @Description Run hot storage garbage collection
// @ID v2-cleanup-logicGC-post
// @Produce json
// @Param hotStorageDays body int true "hotStorageDays"
// @Router /api/v2/cleanup/logicGC [post]
func (api *api) logicGC() http.HandlerFunc {
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
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		if param.DaysOffset <= 0 {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("invalid param")))
			return
		}

		gcTask, err := api.cleanupService.CreateGCTask(ctx, cleanup.GCTaskTypeLogic)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("cannot start GC: %w", err))
			return
		}
		go api.cleanupService.RunLogicGarbageCollection(api.ctx, param.DaysOffset, gcTask.ID)

		response.Ok(w, response.WithItem(*gcTask), response.WithApiVersion(cleanupApiVersion))
	}
}

// @Summary Get logic hot storage view
// @Description Get logic hot storage view
// @ID v2-cleanup-logic-hot-storage-view-get
// @Produce json
// @Router /api/v2/cleanup/logicHotStorage [get]
func (api *api) getLogicHotStorageView() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		hotStorageView, err := api.cleanupService.GetLogicHotStorageView()
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("couldn't get hot storage view: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*hotStorageView), response.WithApiVersion(cleanupApiVersion))
	}
}

// @Summary Get hot offline storage view
// @Description Get offline hot storage view
// @ID v2-cleanup-es-hot-storage-view-get
// @Produce json
// @Router /api/v2/platform/cleanup/offlineHotStorage [get]
func (api *api) getOfflineHotStorageView() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		hotStorageView, err := api.cleanupService.GetOfflineHotStorageView()
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("couldn't get offline hot storage view: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*hotStorageView), response.WithApiVersion(cleanupApiVersion))
	}
}

func getGCTaskIDFromURL(r *http.Request) (primitive.ObjectID, error) {
	gcID := chi.URLParam(r, "gcID")
	if gcID == "" {
		return primitive.NilObjectID, errors.New("gcID is not provided")
	}
	return primitive.ObjectIDFromHex(gcID)
}

// @Summary Run hot offline storage garbage collection
// @Description Run hot offline storage garbage collection
// @ID v2-cleanup-offline-gc-post
// @Produce json
// @Param hotStorageDays body int true "hotStorageDays"
// @Router /api/v2/platform/cleanup/offlineGC [post]
func (api *api) offlineGC() http.HandlerFunc {
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
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		if param.DaysOffset <= 0 {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("invalid param")))
			return
		}

		esGcTask, err := api.cleanupService.CreateGCTask(ctx, cleanup.GCTaskTypeOffline)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("cannot start offlineGC: %w", err))
			return
		}
		go api.cleanupService.RunOfflineGarbageCollection(api.ctx, param.DaysOffset, esGcTask.ID)

		response.Ok(w, response.WithItem(*esGcTask), response.WithApiVersion(cleanupApiVersion))
	}
}
