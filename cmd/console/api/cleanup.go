package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) cleanup() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/gc", api.runGarbageCollection())
		r.Get("/hotStorage", api.getHotStorageView())
	}
}

// @Summary Run hot storage garbage collection
// @Description Run hot storage garbage collection
// @ID v1-cleanup-gc-post
// @Produce json
// @Param hotStorageDays body int true "hotStorageDays"
// @Router /api/v1/cleanup/gc [post]
func (api *api) runGarbageCollection() http.HandlerFunc {
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
		err = api.cleanupService.RunGarbageCollection(ctx, fromTimestamp)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Garbage collection returned an error: %w", err))
			return
		}

		response.Ok(w)
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
