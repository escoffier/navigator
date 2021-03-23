package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/driftprevention"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) driftPrevention() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/raiseAlert", api.raiseDriftPreventionAlert())
	}
}

// @Summary Raise a drift prevention alert
// @Description Raise a drift prevention alert
// @ID v1-raise-drift-prevention-alert-post
// @Produce json
// @Router /api/v1/driftPrevention/raiseAlert [post]
func (api *api) raiseDriftPreventionAlert() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		var rawAlert driftprevention.DriftPreventionAlertRequest

		err := util.DecodeJSONBody(w, r, &rawAlert)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		err = api.driftPreventionService.RaiseAlert(ctx, &rawAlert)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't raise drift prevention alert: %w", err))
			return
		}

		response.Ok(w)
	}
}
