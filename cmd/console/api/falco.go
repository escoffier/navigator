package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/falco"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) falco() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/raiseAlert", api.raiseFalcoAlert())
	}
}

// @Summary Raise a falco alert
// @Description Raise a falco alert
// @ID v1-raise-alert-post
// @Produce json
// @Router /api/v1/falco/raiseAlert [post]
func (api *api) raiseFalcoAlert() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		var rawAlert falco.FalcoAlertRequest

		err := util.DecodeJSONBody(w, r, &rawAlert)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		err = api.falcoService.RaiseAlert(ctx, &rawAlert)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't raise falco alert: %w", err))
			return
		}

		response.Ok(w)
	}
}
