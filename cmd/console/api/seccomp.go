package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) seccomp() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/raiseAlert", api.raiseSeccompAlert())
	}
}

// @Summary Raise a seccomp alert
// @Description Raise a seccomp alert
// @ID v1-raise-seccomp-alert-post
// @Produce json
// @Router /api/v1/seccomp/raiseAlert [post]
func (api *api) raiseSeccompAlert() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		var rawAlert model.SeccompProfileAlertRequest

		err := util.DecodeJSONBody(w, r, &rawAlert)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		err = api.seccompProfileService.RaiseAlert(ctx, &rawAlert)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't raise seccomp profile alert: %w", err))
			return
		}

		response.Ok(w)
	}
}
