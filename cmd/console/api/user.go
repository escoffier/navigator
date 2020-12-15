package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) user() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/resetPassword", api.resetPassword())
	}
}

func (api *api) resetPassword() http.HandlerFunc {
	type reqResetPwd struct {
		Pwd string `json:"pwd"`
	}
	type ResetPwdResponse struct {
		Success bool `json:"success"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		rq := reqResetPwd{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		user := r.Context().Value(userKey).(*model.User)

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		_, err = model.UpdateUserPwd(ctx, api.mongodb, user.UserName, rq.Pwd)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
			return
		}

		response.Ok(w, response.WithItem(ResetPwdResponse{
			Success: true,
		}))
	}
}
