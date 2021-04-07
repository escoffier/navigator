package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/patrickmn/go-cache"
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
		Pwd string `json:"pwd" binding:"required,max=32"`
	}
	type ResetPwdResponse struct {
		Success bool `json:"success" `
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

		if len(rq.Pwd) > 32 || rq.Pwd == "" {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("pwd error")))
			return
		}

		user := r.Context().Value(userKey).(*model.User)

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		err = model.UpdateUserPwd(api.postgresDB, user.UserName, rq.Pwd)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
			return
		}

		userPtr, ok := api.userCache.Get(user.UserName)
		if !ok {
			testWithLogJson("jwt-jwtAccessCheck()", "user get error")
			RespAndLog(w, r.Context(),
				NewSessionExpired(http.StatusUnauthorized,
					fmt.Errorf("User not in cache")))
			return
		}

		u, _ := userPtr.(*model.User)
		api.userCache.Set(user.UserName, u, cache.DefaultExpiration)

		response.Ok(w, response.WithItem(ResetPwdResponse{
			Success: true,
		}))
	}
}

func (api *api) loadUser() http.HandlerFunc {
	type reqResetPwd struct {
		Pwd string `json:"pwd" binding:"required,max=32"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		u, err := model.GetUserByMongo(ctx, api.mongodb)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
			return
		}
		for _, v := range u {
			bool, _, _ := model.SelectUser(api.postgresDB, v.UserName)
			if !bool {
				err := model.InsertUser(api.postgresDB, v.UserName, model.ROLE_NORMAL, []string{"1"})
				if err != nil {
					RespAndLog(w, ctx,
						PostgresError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
					return
				}

				err = model.ActiveUser(api.postgresDB, v.UserName, v.Pwd)
				if err != nil {
					RespAndLog(w, ctx,
						PostgresError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
					return
				}
			}

		}

		response.Ok(w, response.WithItem(resp{
			Status: "OK",
		}))
	}
}
