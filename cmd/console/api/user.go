package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/patrickmn/go-cache"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/usercenter"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

var (
	ErrNoAccess = errors.New("access invalid")
)

func (api *api) user() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/resetPassword", api.resetPassword())
	}
}

func (api *api) verifyAuthorization(ctx context.Context) error {
	token, claims, err := jwtauth.FromContext(ctx)

	if err != nil {
		return err
	}
	if token == nil || !token.Valid {
		return fmt.Errorf("Token empty or invalid")
	}

	username, _ := claims[JWT_KEY_USERNAME].(string)
	userRole, _ := claims[JWT_KEY_USERROLE].(string)

	userPtr, ok := api.userCache.Get(username)
	if !ok {
		testWithLogJson("jwt-jwtAccessCheck()", "user get error")
		return fmt.Errorf("User not in cache")
	}

	u, _ := userPtr.(*model.User)
	if u.Rule == model.ROLE_NORMAL {
		return ErrNoAccess
	}

	if userRole == model.ROLE_ADMIN || userRole == model.ROLE_SUPERADMIN {
		return nil
	} else {
		return ErrNoAccess
	}
}
func getFromModel(m *model.TensorConfig) (usercenter.LimiterConfig, error) {
	var lc usercenter.LimiterConfig
	if m == nil {
		return lc, nil
	}
	err := json.Unmarshal(m.Config, &lc)
	if err != nil {
		return lc, err
	}
	return lc, nil
}
func (api *api) readConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		config, err := dal.GetConfig(r.Context(), api.postgresDB, usercenter.ConfigKey)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to read posgre: %w", err)))
			return

		}
		c, err := getFromModel(config)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to decode conf: %w", err)))
			return

		}
		response.Ok(w, response.WithItem(c))
	}
}
func (api *api) setConfig() http.HandlerFunc {
	type configStatus struct {
		Success int32 `json:"success"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if authErr := api.verifyAuthorization(r.Context()); authErr != nil {
			RespAndLog(w, r.Context(),
				NewNoAccess(http.StatusForbidden,
					fmt.Errorf("no acess: %w", authErr)))
			return
		}
		rq := usercenter.LimiterConfig{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		configBytes, err := json.Marshal(&rq)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusInternalServerError,
					fmt.Errorf("failed to encode json: %w", err)))
			return
		}
		err = dal.SetConfig(r.Context(), api.postgresDB, usercenter.ConfigKey, configBytes)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to write posgre: %w", err)))
			return
		}
		usercenter.GetLimiter(r.Context()).UpdateThreshold(rq.RateLimitThreshold)
		usercenter.GetLimiter(r.Context()).UpdateTimeWindow(rq.RateLimitWindowSecs)
		usercenter.GetLimiter(r.Context()).UpdateEnable(rq.RateLimitEnable)
		response.Ok(w, response.WithItem(configStatus{
			Success: 1,
		}))
	}
}

func (api *api) userBan() http.HandlerFunc {
	type banReq struct {
		User string `json:"user"`
	}
	type BanStatus struct {
		BanStatus int32 `json:"banStatus"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if authErr := api.verifyAuthorization(r.Context()); authErr != nil {
			RespAndLog(w, r.Context(),
				NewNoAccess(http.StatusForbidden,
					fmt.Errorf("no acess: %w", authErr)))
			return
		}

		rq := banReq{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		err = dal.SetAccountBanStatus(r.Context(), api.postgresDB, rq.User, true)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to update posgre: %w", err)))
			return
		}
		response.Ok(w, response.WithItem(BanStatus{BanStatus: 1}))
	}
}
func (api *api) userUnban() http.HandlerFunc {
	type unbanReq struct {
		User string `json:"user"`
	}
	type BanStatus struct {
		BanStatus int32 `json:"banStatus"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		rq := unbanReq{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if authErr := api.verifyAuthorization(r.Context()); authErr != nil {
			RespAndLog(w, r.Context(),
				NewNoAccess(http.StatusForbidden,
					fmt.Errorf("no acess: %w", authErr)))
			return
		}
		err = dal.SetAccountBanStatus(r.Context(), api.postgresDB, rq.User, false)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to update posgre: %w", err)))
			return
		}
		response.Ok(w, response.WithItem(BanStatus{BanStatus: 0}))
	}
}

func checkPwdFormat(pwd string) (matched bool, err error) {
	if len(pwd) < 8 {
		return false, fmt.Errorf("password len < 8")
	}
	if m, err := regexp.MatchString("0-9]+", pwd); !m || err != nil {
		return m, fmt.Errorf("0-9")
	}
	if m, err := regexp.MatchString("[a-z]+", pwd); !m || err != nil {
		return m, fmt.Errorf("a-z")
	}
	if m, err := regexp.MatchString("[A-Z]+", pwd); !m || err != nil {
		return m, fmt.Errorf("A-Z")
	}
	if m, err := regexp.MatchString("[~!@#$%^&*\\.]+", pwd); !m || err != nil {
		return m, fmt.Errorf("A-Z")
	}
	return true, nil
}

func (api *api) resetPassword() http.HandlerFunc {
	type reqResetPwd struct {
		OldPwd string `json:"oldpwd"`
		Pwd    string `json:"pwd" binding:"required,max=32"`
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

		if rq.OldPwd == "" || len(rq.Pwd) > 16 || len(rq.Pwd) < 8 || rq.Pwd == "" {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("pwd error")))
			return
		}

		// checked, err := checkPwdFormat(rq.Pwd)
		// if !checked {
		// 	RespAndLog(w, r.Context(),
		// 		NewMalformedRequestError(http.StatusBadRequest, err))
		// 	return
		// }

		user := r.Context().Value(userKey).(*model.User)

		if dal.GetSaltedPwd(rq.OldPwd, user.Salt) != user.Pwd {
			RespAndLog(w, r.Context(),
				NewPasswordNotMatchError(http.StatusBadRequest,
					fmt.Errorf("oldpwd error")))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		err = dal.UpdateUserPwd(ctx, api.postgresDB, user.UserName, rq.Pwd)
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

		u, err := dal.GetUserByMongo(ctx, api.mongodb.Get())
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
			return
		}
		for _, v := range u {
			bool, _, _ := dal.SelectUser(ctx, api.postgresDB, v.UserName)
			if !bool {
				err := dal.InsertUser(ctx, api.postgresDB, v.UserName, model.ROLE_NORMAL, []string{"1"})
				if err != nil {
					RespAndLog(w, ctx,
						PostgresError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
					return
				}

				err = dal.ActiveUser(ctx, api.postgresDB, v.UserName, v.Pwd)
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
