package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/openapiauth"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
)

func (api *api) openapiAuth() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/token", api.newOpenAPIToken())
	}
}

const (
	OpenAPITokenKey    = "Authorization"
	OpenAPIAuthTimeout = time.Second * 3
	OpenAPIVersion     = "v1"
	OpenAPIGuideURLEnv = "OPEN_API_GUIDE_URL"
)

var (
	OpenAPIGuideURL = util.GetEnvWithDefault(OpenAPIGuideURLEnv, "")
)

func (api *api) getOpenAPIToken() http.HandlerFunc {
	type Rsp struct {
		Token    string              `json:"token"`
		Modules  []model.ModuleGroup `json:"modules"`
		GuideURL string              `json:"guideURL"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), OpenAPIAuthTimeout)
		defer cancel()
		user, ok := util.GetSessionFromContext(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, errors.New("unexpected request: no user info"))
			return
		}

		if user.External {
			response.Ok(w, response.WithApiVersion(OpenAPIVersion), response.WithItem(Rsp{GuideURL: OpenAPIGuideURL}))
			return
		}

		token, ok, err := dal.GetUserAuthTokenByUsername(ctx, api.rdb.GetReadDB(), user.Username)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}
		if !ok {
			response.Ok(w, response.WithApiVersion(OpenAPIVersion), response.WithItem(Rsp{GuideURL: OpenAPIGuideURL}))
			return
		}

		modules, err := dal.GetModuleGroup(ctx, api.rdb.GetReadDB(), user.ModuleID)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(OpenAPIVersion), response.WithItem(Rsp{Modules: modules, GuideURL: OpenAPIGuideURL, Token: token.Token}))
	}
}

func (api *api) newOpenAPIToken() http.HandlerFunc {
	type req struct {
		AuthToken string `json:"authToken"`
	}

	type rsp struct {
		Token string `json:"token"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), OpenAPIAuthTimeout)
		defer cancel()
		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		user, ok, err := dal.GetUserByToken(ctx, api.rdb.GetReadDB(), cliReq.AuthToken)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewInvalidAuthToken(http.StatusUnauthorized, fmt.Errorf("invalid auth token")))
			return
		}

		if user.BanStatus == 1 {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewAccountBanError(http.StatusPreconditionFailed,
					fmt.Errorf("the account %s is banned", user.UserName)))
			return
		}

		if !user.Checked {
			apperror.RespAndLog(w, r.Context(),
				apperror.AccountUnActive(http.StatusForbidden,
					fmt.Errorf("account is not activated")))
			return
		}

		service, ok := openapiauth.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, r.Context(), ErrServiceNotReady)
			return
		}

		token, err := service.ObtainToken(ctx, user.UserName)
		if err != nil {
			apperror.RespAndLog(w, r.Context(), err)
			return
		}

		response.Ok(w, response.WithApiVersion(OpenAPIVersion), response.WithItem(rsp{Token: token}))
	}
}

func openAPIAccessCheck(rdb *databases.RDBInstance) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			timeoutCtx, cancel := context.WithTimeout(r.Context(), OpenAPIAuthTimeout)
			defer cancel()
			token := r.Header.Get(OpenAPITokenKey)
			service, ok := openapiauth.GetServiceInstance()
			if !ok {
				apperror.RespAndLog(w, r.Context(), ErrServiceNotReady)
				return
			}

			username, err := service.GetUsernameByToken(timeoutCtx, token)
			if err != nil {
				if err == openapiauth.ErrInvalidToken {
					apperror.RespAndLog(w, r.Context(), apperror.NewInvalidAuthToken(http.StatusUnauthorized, err))
					return
				}

				apperror.RespAndLog(w, r.Context(), fmt.Errorf("GetUsernameByToken fail, err:%w", err))
				return
			}

			exists, user, err := dal.SelectUser(timeoutCtx, rdb.GetReadDB(), username)
			if err != nil {
				apperror.RespAndLog(w, r.Context(), err)
				return
			}

			if !exists {
				apperror.RespAndLog(w, r.Context(), apperror.NewInvalidAuthToken(http.StatusUnauthorized, fmt.Errorf("user:%s not exists", username)))
				return
			}

			if user.BanStatus == 1 {
				apperror.RespAndLog(w, r.Context(),
					apperror.NewAccountBanError(http.StatusPreconditionFailed,
						fmt.Errorf("the account %s is banned", username)))
				return
			}

			if !user.Checked {
				apperror.RespAndLog(w, r.Context(),
					apperror.AccountUnActive(http.StatusForbidden,
						fmt.Errorf("account is not activated")))
				return
			}

			ctx := context.WithValue(r.Context(), util.CtxUserSessionKey, user.GenerateSession(false))
			if r.Method == http.MethodGet {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			accessListUrl, err := dal.GetAccessUrl(rdb.GetReadDB(), user.ModuleID)
			if err != nil {
				apperror.RespAndLog(w, r.Context(),
					apperror.NewMongoError(http.StatusInsufficientStorage,
						fmt.Errorf("select access error: %w", err)))
				return
			}
			hasAccess := false

			currentURL := strings.Replace(strings.ToLower(r.URL.Path), OpenAPIURLPrefix, NormalAPIURLPrefix, 1)
			for i := range accessListUrl {
				url := strings.ToLower(accessListUrl[i])
				if strings.HasPrefix(currentURL, url) {
					hasAccess = true
					break
				}
			}

			if !hasAccess {
				apperror.RespAndLog(w, r.Context(),
					apperror.NewNoAccess(http.StatusForbidden,
						fmt.Errorf("access invalid")))
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
