//go:build !debug

package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/golang-jwt/jwt/v5"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cmcc"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/session"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
	"gitlab.com/piccolo_su/vegeta/pkg/token"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	headerAutoRequest      = "X-Auto-Request"
	autoRequestTypeDefault = "auto"
	autoRequestTypePolling = "polling"
)

// 获取中移磐基系统的用户token
func getCMCCToken(r *http.Request) string {
	bearer := r.Header.Get("ai-jwt-token")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}

	return bearer
}

func verifyCMCC(tokenStr string, r *http.Request) (*token.Payload, error) {
	ctx := r.Context()
	cm, ok := cmcc.GetCMUserService(ctx)
	if !ok {
		return nil, errors.New("ChinaMobile auth not initialed")
	}

	clm := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, &clm, func(t *jwt.Token) (interface{}, error) { return cm.GetCMVerifyKey(), nil })
	if err != nil {
		return nil, err
	}

	user, err := cm.Authenticate(ctx, clm)
	if err != nil {
		return nil, err
	}

	return &token.Payload{
		Username: user.UserName,
		Account:  user.UserName,
		Role:     user.Role,
		Platform: user.Platform,
		ModuleID: user.ModuleID,
		External: true,
		Status:   user.Status,
	}, nil
}

func tokenFromHeader(r *http.Request) string {
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

func tokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie("jwt")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func tokenFromQuery(r *http.Request) string {
	return r.URL.Query().Get("jwt")
}

func findDefaultToken(r *http.Request, findTokenFns ...func(r *http.Request) string) string {
	var tokenStr string

	for _, fn := range findTokenFns {
		tokenStr = fn(r)
		if tokenStr != "" {
			break
		}
	}

	return tokenStr
}

func Authenticator(manager token.Manager, db *databases.RDBInstance) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				ctx     = r.Context()
				reqId   = middleware.GetReqID(ctx)
				payload *token.Payload
				err     error
			)

			// 先获取中移的token
			tokenVal := getCMCCToken(r)
			if tokenVal != "" {
				payload, err = verifyCMCC(tokenVal, r)
				if err != nil {
					apperror.RespAndLog(w, ctx, apperror.NewInvalidAuthToken(http.StatusUnauthorized,
						fmt.Errorf("ctx not found the token: %s", tokenVal)))
					return
				}
			} else {
				// 获取默认的token
				tokenVal = findDefaultToken(r, tokenFromHeader, tokenFromCookie, tokenFromQuery)
				if tokenVal == "" {
					apperror.RespAndLog(w, ctx, apperror.NewInvalidAuthToken(http.StatusUnauthorized,
						fmt.Errorf("ctx not found the token: %s", tokenVal)))
					return
				}

				payload, err = manager.Verify(tokenVal)
				if err != nil {
					logging.Get().Info().Err(err).Str("reqId", reqId).Str("tokenVal", tokenVal).Msg("解析token错误")
					apperror.RespAndLog(w, ctx, apperror.NewInvalidAuthToken(http.StatusUnauthorized, err))
					return
				}
			}

			logging.Get().Debug().Str("reqId", reqId).Any("payload", payload).Msg("token payload")

			if payload.Platform != cmcc.CMUserPlatform {
				sessionService, ok := session.GetService()
				if !ok {
					apperror.RespAndLog(w, ctx, fmt.Errorf("authenticator: service not ready"))
					return
				}

				// check whether the token exists
				tokenStr, err := sessionService.GetToken(ctx, db.Get(), payload.Username)
				if err != nil {
					logging.Get().Warn().Err(err).Str("reqId", reqId).Msgf("redis not found the token: %s", payload.Username)
				}

				if tokenVal != tokenStr {
					logging.Get().Debug().Str("reqId", reqId).Msgf("%s\nfrom: %s\nexits: %s", payload.Username, tokenVal, tokenStr)
					apperror.RespAndLog(w, ctx, apperror.NewInvalidAuthToken(http.StatusUnauthorized,
						fmt.Errorf("token not match")))
					return
				}

				// check user-agent

				if util.MD5Hex(r.UserAgent()) != payload.Eigenvalue {
					if err = sessionService.DeleteToken(ctx, db.Get(), payload.Username); err != nil {
						logging.Get().Warn().Err(err).Str("reqId", reqId).Msgf("user-agent not match: delete token failed")
					}

					logging.Get().Debug().Str("reqId", reqId).
						Msgf("%s %s %s", payload.Username, util.MD5Hex(r.UserAgent()), payload.Eigenvalue)

					apperror.RespAndLog(w, ctx, apperror.NewInvalidAuthToken(http.StatusUnauthorized,
						fmt.Errorf("user-agent not match")))
					return
				}

				// renewal the token
				if h := r.Header.Get(headerAutoRequest); h != autoRequestTypeDefault && h != autoRequestTypePolling {
					go func() {
						// if redis timeout mysql cannot update, via goroutine update redis
						if err = sessionService.RenewalToken(ctx, payload.Username); err != nil {
							logging.Get().Warn().Err(err).Str("reqId", reqId).Msgf("redis renewal the token failed")
						}
					}()

					err = dal.UpdateUserTokenExpireAt(ctx, db.Get(), payload.Username, time.Now().Add(session.DefaultTokenTTL).Unix())
					if err != nil {
						logging.Get().Warn().Err(err).Str("reqId", reqId).Msgf("mysql renewal the token failed")
					}
				}
			}

			ctx = request.WithSession(r.Context(), *payload)
			// Token is authenticated, pass it through
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
