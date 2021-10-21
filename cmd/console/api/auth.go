package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/jwtauth"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/captcha"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/session"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/usercenter"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

const (
	JWTKeyUsername = "user_name"
	JWTKeyUserRole = "user_role"
	JWTExpiration  = time.Hour * 24
)

// LoginResponse is the response of the login API
type LoginResponse struct {
	CurrentAuthority string `json:"currentAuthority"`
	Status           string `json:"status"`
	Type             string `json:"type"`
	Token            string `json:"token"`
	Role             string `json:"role"`
	ChallengeState   string `json:"challengeState"`
}

func (api *api) login() http.HandlerFunc {
	type credentials struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		CaptchaID    string `json:"captchaID"`
		CaptchaValue string `json:"captchavalue"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		creds := &credentials{}
		err := json.NewDecoder(r.Body).Decode(creds)

		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		if creds.Username == "" || creds.Password == "" {
			// Handle case where  username or password are missing
			// We probably should have some validation helper instead of nested
			// ifs like this.
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("missing field 'password' or 'username'"),
					Suberror{"username", ""}, Suberror{"password", ""}))
			return
		}

		captchaService, ok := captcha.GetService()
		if !ok {
			RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		if !captchaService.Verify(creds.CaptchaID, creds.CaptchaValue) {
			RespAndLog(w, ctx,
				NewCaptchaError(http.StatusBadRequest,
					fmt.Errorf("captcha value error")))
			return
		}

		var findUser *model.User
		ok, findUser, err = dal.GetUserByPassword(ctx, api.postgresDB, creds.Username, creds.Password)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("error when checking login credentials in database: %w", err)))
			return
		}
		if !ok {
			limiter := usercenter.GetLimiter(ctx)
			banning := limiter.LoginFailToReachLimit(ctx, creds.Username)
			if banning {
				RespAndLog(w, r.Context(),
					NewAccountBanError(http.StatusPreconditionFailed,
						fmt.Errorf("the account %s is banned", creds.Username)))
				return
			}

			RespAndLog(w, r.Context(),
				LoginError(http.StatusPreconditionFailed,
					fmt.Errorf("user and password not match: %w", err)))
			return
		}

		if findUser.BanStatus == 1 {
			RespAndLog(w, r.Context(),
				NewAccountBanError(http.StatusPreconditionFailed,
					fmt.Errorf("the account %s is banned", creds.Username)))
			return
		}

		tokenString := api.saveJWTToken(creds.Username, findUser.Rule)

		sessionService, ok := session.GetService()
		if !ok {
			RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		if err = sessionService.SaveUserSession(ctx, findUser.GenerateSession(false)); err != nil {
			RespAndLog(w, ctx, fmt.Errorf("save user session fail:%w", err))
			return
		}

		response.Ok(w, response.WithItem(LoginResponse{
			CurrentAuthority: findUser.UserName,
			Status:           "ok",
			Type:             AccountTypeNormal,
			Token:            tokenString,
			Role:             findUser.Rule,
		}))
	}
}

type resp struct {
	Status string `json:"status"`
}

func (api *api) logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		token, claims, err := jwtauth.FromContext(r.Context())
		if err != nil || token == nil || !token.Valid {
			response.Ok(w)
			return
		}

		username := claims[JWTKeyUsername].(string)
		sessionService, ok := session.GetService()
		if !ok {
			RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		if err := sessionService.DeleteUserSession(ctx, username); err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w)
	}
}

func (api *api) activeUser() http.HandlerFunc {

	type reqActiveUser struct {
		HashCode string `json:"hash_code" binding:"required,max=64"`
		Pwd      string `json:"pwd" binding:"required,min=6,max=32"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ru := reqActiveUser{}
		err := json.NewDecoder(r.Body).Decode(&ru)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if ru.HashCode == "" {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("hashcode is not empty")))
			return
		}

		username, ok := dal.CheckHashCode(r.Context(), api.postgresDB, ru.HashCode)
		if !ok {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("hashcode is error")))
			return
		}

		// active user
		err = dal.ActiveUser(r.Context(), api.postgresDB.Get(), username, ru.Pwd)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("database error:%+v", err)))
			return
		}

		response.Ok(w, response.WithItem(resp{
			Status: fmt.Sprintf("%v", "OK"),
		}))
	}
}

func (api *api) forgetPwd() http.HandlerFunc {

	type reqForgetUser struct {
		Username     string `json:"username" binding:"required,max=32"`
		CaptchaID    string `json:"captchaID"`
		CaptchaValue string `json:"captchavalue"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		rf := reqForgetUser{}
		err := json.NewDecoder(r.Body).Decode(&rf)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		captchaService, ok := captcha.GetService()
		if !ok {
			RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		if !captchaService.Verify(rf.CaptchaID, rf.CaptchaValue) {
			RespAndLog(w, ctx,
				NewCaptchaError(http.StatusBadRequest,
					fmt.Errorf("captcha value error")))
			return
		}

		exist, _, err := dal.SelectUser(ctx, api.postgresDB.Get(), rf.Username)
		if err != nil {
			RespAndLog(w, ctx,
				PostgresError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}
		if !exist {
			RespAndLog(w, ctx,
				UserNotExistError(http.StatusBadRequest, fmt.Errorf("user not exist")))
			return
		}

		emailHashCode := dal.RandStringBytesMaskImprSrcUnsafe(64)

		successful := model.SendEmail(rf.Username, r.Host, emailHashCode, api.emailOpts)
		if !successful {
			RespAndLog(w, ctx,
				SendmailError(http.StatusBadRequest, fmt.Errorf("send email error")))
			return
		}

		err = dal.InsertEmail(ctx, api.postgresDB.Get(), rf.Username, emailHashCode)
		if err != nil {
			RespAndLog(w, ctx,
				PostgresError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}

		response.Ok(w, response.WithItem(resp{
			Status: fmt.Sprintf("%v", "OK"),
		}))
	}
}

func (api *api) saveJWTToken(username, role string) string {
	jwtMC := jwt.MapClaims{
		JWTKeyUsername: username,
		JWTKeyUserRole: role,
	}
	jwtauth.SetIssuedNow(jwtMC)
	jwtauth.SetExpiryIn(jwtMC, JWTExpiration)

	_, tokenString, _ := api.tokenAuth.Encode(jwtMC)
	return tokenString
}
