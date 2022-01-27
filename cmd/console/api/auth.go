package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/jwtauth"
	"gopkg.in/gomail.v2"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/captcha"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/session"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/usercenter"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

const (
	JWTKeyUsername = "user_name"
	JWTKeyUserRole = "user_role"
	JWTExpiration  = 12 * time.Hour
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
		ok, findUser, err = dal.GetUserByPassword(ctx, api.rdb, creds.Username, creds.Password)
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

		username, ok := dal.CheckHashCode(r.Context(), api.rdb, ru.HashCode)
		if !ok {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("hashcode is error")))
			return
		}

		// active user
		err = dal.ActiveUser(r.Context(), api.rdb.Get(), username, ru.Pwd)
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

		exist, _, err := dal.SelectUser(ctx, api.rdb.Get(), rf.Username)
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

		successful := SendEmail(rf.Username, r.Host, emailHashCode)
		if !successful {
			RespAndLog(w, ctx,
				SendmailError(http.StatusBadRequest, fmt.Errorf("send email error")))
			return
		}

		err = dal.InsertEmail(ctx, api.rdb.Get(), rf.Username, emailHashCode)
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

func SendMails(mailTo []string, subject string, body string) error {

	mailConn := map[string]string{
		"user": env.GetEmailUsername(),
		"pass": env.GetEmailPassword(),
		"host": env.GetEmailHost(),
		"port": env.GetEmailPort(),
	}

	port, _ := strconv.Atoi(mailConn["port"])

	m := gomail.NewMessage()

	m.SetHeader("From", m.FormatAddress(mailConn["user"],
		env.GetEmailOfficialName()))
	m.SetHeader("To", mailTo...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer(mailConn["host"], port, mailConn["user"], mailConn["pass"])
	tl := tls.Config{InsecureSkipVerify: true}
	d.TLSConfig = &tl

	err := d.DialAndSend(m)
	return err

}

func SendEmail(username, host, emailHashCode string) bool {

	mailBody := "<div\n      style=\"\n  height:560px; \n    width: 752px;\n        min-width: 752px;\n        margin: 0 auto;\n        overflow-x: scroll;\n        position: relative;\n      \"\n    >\n      <div\n        style=\"\n          border-radius: 4px 4px 0 0;\n          border: 1px solid #9bb1c7;\n          border-bottom: 0px;\n          background-color: #ffffff;\n          height: 100%;\n          z-index: 10;\n          margin: 0 30px;\n          padding: 50px 60px 150px;\n          box-sizing: border-box;\n        \"\n      >\n        <div\n          style=\"width: 100%; border-top: 2px solid #d1d8dc; margin: 20px 0\"\n        ></div>\n        <div style=\"width: 100%; padding: 14px 0; box-sizing: border-box\">\n          <span\n            style=\"\n              display: block;\n              font-size: 16px;e\n              font-family: PingFangSC-Medium, PingFang SC;\n              font-weight: 500;\n              color: #333333;\n            \"\n          >\n            " + username + " ,您好！\n          </span>\n          <span\n            style=\"\n              display: block;\n              font-size: 16px;\n              font-family: PingFangSC-Medium, PingFang SC;\n              font-weight: 400;\n              color: #333333;\n              margin-top: 20px;\n              text-indent: 2em;\n            \"\n          >\n            有人请求激活或者重置您的帐户的密码。\n            如果您没有执行此请求，则可以放心地忽略此电子邮件。\n            否则，请单击下面的链接以完成该过程。\n            <a href=\" http://" + host + "/#/email/password/" + emailHashCode + "\"  \"target=\"_blank\">点击此链接</a>\n          </span>\n        </div>\n        <div\n          style=\"width: 100%; border-top: 2px solid #d1d8dc; margin: 20px 0\"\n        ></div>\n        <span\n          style=\"\n            display: block;\n            font-size: 14px;\n            font-family: PingFangSC-Medium, PingFang SC;\n            font-weight: 400;\n            color: #777777;\n          \"\n          >如有任何问题，可以与我们联系，我们将尽快为你解答。\n        </span>\n        <span\n          style=\"\n            display: block;\n            font-size: 14px;\n            font-family: PingFangSC-Medium, PingFang SC;\n            font-weight: 400;\n            color: #777777;\n            margin-top: 4px;\n          \"\n          >Email：" + env.GetContactEmail() + " \n        </span>\n\n      </div>\n      <div style=\"width: 100%; height: 100%; margin-top: -160px\">\n        </div>\n    </div>"
	subject := "Account manager"

	err := SendMails([]string{username}, subject, mailBody)
	if err != nil {
		logging.GetLogger().Error().Msgf("send email error:%+v", err)
		return false
	}

	return true

}
