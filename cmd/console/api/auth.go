package api

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/jwtauth"
	param "github.com/oceanicdev/chi-param"
	"gopkg.in/gomail.v2"
	"gorm.io/gorm"

	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/captcha"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/idp"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/license"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/session"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/user"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/usercenter"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type getLoginSecretResp struct {
	Key string `json:"key"`
	// Seed   string
}

func (api *api) getLoginSecret() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		username := r.URL.Query().Get("seed")
		if username == "" {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("missing params 'seed'")))
			return
		}

		exist, _, err := dal.SelectUser(ctx, api.rdb.Get(), username)
		if !exist || err != nil {
			RespAndLog(w, ctx, UserNotExistError(http.StatusBadRequest,
				fmt.Errorf("user not found %w", err)))
			return
		}

		// generate AES key and save to redis
		aesKey := dal.RandStringBytesMaskImprSrcUnsafe(16)
		sessionService, ok := session.GetService()
		if !ok {
			RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		if err = sessionService.SaveUserLoginSecret(ctx, username, aesKey); err != nil {
			logging.Get().Warn().Err(err).Msg("save login secret fail")
		}

		// save to mysql
		if err = dal.UpdateUserLoginKey(ctx, api.rdb.Get(), username, aesKey, time.Now().Add(time.Minute).Unix()); err != nil {
			RespAndLog(w, ctx, fmt.Errorf("save login secret fail:%w", err))
			return
		}

		response.Ok(w, response.WithItem(getLoginSecretResp{Key: aesKey}))
	}
}

func (api *api) loginBodyDecrypt(ctx context.Context, r io.ReadCloser) ([]byte, error) {
	body, err := ioutil.ReadAll(r)
	defer r.Close()
	if err != nil {
		return nil, err
	}

	params := strings.Split(string(body), "##")
	if len(params) != 2 || params[0] == "" || params[1] == "" {
		return nil, fmt.Errorf("parameter numbers error")
	}

	sessionService, ok := session.GetService()
	if !ok {
		return nil, ErrServiceNotReady
	}

	key, err := sessionService.GetUserLoginSecret(ctx, api.rdb.Get(), params[0])
	if err != nil {
		return nil, fmt.Errorf("get redis data err %w", err)
	}

	encrypted, err := base64.StdEncoding.DecodeString(params[1])
	if err != nil {
		return nil, err
	}

	decrypted, err := util.AesDecryptCBC(encrypted, []byte(key))
	if err != nil {
		logging.Get().Error().Msgf("decrypt ase data err: %v\n%s", params, key)
		return nil, err
	}

	return decrypted, nil
}

// LoginResponse is the response of the login API
type LoginResponse struct {
	CurrentAuthority  string         `json:"currentAuthority"`
	Status            string         `json:"status"`
	Type              string         `json:"type"`
	Token             string         `json:"token"`
	Role              string         `json:"role"`
	Platform          string         `json:"platform"`
	ChallengeState    string         `json:"challengeState"`
	LicenseStatus     license.Status `json:"licenseStatus"`
	CycleChangePwdDay int            `json:"cycleChangePwdDay"`
	MustChangePwd     bool           `json:"mustChangePwd"`
	ChangePwdHashCode string         `json:"changePwdHashCode"`
}

type DXLoginResponse struct {
	LoginResponse
	IDToken string `json:"IDToken"`
}

func (api *api) login() http.HandlerFunc {
	type credentials struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		CaptchaID    string `json:"captchaID"`
		CaptchaValue string `json:"captchavalue"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		decrypted, err := api.loginBodyDecrypt(ctx, r.Body)
		if err != nil {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("illeagal params: %w", err)))
			return
		}

		creds := &credentials{}
		if err = json.Unmarshal(decrypted, creds); err != nil {
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
					Suberror{Location: "username", Message: ""}, Suberror{Location: "password", Message: ""}))
			return
		}

		captchaService, ok := captcha.GetService()
		if !ok {
			RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		if captchaService.IsBreakerClosed() &&
			!captchaService.Verify(creds.CaptchaID, creds.CaptchaValue) {
			RespAndLog(w, ctx,
				NewCaptchaError(http.StatusBadRequest,
					fmt.Errorf("captcha value error")))
			return
		}

		passwordOk, findUser, err := dal.GetUserByPassword(ctx, api.rdb.GetReadDB(), creds.Username, creds.Password)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("error when checking login credentials in database: %w", err)))
			return
		}
		userRole := ""
		if !passwordOk {
			// 用username查询user
			nameOk, userByName, err := dal.SelectUser(ctx, api.rdb.GetReadDB(), creds.Username)
			if err != nil {
				RespAndLog(w, r.Context(),
					LoginError(http.StatusInternalServerError,
						fmt.Errorf("error when checking login credentials in database: %w", err)))
				return
			}
			if !nameOk {
				RespAndLog(w, r.Context(),
					LoginError(http.StatusInternalServerError,
						fmt.Errorf("invalid user name")))
				return
			}
			userRole = userByName.Role
		} else {
			userRole = findUser.Role
		}
		cycleChangePwdDay := 0
		// super-admin 只返回密码不对
		if userRole == model.RoleSuperAdmin {
			if !passwordOk {
				RespAndLog(w, r.Context(),
					LoginError(http.StatusPreconditionFailed,
						fmt.Errorf("user and password not match")))
				return
			}
		} else { // 非super-admin的检查逻辑
			loginConf, err := getLoginConf(ctx, api.rdb)
			if err != nil {
				RespAndLog(w, r.Context(),
					LoginError(http.StatusInternalServerError,
						fmt.Errorf("query login conf fails")))
				return
			}
			// 多次输错密码检查
			limiter := usercenter.GetLimiter(ctx)
			if !passwordOk {
				if loginConf.RateLimitEnable {
					locking := limiter.LoginFailToReachLimit(ctx, creds.Username)
					if locking {
						RespAndLog(w, r.Context(),
							NewAccountLockError(http.StatusPreconditionFailed,
								fmt.Errorf("the account %s is banned", creds.Username)))
						return
					}
				}
				RespAndLog(w, r.Context(),
					LoginError(http.StatusPreconditionFailed,
						fmt.Errorf("user and password not match")))
				return
			}
			limiter.LoginSuccessClean(findUser.UserName)

			// 周期修改密码检查
			// 获取周期修改密码时间
			if loginConf.CycleChangePwd {
				cycleChangePwdDay, err = getCycleChangePwdDay(ctx, api.rdb, loginConf, findUser)
				if err != nil {
					RespAndLog(w, ctx, err)
					return
				}
			}

			// 账户状态检查
			if err = checkUserStatus(findUser.UserName, findUser.Status); err != nil {
				RespAndLog(w, ctx, err)
				return
			}

			// 是否需要立即修改密码（首次登录）
			if findUser.MustChangePwd {
				emailHashCode := dal.RandStringBytesMaskImprSrcUnsafe(64)
				innerErr := dal.InsertEmail(ctx, api.rdb.Get(), findUser.UserName, emailHashCode)
				if innerErr != nil {
					RespAndLog(w, ctx, innerErr)
					return
				}
				response.Ok(w, response.WithItem(LoginResponse{
					CurrentAuthority:  findUser.UserName,
					Role:              findUser.Role,
					CycleChangePwdDay: cycleChangePwdDay,
					MustChangePwd:     true,
					ChangePwdHashCode: emailHashCode,
				}))
				return
			}
		}

		// issue JWT Token
		tokenString, err := api.issueJWTToken(ctx, findUser.UserName, findUser.Role, r.UserAgent(), false)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("issue jwt token failed %w", err)))
			return
		}

		sessionService, ok := session.GetService()
		if !ok {
			RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		if err = sessionService.SaveUserSession(ctx, findUser.GenerateSession(false)); err != nil {
			logging.Get().Warn().Err(err).Msgf("login save user session fail")
		}

		response.Ok(w, response.WithItem(LoginResponse{
			CurrentAuthority:  findUser.UserName,
			Status:            "ok",
			Type:              AccountTypeNormal,
			Token:             tokenString,
			Role:              findUser.Role,
			Platform:          findUser.Platform,
			LicenseStatus:     license.ValidateLicense(false),
			CycleChangePwdDay: cycleChangePwdDay,
		}), response.WithTarget(&response.TargetRef{
			Name: creds.Username,
			ID:   "",
			Link: "",
		}))
	}
}

func getLoginConf(ctx context.Context, rdb *databases.RDBInstance) (loginConfigInfo, error) {
	loginConf := loginConfigInfo{}
	dbConf, err := dal.GetConfig(ctx, rdb.GetReadDB(), model.ConfLogin)
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return loginConf, err
		}
	} else {
		if err = json.Unmarshal(dbConf.Config, &loginConf); err != nil {
			return loginConf, err
		}
	}
	return loginConf, nil
}

func getCycleChangePwdDay(ctx context.Context, rdb *databases.RDBInstance, loginConf loginConfigInfo, findUser *model.User) (int, error) {
	seconds := time.Now().Sub(time.UnixMilli(findUser.LastChangePwdAt)).Seconds()
	if int(seconds) > loginConf.CycleDay*86400 {
		// 锁定账号
		findUser.Status = model.UserStatusLock
		err := dal.UpdateUserStatus(ctx, rdb.Get(), findUser.UserName, findUser.Status)
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			return 0, err
		}
	} else {
		return loginConf.CycleDay - int(seconds/86400), nil
	}
	return 0, nil
}

func (api *api) getIdpLoginUrl() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		platform := r.URL.Query().Get("platform")
		if platform == "" {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("missing params 'platform'")))
			return
		}

		p, err := idp.GetProvider(platform)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("platform unsupport %w", err)))
			return
		}
		if !p.Enabled() {
			RespAndLog(w, r.Context(),
				NewSSONotEnabledError(http.StatusBadRequest,
					fmt.Errorf("platform not enable")))
			return
		}

		url, err := p.GetAuthUrl()
		if err != nil {
			RespAndLog(w, r.Context(),
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("p.GetAuthUrl error %w", err)))
			return
		}

		response.Ok(w, response.WithItem(map[string]string{"url": url}))
	}
}

func (api *api) idpLogin() http.HandlerFunc {
	type idpLoginReq struct {
		Platform string          `json:"platform"`
		Payload  json.RawMessage `json:"payload"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		req := idpLoginReq{}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if req.Platform == "" {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("missing field 'platform' or 'username'")))
			return
		}

		p, err := idp.GetProvider(req.Platform)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("platform unsupport")))
			return
		}
		if !p.Enabled() {
			RespAndLog(w, r.Context(),
				NewSSONotEnabledError(http.StatusBadRequest,
					fmt.Errorf("platform not enable")))
			return
		}

		idpInfo, err := p.GetUserInfo(ctx, req.Payload)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewAnError(http.StatusInternalServerError, fmt.Errorf("p.GetUserInfo error %w", err)))
			return
		}

		user := &model.User{}
		err = api.rdb.GetReadDB().Where("username = ?", idpInfo.Username).First(user).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			RespAndLog(w, r.Context(),
				NewAnError(http.StatusInternalServerError, fmt.Errorf("db query error: %w", err)))
			return
		}

		// 新用户第一次登录
		if err == gorm.ErrRecordNotFound || user.Platform != req.Platform {
			// 如果有重复的账号，追加一个prefix
			prefix := err == nil && user.Platform != req.Platform
			user, err = createUserByIdp(ctx, api.rdb, req.Platform, idpInfo, prefix)
			if err != nil {
				RespAndLog(w, r.Context(), err)
				return
			}
		}

		// 判定账号是否被停用
		if err = checkUserStatus(user.UserName, user.Status); err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		// issue JWT Token
		tokenString, err := api.issueJWTToken(ctx, user.UserName, user.Role, r.UserAgent(), false)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("issue jwt token failed %w", err)))
			return
		}

		sessionService, ok := session.GetService()
		if !ok {
			RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		if err = sessionService.SaveUserSession(ctx, user.GenerateSession(false)); err != nil {
			logging.Get().Warn().Err(err).Msgf("login save user session fail")
		}

		response.Ok(w, response.WithItem(DXLoginResponse{
			LoginResponse: LoginResponse{
				CurrentAuthority: user.UserName,
				Status:           "ok",
				Type:             AccountTypeNormal,
				Token:            tokenString,
				Role:             user.Role,
				Platform:         user.Platform,
				LicenseStatus:    license.ValidateLicense(false),
			},
			IDToken: idpInfo.IDToken,
		}), response.WithTarget(&response.TargetRef{
			Name: user.UserName,
			ID:   "",
			Link: "",
		}))
	}
}

func createUserByIdp(ctx context.Context, rdb *databases.RDBInstance, platform string, thirdInfo *idp.IdpUserInfo, prefix bool) (*model.User, error) {
	conf, err := dal.GetConfig(ctx, rdb.GetReadDB(), model.ConfIdpLogin)
	if err != nil {
		return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("db query error: %w", err))
	}

	idpConf := idp.LoginConfig{}
	if err = json.Unmarshal(conf.Config, &idpConf); err != nil {
		return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("json unmarshal error: %w", err))
	}

	// 默认权限
	moduleIDs := make([]string, 0)
	for _, auth := range idpConf.DefaultAuth {
		moduleIDs = append(moduleIDs, strconv.Itoa(auth.Id))
	}
	if thirdInfo.Role != "" {
		moduleSet := map[int]string{}
		for _, permission := range idpConf.PermissionMapping {
			if permission.RoleName != thirdInfo.Role {
				continue
			}

			for _, auth := range permission.Auth {
				moduleSet[auth.Id] = strconv.Itoa(auth.Id)
			}
		}

		if len(moduleSet) > 0 {
			moduleIDs = make([]string, 0)
			for _, v := range moduleSet {
				moduleIDs = append(moduleIDs, v)
			}
		}
	}
	moduleID, _ := json.Marshal(moduleIDs)

	username := thirdInfo.Username
	if prefix {
		username = string(platform) + "." + username
	}

	// 默认生成一个账号
	u := model.User{
		UserName:  username,
		Role:      model.RoleNormal,
		ModuleID:  string(moduleID),
		Platform:  platform,
		CreatedAt: time.Now().UnixMilli(),
		Status:    model.UserStatusNormal,
		Token:     util.GenerateUUIDHex(),
	}

	if err = rdb.Get().WithContext(ctx).Create(&u).Error; err != nil {
		return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("create a new accpount error from idp: %w", err))
	}

	return &u, nil
}

func checkUserStatus(username string, status int) error {
	return nil
	if username == model.UserSuperAdmin {
		return nil
	}
	if status == model.UserStatusInactive {
		return AccountUnActive(http.StatusForbidden,
			fmt.Errorf("account is not activated"))
	} else if status == model.UserStatusLock {
		return NewAccountLockError(http.StatusPreconditionFailed,
			fmt.Errorf("the account %s is locked", username))
	} else if status != model.UserStatusNormal {
		return NewAccountBanError(http.StatusPreconditionFailed,
			fmt.Errorf("the account %s is banned", username))
	}

	return nil
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

		if err = sessionService.DeleteUserSession(ctx, username); err != nil {
			logging.Get().Warn().Err(err)
		}

		if err = sessionService.DeleteToken(ctx, api.rdb.Get(), username); err != nil {
			logging.Get().Warn().Err(err)
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

		username, ok := dal.CheckHashCode(r.Context(), api.rdb.Get(), ru.HashCode)
		if !ok {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("hashcode is error")))
			return
		}

		// active user
		user, err := dal.ActiveUser(r.Context(), api.rdb.Get(), username, ru.Pwd, false)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("database error:%+v", err)))
			return
		}

		// issue JWT Token
		tokenString, err := api.issueJWTToken(r.Context(), user.UserName, user.Role, r.UserAgent(), false)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("issue jwt token failed %w", err)))
			return
		}

		sessionService, ok := session.GetService()
		if !ok {
			RespAndLog(w, r.Context(), ErrServiceNotReady)
			return
		}

		if err = sessionService.SaveUserSession(r.Context(), user.GenerateSession(false)); err != nil {
			logging.Get().Warn().Err(err).Msgf("login save user session fail")
		}

		// 获取周期修改密码时间
		loginConf, err := getLoginConf(r.Context(), api.rdb)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("query login conf fails")))
			return
		}
		cycleChangePwdDay := 0
		if loginConf.CycleChangePwd {
			cycleChangePwdDay, err = getCycleChangePwdDay(r.Context(), api.rdb, loginConf, user)
			if err != nil {
				RespAndLog(w, r.Context(), err)
				return
			}
		}

		response.Ok(w, response.WithItem(LoginResponse{
			CurrentAuthority:  user.UserName,
			Status:            "ok",
			Type:              AccountTypeNormal,
			Token:             tokenString,
			Role:              user.Role,
			Platform:          user.Platform,
			LicenseStatus:     license.ValidateLicense(false),
			CycleChangePwdDay: cycleChangePwdDay,
		}), response.WithTarget(&response.TargetRef{
			Name: user.UserName,
			ID:   "",
			Link: "",
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
				RDBError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
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
				RDBError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}

		response.Ok(w, response.WithItem(resp{
			Status: fmt.Sprintf("%v", "OK"),
		}))
	}
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
		logging.Get().Error().Msgf("send email error:%+v", err)
		return false
	}

	return true

}

// -----jwt-----
const (
	JWTKeyUsername   = "user_name"
	JWTKeyUserRole   = "user_role"
	JWTKeyExternal   = "external"
	JWTKeyEigenvalue = "eigenvalue"

	accessCheckTimeout = time.Second * 3
)

func (api *api) issueJWTToken(ctx context.Context, username, role, userAgent string, external bool) (string, error) {
	jwtMC := jwt.MapClaims{
		JWTKeyUsername:   username,
		JWTKeyUserRole:   role,
		JWTKeyExternal:   external,
		JWTKeyEigenvalue: util.MD5Hex(userAgent),
	}
	jwtauth.SetIssuedNow(jwtMC)
	jwtauth.SetExpiryIn(jwtMC, time.Hour*24)

	_, tokenString, err := api.tokenAuth.Encode(jwtMC)
	if err != nil {
		logging.Get().Error().Err(err)
		return "", err
	}

	// save token to redis
	sessionService, ok := session.GetService()
	if !ok {
		return "", ErrServiceNotReady
	}

	if err = sessionService.SaveToken(ctx, username, tokenString); err != nil {
		logging.Get().Warn().Err(err).Msgf("redis: save user token fail")
	}

	// save to mysql
	err = dal.UpdateUserToken(ctx, api.rdb.Get(), username, tokenString, time.Now().Add(session.DefaultTokenTTL).Unix())
	if err != nil {
		return "", fmt.Errorf("save user token fail:%w", err)
	}

	logging.Get().Debug().Msgf("login token issue: %s %s %t", username, tokenString, external)
	return tokenString, nil
}

func authenticator(db *databases.RDBInstance) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), accessCheckTimeout)
			defer cancel()

			if skipNormalAuth(ctx) {
				next.ServeHTTP(w, r)
				return
			}

			token, claims, err := jwtauth.FromContext(ctx)
			if err != nil {
				RespAndLog(w, ctx, NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("ctx not found the token: %w", err)))
				return
			}

			if token == nil || !token.Valid {
				RespAndLog(w, ctx, NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("token invalid")))
				return
			}

			var username string
			if v, ok := claims[JWTKeyUsername]; ok {
				username = v.(string)
			}

			if username == "" {
				RespAndLog(w, ctx, NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("username is empty. not found the token")))
				return
			}

			sessionService, ok := session.GetService()
			if !ok {
				RespAndLog(w, ctx, ErrServiceNotReady)
				return
			}

			// check whether the token exists
			tokenStr, err := sessionService.GetToken(ctx, db.Get(), username)
			if err != nil {
				logging.Get().Warn().Err(err).Msgf("redis not found the token: %s", username)
			}

			if token.Raw != tokenStr {
				logging.Get().Debug().Msgf("%s\n%s\n%s", username, token.Raw, tokenStr)
				RespAndLog(w, ctx, NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("token not match")))
				return
			}

			// check user-agent
			var eigenvalue string
			if v, ok := claims[JWTKeyEigenvalue]; ok {
				eigenvalue = v.(string)
			}

			if util.MD5Hex(r.UserAgent()) != eigenvalue {
				if err = sessionService.DeleteToken(ctx, db.Get(), username); err != nil {
					logging.Get().Warn().Err(err).Msgf("user-agent not match: delete token failed")
				}

				logging.Get().Debug().Msgf("%s %s %s", username, util.MD5Hex(r.UserAgent()), eigenvalue)
				RespAndLog(w, ctx, NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("user-agent not match")))
				return
			}

			// renewal the token
			if h := r.Header.Get(headerAutoRequest); h != autoRequestTypeDefault && h != autoRequestTypePolling {
				go func() {
					// if redis timeout mysql cannot update, via goroutine update redis
					if err = sessionService.RenewalToken(ctx, username); err != nil {
						logging.Get().Warn().Err(err).Msgf("redis renewal the token failed")
					}
				}()

				err = dal.UpdateUserTokenExpireAt(ctx, db.Get(), username, time.Now().Add(session.DefaultTokenTTL).Unix())
				if err != nil {
					logging.Get().Warn().Err(err).Msgf("mysql renewal the token failed")
				}
			}

			// Token is authenticated, pass it through
			next.ServeHTTP(w, r)
		})
	}
}

func jwtAccessCheck(db *databases.RDBInstance) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), accessCheckTimeout)
			defer cancel()

			if skipNormalAuth(ctx) {
				next.ServeHTTP(w, r)
				return
			}

			token, claims, err := jwtauth.FromContext(ctx)
			if err != nil {
				RespAndLog(w, ctx,
					NewInvalidAuthToken(http.StatusUnauthorized,
						fmt.Errorf("error when getting token & claims from context: %w", err)))
				return
			}
			if token == nil || !token.Valid {
				RespAndLog(w, ctx,
					NewInvalidAuthToken(http.StatusUnauthorized,
						fmt.Errorf("token empty or invalid")))
				return
			}

			username, _ := claims[JWTKeyUsername].(string)
			external, _ := claims[JWTKeyExternal].(bool)
			sessionService, ok := session.GetService()
			if !ok {
				RespAndLog(w, ctx, ErrServiceNotReady)
				return
			}

			userSession, err := sessionService.GetUserSession(ctx, db.GetReadDB(), username, external)
			if err != nil {
				if err == session.ErrNotFound {
					RespAndLog(w, r.Context(),
						NewSessionExpired(http.StatusUnauthorized,
							fmt.Errorf("user not in cache")))
					return
				}

				RespAndLog(w, ctx, err)
				return
			}

			if err = sessionService.RefreshUserSession(ctx, username); err != nil {
				logging.Get().Err(err).Msgf("refresh session fail")
			}

			if err = checkUserStatus(username, userSession.Status); err != nil {
				RespAndLog(w, r.Context(), err)
				return
			}

			ctx = context.WithValue(r.Context(), model.CtxUserSessionKey, userSession)
			if r.Method == http.MethodGet ||
				r.URL.Path == "/api/v2/platform/sherlock/palace/events" ||
				r.URL.Path == "/api/v2/platform/sherlock/palace/signals" ||
				r.URL.Path == "/api/v2/platform/sherlock/palace/event/stats" ||
				r.URL.Path == "/api/v2/platform/sherlock/hola/rules" ||
				r.URL.Path == "/api/v2/platform/nodeImage/images/list" ||
				r.URL.Path == "/api/v2/containerSec/scanner/images/list" ||
				r.URL.Path == "/api/v2/containerSec/scanner/images/detail/riskInfo" ||
				r.URL.Path == "/api/v2/platform/sherlock/palace/attck/matrix" {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			accessListUrl, err := dal.GetAccessUrl(db.GetReadDB(), userSession.ModuleID)
			if err != nil {
				RespAndLog(w, r.Context(), fmt.Errorf("select access error: %w", err))
				return
			}
			hasAccess := false

			currentURL := strings.ToLower(r.URL.Path)
			for i := range accessListUrl {
				url := strings.ToLower(accessListUrl[i])
				if strings.HasPrefix(currentURL, url) {
					hasAccess = true
					break
				}
			}

			if !hasAccess {
				RespAndLog(w, r.Context(),
					NewNoAccess(http.StatusForbidden,
						fmt.Errorf("access invalid")))
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func downloadAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
			defer cancel()
			token, _ := param.QueryString(r, "jwt")
			if token == "" {
				RespAndLog(w, ctx,
					NoTokenError(http.StatusBadRequest,
						fmt.Errorf("no token")))
				return
			}
			// 验证token是否已失效
			jt := util.NewJWT(r.URL.Path)
			if !jt.ValidateToken(token) {
				RespAndLog(w, ctx, InvalidTokenError(http.StatusBadRequest, fmt.Errorf("token invalid or expired")))
				return
			}

			// 解密
			jwtToken, err := jt.DecodeJwtToken(token)
			if err != nil {
				RespAndLog(w, ctx, InvalidTokenError(http.StatusBadRequest, fmt.Errorf("token invalid or expired")))
				return
			}
			decodeString, err := hex.DecodeString(jwtToken.Subject)
			if err != nil {
				RespAndLog(w, ctx, InvalidTokenError(http.StatusBadRequest, fmt.Errorf("token invalid or expired")))
				return
			}
			decrypted, err := util.AesDecryptCBC(decodeString, []byte(util.DownloadFileKey))
			if err != nil || string(decrypted) != r.URL.Path {
				RespAndLog(w, ctx, InvalidTokenError(http.StatusBadRequest, fmt.Errorf("token invalid or expired")))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func verifier(ja *jwtauth.JWTAuth) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				ctx context.Context
				err error
			)
			cmToken := getCMToken(r)

			if cmToken == "" {
				ctx, err = verify(ja, r)
			} else {
				ctx, err = verifyCM(cmToken, r)
			}

			if err != nil {
				RespAndLog(w, ctx, NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("ctx not found the token: %w", err)))
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

var (
	tokenCtxKey          struct{}
	skipNormalAuthCtxKey struct{}
)

type tokenCtxValue struct {
	// token签发平台
	IssuePlatform string
	// token
	Token *jwt.Token
}

// normal way
func verify(ja *jwtauth.JWTAuth, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	token, err := jwtauth.VerifyRequest(ja, r, jwtauth.TokenFromHeader, jwtauth.TokenFromCookie, jwtauth.TokenFromQuery)
	if err != nil {
		return ctx, err
	}
	ctx = jwtauth.NewContext(ctx, token, err)

	ctx = context.WithValue(ctx, &tokenCtxKey, &tokenCtxValue{IssuePlatform: "TensorSecurity", Token: token})

	return ctx, nil
}

func verifyCM(tokenStr string, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	ja, ok := user.GetCMUserAuth(context.Background())
	if !ok {
		return ctx, errors.New("ChinaMobile auth not initialated")
	}

	token, err := jwtauth.VerifyRequest(ja, r, getCMToken)
	if err != nil {
		return ctx, err
	}

	ctx = context.WithValue(ctx, &tokenCtxKey, &tokenCtxValue{IssuePlatform: "ChinaMobile", Token: token})

	return ctx, nil
}

// 获取中移磐基系统的用户token
func getCMToken(r *http.Request) string {
	token := r.Header.Get("ai-jwt-token")
	if len(token) > 7 && strings.ToUpper(token[0:6]) == "BEARER" {
		return token[7:]
	}
	return token
}

func shouldUseCM(ctx context.Context) bool {
	value, ok := ctx.Value(&tokenCtxKey).(*tokenCtxValue)
	if !ok {
		return false
	}

	if value != nil && value.IssuePlatform == "ChinaMobile" {
		return true
	}
	return false
}

func skipNormalAuth(ctx context.Context) bool {
	skip, ok := ctx.Value(skipNormalAuthCtxKey).(bool)
	if !ok {
		return false
	}

	return skip
}

// 旁路验证
func bypassAuthenticator(rdb *databases.RDBInstance) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), accessCheckTimeout)
			defer cancel()

			if shouldUseCM(ctx) {
				cm, ok := user.GetCMUserService(ctx)

				if !ok {
					RespAndLog(w, ctx, NewInvalidAuthToken(http.StatusInternalServerError, errors.New("ChinaMobile service not initialized")))
					return
				}

				tokenValue, ok := ctx.Value(&tokenCtxKey).(*tokenCtxValue)

				if !ok {
					RespAndLog(w, ctx, NewInvalidAuthToken(http.StatusUnauthorized, errors.New("ChinaMobile token not found")))
					return
				}

				cmUser, err := cm.Authenticate(ctx, tokenValue.Token)
				if err != nil {
					RespAndLog(w, ctx, NewInvalidAuthToken(http.StatusUnauthorized, fmt.Errorf("authorized failed: %v", err)))
					return
				}

				// set skip the normal way
				newCtx := context.WithValue(ctx, skipNormalAuthCtxKey, true)

				// save user info to ctx
				userSession := &model.UserSession{
					Username: cmUser.UserName,
					Role:     cmUser.Role,
					ModuleID: cmUser.ModuleID,
					Status:   cmUser.Status,
					External: true,
				}
				newCtx = context.WithValue(newCtx, model.CtxUserSessionKey, userSession)

				r = r.WithContext(newCtx)
			}

			next.ServeHTTP(w, r)
		})
	}
}
