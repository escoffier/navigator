package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/time/rate"

	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
	"gitlab.com/piccolo_su/vegeta/pkg/token"
	"gopkg.in/gomail.v2"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/captcha"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/idp"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/license"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/session"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/usercenter"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
)

type getLoginSecretResp struct {
	Key string `json:"key"`
	// Seed   string
}

func (api *api) getLoginSecret() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		account := r.URL.Query().Get("seed")
		if account == "" {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("missing params 'seed'")))
			return
		}

		aesKey := dal.RandStringBytesMaskImprSrcUnsafe(16)

		exist, _, err := dal.SelectUserByAccount(ctx, api.rdb.Get(), account)
		if err != nil {
			RespAndLog(w, ctx, LoginError(http.StatusBadRequest,
				fmt.Errorf("user not found %w", err)))
			return
		}

		sessionService, ok := session.GetService()
		if !ok {
			RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		if err = sessionService.SaveUserLoginSecret(ctx, account, aesKey); err != nil {
			logging.Get().Warn().Err(err).Msg("save login secret fail")
		}

		// 如果用户不存在也直接返回key
		// 防止前端利用error遍历用户名
		if exist {
			// save to mysql
			if err = dal.UpdateUserLoginKey(ctx, api.rdb.Get(), account, aesKey, time.Now().Add(time.Minute).Unix()); err != nil {
				RespAndLog(w, ctx, fmt.Errorf("save login secret fail:%w", err))
				return
			}
		}

		response.Ok(w, response.WithItem(getLoginSecretResp{Key: aesKey}))
	}
}

func (api *api) loginBodyDecrypt(ctx context.Context, r io.ReadCloser) ([]byte, error) {
	body, err := io.ReadAll(r)
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
	Username             string          `json:"username"`
	Account              string          `json:"account"`
	Status               string          `json:"status"`
	Type                 string          `json:"type"`
	Token                string          `json:"token"`
	Role                 model.RoleType  `json:"role"`
	Platform             string          `json:"platform"`
	ChallengeState       string          `json:"challengeState"`
	LicenseStatus        license.Status  `json:"licenseStatus"`
	CycleChangePwdDay    int             `json:"cycleChangePwdDay"`
	MustChangePwd        bool            `json:"mustChangePwd"`
	ChangePwdHashCode    string          `json:"changePwdHashCode"`
	TwoFactorLoginStatus string          `json:"twoFactorLoginStatus"`
	TwoFactorSecret      string          `json:"twoFactorSecret"`
	ModuleID             json.RawMessage `json:"module_id"`
}

const (
	MfaBinding            = "MfaBinding"            // 绑定获取二维码
	MfaSecretVerify       = "mfaSecretVerify"       // 验证绑定是否成功
	MfaVerify             = "MfaVerify"             // 二次验证
	AnewLogin             = "anewLogin"             // 重新登录
	TwoFactorVerifyFailed = "TwoFactorVerifyFailed" // 动态码验证失败，重新操作
)

type DXLoginResponse struct {
	LoginResponse
	IDToken string `json:"IDToken"`
}

func (api *api) login() http.HandlerFunc {
	type credentials struct {
		Account      string `json:"account"`
		Password     string `json:"password"`
		CaptchaID    string `json:"captchaID"`
		CaptchaValue string `json:"captchavalue"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		loginConf, err := getLoginConf(ctx, api.rdb)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("query login conf fails")))
			return
		}

		// check ip address
		flag, err := checkIpBlackList(ctx, loginConf.IPBlackList, r.RemoteAddr)
		if err != nil {
			RespAndLog(w, ctx,
				LoginError(http.StatusInternalServerError,
					err))
			return
		}
		if flag {
			RespAndLog(w, ctx,
				NewIPListBlackError(http.StatusInternalServerError,
					fmt.Errorf("this ip address cannot be logged in")))
			return
		}

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

		if creds.Account == "" || creds.Password == "" {
			// Handle case where  username or password are missing
			// We probably should have some validation helper instead of nested
			// ifs like this.
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("missing field 'password' or 'account': %s", decrypted),
					Suberror{Location: "account", Message: ""}, Suberror{Location: "password", Message: ""}))
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

		passwordOk, findUser, err := dal.GetUserByAccountPwd(ctx, api.rdb.GetReadDB(), creds.Account, creds.Password)
		if err != nil || findUser == nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("error when checking login credentials in database: %w", err)))
			return
		}

		// 多次输错密码检查
		limiter := usercenter.GetLimiter(ctx)
		if !passwordOk {
			if loginConf.RateLimitEnable && findUser.Role != model.RoleTypeSuperAdmin {
				locking := limiter.LoginFailToReachLimit(ctx, creds.Account)
				if locking {
					RespAndLog(w, r.Context(),
						NewAccountLockError(http.StatusPreconditionFailed,
							fmt.Errorf("the account %s is banned", creds.Account)))
					return
				}
			}
			RespAndLog(w, r.Context(),
				LoginError(http.StatusPreconditionFailed,
					fmt.Errorf("user and password not match")))
			return
		}
		limiter.LoginSuccessClean(findUser.UserName)

		cycleChangePwdDay := 0
		// 周期修改密码检查
		// 获取周期修改密码时间
		if loginConf.CycleChangePwd && findUser.Role != model.RoleTypeSuperAdmin {
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
				Username:          findUser.UserName,
				Account:           findUser.Account,
				Role:              findUser.Role,
				CycleChangePwdDay: cycleChangePwdDay,
				MustChangePwd:     true,
				ChangePwdHashCode: emailHashCode,
			}))
			return
		}

		// mfa认证
		if loginConf.MfaVerityLogin {
			twoFactorSecret, err := loginTwoFactorEncrypt(ctx, api.rdb.Get(), findUser.Account)
			if err != nil {
				RespAndLog(w, ctx,
					NewTwoFactorSecretError(http.StatusInternalServerError, err))
				return
			}
			var NextStep string
			if findUser.MfaStatus {
				NextStep = MfaVerify
			} else {
				NextStep = MfaBinding
			}

			response.Ok(w, response.WithItem(LoginResponse{
				Username:             findUser.UserName,
				Account:              findUser.Account,
				Role:                 findUser.Role,
				CycleChangePwdDay:    cycleChangePwdDay,
				TwoFactorLoginStatus: NextStep,
				TwoFactorSecret:      twoFactorSecret,
				ModuleID:             json.RawMessage(findUser.ModuleID),
			}), response.WithTarget(&response.TargetRef{
				Name:   findUser.Account,
				ID:     "",
				Link:   "",
				Active: NextStep,
			}))
			return
		}

		// issue JWT Token
		tokenString, err := api.issueJWTToken(ctx, findUser, r.UserAgent(), false)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("issue jwt token failed %w", err)))
			return
		}

		if findUser.ModuleID == "" {
			findUser.ModuleID = "[]"
		}
		response.Ok(w, response.WithItem(LoginResponse{
			Username:          findUser.UserName,
			Account:           findUser.Account,
			Status:            "ok",
			Type:              AccountTypeNormal,
			Token:             tokenString,
			Role:              findUser.Role,
			Platform:          findUser.Platform,
			LicenseStatus:     license.ValidateLicense(false),
			CycleChangePwdDay: cycleChangePwdDay,
			ModuleID:          json.RawMessage(findUser.ModuleID),
		}), response.WithTarget(&response.TargetRef{
			Name: creds.Account,
			ID:   "",
			Link: "",
		}))
	}
}

func getLoginConf(ctx context.Context, rdb *databases.RDBInstance) (loginConfigInfo, error) {
	loginConf := loginConfigInfo{}
	// select from redis
	sessionService, ok := session.GetService()
	if !ok {
		return loginConf, ErrServiceNotReady
	}

	config, err := sessionService.GetLoginConf(ctx)
	if err == nil {
		if err = json.Unmarshal(config, &loginConf); err != nil {
			return loginConf, err
		}
		return loginConf, nil
	}

	// select from mysql
	dbConf, err := dal.GetConfig(ctx, rdb.GetReadDB(), model.ConfLogin)
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return loginConf, err
		}
		dbConf = &model.TensorConfig{}
		loginConf = loginConfigInfo{
			FirstLoginChangePwd: false,
			ResetLoginChangePwd: false,
			CycleChangePwd:      false,
			CycleDay:            90,
			RateLimitEnable:     false,
			RateLimitThreshold:  5,
			MfaVerityLogin:      false,
			PwdSecurityLevel:    AVERAGE,
			IPBlackList:         nil,
		}
		dbConf.Config, err = json.Marshal(&loginConf)
		if err != nil {
			return loginConf, err
		}
	} else {
		if err = json.Unmarshal(dbConf.Config, &loginConf); err != nil {
			return loginConf, err
		}
	}
	if err = sessionService.SaveLoginConf(ctx, dbConf.Config); err != nil {
		logging.Get().Warn().Err(err).Msgf("redis: save login config fail")
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
		tokenString, err := api.issueJWTToken(ctx, user, r.UserAgent(), false)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("issue jwt token failed %w", err)))
			return
		}

		if user.ModuleID == "" {
			user.ModuleID = "[]"
		}
		response.Ok(w, response.WithItem(DXLoginResponse{
			LoginResponse: LoginResponse{
				Username:      user.UserName,
				Account:       user.Account,
				Status:        "ok",
				Type:          AccountTypeNormal,
				Token:         tokenString,
				Role:          user.Role,
				Platform:      user.Platform,
				LicenseStatus: license.ValidateLicense(false),
				ModuleID:      json.RawMessage(user.ModuleID),
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
		Account:   username,
		Nickname:  thirdInfo.Username,
		Role:      model.RoleTypeAdmin,
		ModuleID:  string(moduleID),
		Platform:  platform,
		CreatedAt: time.Now().Unix(),
		Creator:   "system",
		Status:    model.UserStatusNormal,
		Token:     util.GenerateUUIDHex(),
	}

	if err = rdb.Get().WithContext(ctx).Create(&u).Error; err != nil {
		return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("create a new accpount error from idp: %w", err))
	}

	return &u, nil
}

func checkUserStatus(username string, status int) error {
	if username == model.SuperAdminUsername {
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

func (api *api) logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		username := request.GetUsernameFromContext(ctx)

		sessionService, ok := session.GetService()
		if !ok {
			RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		if err := sessionService.DeleteToken(ctx, api.rdb.Get(), username); err != nil {
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

		loginConf, err := getLoginConf(r.Context(), api.rdb)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("query login conf fails")))
			return
		}

		if !checkPWD(ru.Pwd, loginConf.PwdSecurityLevel) {
			RespAndLog(w, r.Context(),
				NewPwdSecurityLevelError(http.StatusBadRequest,
					fmt.Errorf("the password strength is not up to standard")))
			return
		}

		// active user
		user, err := dal.ActiveUser(r.Context(), api.rdb.Get(), username, ru.Pwd, false)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("database error:%+v", err)))
			return
		}

		// mfa
		if loginConf.MfaVerityLogin {
			twoFactorSecret, err := loginTwoFactorEncrypt(r.Context(), api.rdb.Get(), username)
			if err != nil {
				RespAndLog(w, r.Context(),
					NewTwoFactorSecretError(http.StatusInternalServerError, err))
				return
			}

			response.Ok(w, response.WithItem(LoginResponse{
				Username:             user.UserName,
				Account:              user.Account,
				Role:                 user.Role,
				TwoFactorLoginStatus: MfaBinding,
				TwoFactorSecret:      twoFactorSecret,
			}))
			return
		}

		// issue JWT Token
		tokenString, err := api.issueJWTToken(r.Context(), user, r.UserAgent(), false)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("issue jwt token failed %w", err)))
			return
		}

		// 获取周期修改密码时间
		cycleChangePwdDay := 0
		if loginConf.CycleChangePwd {
			cycleChangePwdDay, err = getCycleChangePwdDay(r.Context(), api.rdb, loginConf, user)
			if err != nil {
				RespAndLog(w, r.Context(), err)
				return
			}
		}

		if user.ModuleID == "" {
			user.ModuleID = "[]"
		}
		response.Ok(w, response.WithItem(LoginResponse{
			Username:          user.UserName,
			Account:           user.Account,
			Status:            "ok",
			Type:              AccountTypeNormal,
			Token:             tokenString,
			Role:              user.Role,
			Platform:          user.Platform,
			LicenseStatus:     license.ValidateLicense(false),
			CycleChangePwdDay: cycleChangePwdDay,
			ModuleID:          json.RawMessage(user.ModuleID),
		}), response.WithTarget(&response.TargetRef{
			Name: user.UserName,
			ID:   "",
			Link: "",
		}))
	}
}

func (api *api) forgetPwd() http.HandlerFunc {
	// 1 token is generated per minute, maximum 5
	lmt := util.NewLimiter(rate.Every(time.Minute), 5, time.Minute*10)

	type reqForgetUser struct {
		Account      string `json:"account" binding:"required,max=32"`
		CaptchaID    string `json:"captchaID"`
		CaptchaValue string `json:"captchavalue"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if !lmt.AllowKey(util.MD5Hex(r.UserAgent())) {
			RespAndLog(w, r.Context(),
				NewCommonError(http.StatusBadRequest, fmt.Errorf("忘记密码请求过快:%s", r.UserAgent()),
					"发送邮件频率过快，请稍后再试", "Request is too fast. Please try again later"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		rf := reqForgetUser{}
		err := json.NewDecoder(r.Body).Decode(&rf)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if rf.Account == "" {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("account is empty")))
			return
		}

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

		exist, u, err := dal.SelectUserByAccount(ctx, api.rdb.Get(), rf.Account)
		if err != nil {
			RespAndLog(w, ctx,
				RDBError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}
		if !exist {
			// 用户不存在直接返回成功
			// 防止利用error遍历用户
			logging.Get().Warn().Str("account", rf.Account).Msg("forgetPwd: user not exist")

			response.Ok(w)
			return
		}

		emailHashCode := dal.RandStringBytesMaskImprSrcUnsafe(64)

		successful := SendEmail(rf.Account, r.Host, emailHashCode)
		if !successful {
			RespAndLog(w, ctx,
				SendmailError(http.StatusBadRequest, fmt.Errorf("send email error")))
			return
		}

		err = dal.InsertEmail(ctx, api.rdb.Get(), u.UserName, emailHashCode)
		if err != nil {
			RespAndLog(w, ctx,
				RDBError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}

		response.Ok(w)
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

func SendEmail(account, host, emailHashCode string) bool {

	mailBody := "<div\n      style=\"\n  height:560px; \n    width: 752px;\n        min-width: 752px;\n        margin: 0 auto;\n        overflow-x: scroll;\n        position: relative;\n      \"\n    >\n      <div\n        style=\"\n          border-radius: 4px 4px 0 0;\n          border: 1px solid #9bb1c7;\n          border-bottom: 0px;\n          background-color: #ffffff;\n          height: 100%;\n          z-index: 10;\n          margin: 0 30px;\n          padding: 50px 60px 150px;\n          box-sizing: border-box;\n        \"\n      >\n        <div\n          style=\"width: 100%; border-top: 2px solid #d1d8dc; margin: 20px 0\"\n        ></div>\n        <div style=\"width: 100%; padding: 14px 0; box-sizing: border-box\">\n          <span\n            style=\"\n              display: block;\n              font-size: 16px;e\n              font-family: PingFangSC-Medium, PingFang SC;\n              font-weight: 500;\n              color: #333333;\n            \"\n          >\n            " + account + " ,您好！\n          </span>\n          <span\n            style=\"\n              display: block;\n              font-size: 16px;\n              font-family: PingFangSC-Medium, PingFang SC;\n              font-weight: 400;\n              color: #333333;\n              margin-top: 20px;\n              text-indent: 2em;\n            \"\n          >\n            有人请求激活或者重置您的帐户的密码。\n            如果您没有执行此请求，则可以放心地忽略此电子邮件。\n            否则，请单击下面的链接以完成该过程。\n            <a href=\" http://" + host + "/#/email/password/" + emailHashCode + "\"  \"target=\"_blank\">点击此链接</a>\n          </span>\n        </div>\n        <div\n          style=\"width: 100%; border-top: 2px solid #d1d8dc; margin: 20px 0\"\n        ></div>\n        <span\n          style=\"\n            display: block;\n            font-size: 14px;\n            font-family: PingFangSC-Medium, PingFang SC;\n            font-weight: 400;\n            color: #777777;\n          \"\n          >如有任何问题，可以与我们联系，我们将尽快为你解答。\n        </span>\n        <span\n          style=\"\n            display: block;\n            font-size: 14px;\n            font-family: PingFangSC-Medium, PingFang SC;\n            font-weight: 400;\n            color: #777777;\n            margin-top: 4px;\n          \"\n          >Email：" + env.GetContactEmail() + " \n        </span>\n\n      </div>\n      <div style=\"width: 100%; height: 100%; margin-top: -160px\">\n        </div>\n    </div>"
	subject := "Account manager"

	err := SendMails([]string{account}, subject, mailBody)
	if err != nil {
		logging.Get().Error().Msgf("send email error:%+v", err)
		return false
	}

	return true

}

// -----jwt-----
func (api *api) issueJWTToken(ctx context.Context, u *model.User, userAgent string, external bool) (string, error) {
	tokenPayload := token.Payload{
		Username:   u.UserName,
		Account:    u.Account,
		Role:       u.Role,
		Platform:   u.Platform,
		ModuleID:   u.ModuleID,
		External:   external,
		Status:     u.Status,
		Eigenvalue: util.MD5Hex(userAgent),
	}

	tokenString, err := api.tokenManager.IssueTo(tokenPayload, time.Hour*24)
	if err != nil {
		logging.Get().Info().Err(err).Msg("")
		return "", err
	}

	// save token to redis
	sessionService, ok := session.GetService()
	if !ok {
		return "", ErrServiceNotReady
	}

	if err = sessionService.SaveToken(ctx, u.UserName, tokenString); err != nil {
		logging.Get().Warn().Err(err).Msgf("redis: save user token fail")
	}

	// save to mysql
	err = dal.UpdateUserToken(ctx, api.rdb.Get(), u.UserName, tokenString, time.Now().Add(session.DefaultTokenTTL).Unix())
	if err != nil {
		return "", fmt.Errorf("save user token fail:%w", err)
	}

	logging.Get().Debug().Msgf("login token issue: %s %s %t", u.UserName, tokenString, external)
	return tokenString, nil
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

// MFA
const (
	Issuer  = "tensorsecurity.cn"
	android = "https://jms-pkg.oss-cn-beijing.aliyuncs.com/Google%20Authenticator_v5.10_apkpure.com.apk"
	ios     = "https://apps.apple.com/cn/app/google-authenticator/id388497605?l=en-GB"
)

type GetImageResponse struct {
	CurrentAuthority     string `json:"currentAuthority"`
	TwoFactorLoginStatus string `json:"twoFactorLoginStatus"`
	TwoFactorSecret      string `json:"twoFactorSecret"`
	MfaImage             string `json:"mfaImage"`
	MfaSecret            string `json:"mfaSecret"`
	MfaQrCodeInfo        string `json:"mfaQrCodeInfo"`
}

type VerifyMfaResponse struct {
	CurrentAuthority     string `json:"currentAuthority"`
	TwoFactorLoginStatus string `json:"twoFactorLoginStatus"`
	TwoFactorSecret      string `json:"twoFactorSecret"`
}

func (api *api) getVerifyAppURL() http.HandlerFunc {
	type AppUrl struct {
		Android string `json:"android"`
		Ios     string `json:"ios"`
	}
	iosUrl := os.Getenv("IOS_APP_URL")
	if iosUrl == "" {
		iosUrl = ios
	}
	androidUrl := os.Getenv("ANDROIDURL")
	if androidUrl == "" {
		androidUrl = android
	}
	return func(w http.ResponseWriter, r *http.Request) {

		response.Ok(w, response.WithItem(AppUrl{
			Android: androidUrl,
			Ios:     iosUrl,
		}))
	}
}

func (api *api) BindGetMFASecret() http.HandlerFunc {
	type CreateImage struct {
		Account         string `json:"account"`
		TwoFactorSecret string `json:"loginTwoFactorSecret"`
		Width           int    `json:"width"`
		Height          int    `json:"height"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		createInfo := &CreateImage{}
		if err := json.NewDecoder(r.Body).Decode(createInfo); err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		u, _, err := loginTwoFactorDecrypt(ctx, api.rdb.Get(), createInfo.Account, createInfo.TwoFactorSecret)
		if err != nil {
			RespAndLog(w, ctx,
				NewTwoFactorVerifyError(http.StatusInternalServerError, err))
			return
		}

		if u.MfaStatus {
			RespAndLog(w, ctx,
				NewMfaSecretStatusIsExistError(http.StatusInternalServerError, fmt.Errorf("密钥已绑定")))
			return
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      Issuer,
			AccountName: u.Account,
		})
		if err != nil {
			RespAndLog(w, ctx,
				NewMfaSecretError(http.StatusInternalServerError,
					fmt.Errorf("create mfa secret fail:%w", err)))
			return
		}

		img, err := key.Image(200, 200)
		if err != nil {
			RespAndLog(w, ctx,
				NewMfaSecretError(http.StatusInternalServerError,
					fmt.Errorf("create mfa QR fail:%w", err)))
			return
		}

		var image bytes.Buffer
		png.Encode(&image, img)
		imgStr := base64.StdEncoding.EncodeToString(image.Bytes())

		if err := dal.UpdateUserMfaSecret(ctx, api.rdb.GetReadDB(), key.Secret(), u.UserName); err != nil {
			RespAndLog(w, ctx,
				RDBError(http.StatusInternalServerError,
					fmt.Errorf("save login mfa secret fail:%w", err)))
			return
		}

		TwoFactorSecret, err := loginTwoFactorEncrypt(ctx, api.rdb.Get(), u.Account)
		if err != nil {
			RespAndLog(w, ctx,
				NewTwoFactorSecretError(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w, response.WithItem(GetImageResponse{
			CurrentAuthority:     u.Account,
			TwoFactorSecret:      TwoFactorSecret,
			MfaImage:             imgStr,
			MfaQrCodeInfo:        key.String(),
			TwoFactorLoginStatus: MfaSecretVerify,
			MfaSecret:            key.Secret(),
		}))
	}
}

func (api *api) BindMfaSecretVerify() http.HandlerFunc {
	type VerifyInfo struct {
		MfaCode         string `json:"mfaCode"`
		Account         string `json:"account"`
		TwoFactorSecret string `json:"loginTwoFactorSecret"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		bindVerifyInfo := &VerifyInfo{}
		if err := json.NewDecoder(r.Body).Decode(bindVerifyInfo); err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		u, _, err := loginTwoFactorDecrypt(ctx, api.rdb.Get(), bindVerifyInfo.Account, bindVerifyInfo.TwoFactorSecret)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewTwoFactorVerifyError(http.StatusInternalServerError, err))
			return
		}
		if u.MfaStatus {
			RespAndLog(w, ctx,
				NewMfaSecretStatusIsExistError(http.StatusInternalServerError, fmt.Errorf("密钥已绑定")))
			return
		}
		if u.MfaSecret == "" {
			RespAndLog(w, r.Context(),
				NewTwoFactorVerifyError(http.StatusInternalServerError, fmt.Errorf("data missing")))
			return
		}

		if valid := totp.Validate(bindVerifyInfo.MfaCode, u.MfaSecret); !valid {
			TwoFactorSecret, err := loginTwoFactorEncrypt(r.Context(), api.rdb.Get(), u.Account)
			if err != nil {
				RespAndLog(w, ctx,
					NewTwoFactorSecretError(http.StatusInternalServerError, err))
				return
			}

			response.Ok(w, response.WithItem(VerifyMfaResponse{
				CurrentAuthority:     u.Account,
				TwoFactorSecret:      TwoFactorSecret,
				TwoFactorLoginStatus: TwoFactorVerifyFailed,
			}))
			return
		}

		if err := dal.UpdateUserMfaStatus(r.Context(), api.rdb.GetReadDB(), true, u.UserName); err != nil {
			var TwoFactorSecret string
			if TwoFactorSecret, err = loginTwoFactorEncrypt(r.Context(), api.rdb.Get(), u.UserName); err != nil {
				RespAndLog(w, ctx,
					NewTwoFactorSecretError(http.StatusInternalServerError, err))
				return
			}

			response.Ok(w, response.WithItem(VerifyMfaResponse{
				CurrentAuthority:     u.Account,
				TwoFactorSecret:      TwoFactorSecret,
				TwoFactorLoginStatus: TwoFactorVerifyFailed,
			}))
			return
		}

		response.Ok(w, response.WithItem(VerifyMfaResponse{
			CurrentAuthority:     u.Account,
			TwoFactorLoginStatus: AnewLogin,
		}))
	}
}

func (api *api) LoginMfaSecretVerify() http.HandlerFunc {
	type VerifyInfo struct {
		MfaCode         string `json:"mfaCode"`
		Account         string `json:"account"`
		TwoFactorSecret string `json:"loginTwoFactorSecret"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		bindVerifyInfo := &VerifyInfo{}
		if err := json.NewDecoder(r.Body).Decode(bindVerifyInfo); err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		u, _, err := loginTwoFactorDecrypt(ctx, api.rdb.Get(), bindVerifyInfo.Account, bindVerifyInfo.TwoFactorSecret)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewTwoFactorVerifyError(http.StatusInternalServerError, err))
			return
		}
		if !u.MfaStatus {
			RespAndLog(w, ctx,
				NewMfaSecretStatusNotExistError(http.StatusInternalServerError, fmt.Errorf("密钥未绑定")))
			return
		}

		if valid := totp.Validate(bindVerifyInfo.MfaCode, u.MfaSecret); !valid {
			TwoFactorSecret, err := loginTwoFactorEncrypt(r.Context(), api.rdb.Get(), u.Account)
			if err != nil {
				RespAndLog(w, ctx,
					NewTwoFactorSecretError(http.StatusInternalServerError, err))
				return
			}

			response.Ok(w, response.WithItem(VerifyMfaResponse{
				CurrentAuthority:     u.UserName,
				TwoFactorSecret:      TwoFactorSecret,
				TwoFactorLoginStatus: TwoFactorVerifyFailed,
			}))
			return
		}

		// issue JWT Token
		tokenString, err := api.issueJWTToken(r.Context(), u, r.UserAgent(), false)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("issue jwt token failed %w", err)))
			return
		}

		loginConf, err := getLoginConf(r.Context(), api.rdb)

		cycleChangePwdDay := 0
		if loginConf.CycleChangePwd {
			cycleChangePwdDay, err = getCycleChangePwdDay(r.Context(), api.rdb, loginConf, u)
			if err != nil {
				RespAndLog(w, r.Context(), err)
				return
			}
		}

		if u.ModuleID == "" {
			u.ModuleID = "[]"
		}
		response.Ok(w, response.WithItem(LoginResponse{
			Username:             u.UserName,
			Account:              u.Account,
			Status:               "ok",
			Type:                 AccountTypeNormal,
			Token:                tokenString,
			Role:                 u.Role,
			TwoFactorLoginStatus: "",
			Platform:             u.Platform,
			LicenseStatus:        license.ValidateLicense(false),
			CycleChangePwdDay:    cycleChangePwdDay,
			ModuleID:             json.RawMessage(u.ModuleID),
		}), response.WithTarget(&response.TargetRef{
			Name: u.Account,
			ID:   "",
			Link: "",
		}))
	}
}

func loginTwoFactorEncrypt(ctx context.Context, db *gorm.DB, account string) (string, error) {
	aeskey := dal.RandStringBytesMaskImprSrcUnsafe(16)
	// save to mysql
	if err := dal.UpdateLoginTwoFactorSecret(ctx, db, account, aeskey, time.Now().Add(time.Hour).Unix()); err != nil {
		return "", fmt.Errorf("save two-factor secret failed:%w", err)
	}

	data := []byte(account + "" + strconv.FormatInt(time.Now().Unix(), 10))
	Encrypted, err := util.AesEncryptCBC(data, []byte(aeskey))
	if err != nil {
		return "", fmt.Errorf("AesEncryptCBC failed:%w", err)
	}
	EncryptedStr := base64.StdEncoding.EncodeToString(Encrypted)
	return EncryptedStr, nil
}

func loginTwoFactorDecrypt(ctx context.Context, db *gorm.DB, account, EncryptedStr string) (*model.User, string, error) {
	exist, user, err := dal.SelectUserByAccount(ctx, db, account)
	if err != nil {
		return nil, "", fmt.Errorf("get user information failed:%w", err)
	}
	if !exist {
		return nil, "", fmt.Errorf("invalid user name")
	}
	if time.Now().Unix() > user.TwoFactorKeyExpireAt { // 密钥过期
		return nil, "", fmt.Errorf("login two-factor secret expire, Plase try again")
	}
	aesKey := user.TwoFactorKey
	if EncryptedStr == "" {
		return nil, "", fmt.Errorf("two-factor secret missing")
	}
	encrypted, err := base64.StdEncoding.DecodeString(EncryptedStr)
	if err != nil {
		return nil, "", fmt.Errorf("DecodeString str failed:%w", err)
	}
	decrypted, err := util.AesDecryptCBC(encrypted, []byte(aesKey))
	if err != nil {
		return nil, "", fmt.Errorf("AesDecryptCBC failed:%w", err)
	}
	return user, string(decrypted), nil

}

func checkIpBlackList(ctx context.Context, ipBlackList []string, ip string) (flag bool, err error) {
	if ipBlackList == nil {
		return false, nil
	}

	sessionService, ok := session.GetService()
	if !ok {
		return false, ErrServiceNotReady
	}

	// select from redis
	exists, err := sessionService.CheckBlackListExists(ctx)
	if err != nil {
		logging.Get().Warn().Msg("IPBlackList not save in redis")
	}
	if exists == 1 {
		flag, err = sessionService.CheckIP(ctx, ip)
		if err != nil {
			return false, err
		}
		return flag, nil
	}
	// save in redis
	data := make(map[string]interface{})
	for _, v := range ipBlackList {
		data[v] = v
		if v == ip {
			flag = true
		}
	}
	if err := sessionService.SaveBlackList(ctx, data); err != nil {
		return flag, err
	}
	return flag, nil
}
