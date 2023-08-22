package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/captcha"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/license"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/ldap"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/radius"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	defaultAccountTimeout = time.Second * 5
	accountAPIVersion     = "2.0"
	LoginTypeNormal       = "normal"
	LoginTypeLdap         = "ldap"
	LoginTypeRadius       = "radius"

	LdapUsernamePrefix   = "ldap$"
	RadiusUsernamePrefix = "radius$"

	AccountTypeNormal = "account"
	AccountTypeLdap   = "ldapAccount"
	AccountTypeRadius = "radiusAccount"
)

var (
	ErrNotSupportLoginType = errors.New("not support login type")
)

func (api *api) UpdateLdapConf() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		if authErr := api.verifyAuthorization(ctx); authErr != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewNoAccess(http.StatusForbidden,
					fmt.Errorf("no acess: %w", authErr)))
			return
		}

		type request struct {
			Conf      model.LdapServerConf  `json:"conf"`
			GroupList []model.LdapGroupItem `json:"groupList"`
		}

		var req request
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if err = req.Conf.Check(); err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewCommonError(http.StatusBadRequest, err, "配置参数无效", "invalid config"))
			return
		}

		err = dal.SetConfig(ctx, api.rdb.Get(), model.LdapConfKey, req.Conf.Encode())
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		// 由于这个表的记录量应该特别小而且操作频率特别低，直接清空重写。
		err = api.truncateLdapGroup(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}
		ldapGroupDisplays := make([]*model.LdapGroupDisplay, len(req.GroupList))
		for i := range req.GroupList {
			group, modules, err := api.createLdapGroup(ctx, &req.GroupList[i])
			if err != nil {
				if err == CheckLdapGroupInterError {
					apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(http.StatusBadRequest, err))
					return
				}
				apperror.RespAndLog(w, ctx, err)
				return
			}
			ldapGroupDisplays = append(ldapGroupDisplays, &model.LdapGroupDisplay{
				ID:      group.ID,
				Name:    group.Name,
				Role:    group.Role,
				Modules: modules,
			})
		}

		type resp struct {
			Conf      *model.LdapServerConf     `json:"conf"`
			GroupList []*model.LdapGroupDisplay `json:"groupList"`
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(resp{
			Conf:      &req.Conf,
			GroupList: ldapGroupDisplays,
		}))
	}
}

func (api *api) GetLdapConf() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()
		conf, err := api.getLdapConf(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		groupDisplay, _, err := api.getLdapGroupList(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		type resp struct {
			Conf      *model.LdapServerConf     `json:"conf"`
			GroupList []*model.LdapGroupDisplay `json:"groupList"`
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(resp{
			Conf:      conf,
			GroupList: groupDisplay,
		}))
	}
}

func (api *api) UpdateLdapCert() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		err := r.ParseMultipartForm(100 << 20)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("ParseMultipartForm fail, err:%w", err)))
			return
		}

		getContent := func(key string) ([]byte, bool) {
			file, _, err := r.FormFile(key)
			if err != nil {
				return nil, false
			}

			data, err := ioutil.ReadAll(file)
			if err != nil {
				return nil, false
			}

			return data, true
		}

		var configs []*model.TensorConfig
		nowTime := time.Now()
		caContent, ok := getContent("ca")
		if ok {
			configs = append(configs, dal.NewConfig(ctx, model.LdapCAKey, caContent, nowTime))
		}

		clientCertContent, ok := getContent("clientCert")
		if ok {
			configs = append(configs, dal.NewConfig(ctx, model.LdapClientCertKey, clientCertContent, nowTime))
		}

		clientKeyContent, ok := getContent("clientKey")
		if ok {
			configs = append(configs, dal.NewConfig(ctx, model.LdapClientKey, clientKeyContent, nowTime))
		}

		if len(configs) == 0 {
			apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(http.StatusBadRequest, errors.New("no config")))
			return
		}

		err = dal.BatchSetConfig(ctx, api.rdb.Get(), configs)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		info, err := api.getLdapCertInfo(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(*info))
	}
}

type LdapCertInfo struct {
	CaUpdatedTimestamp         int64 `json:"caUpdatedTimestamp"`
	ClientCertUpdatedTimestamp int64 `json:"clientCertUpdatedTimestamp"`
	ClientKeyUpdatedTimestamp  int64 `json:"clientKeyUpdatedTimestamp"`
}

func (api *api) GetLdapCertInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		info, err := api.getLdapCertInfo(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(*info))
	}
}

func (api *api) getLdapCertInfo(ctx context.Context) (*LdapCertInfo, error) {
	configs, err := dal.BatchGetConfig(ctx, api.rdb.GetReadDB(),
		[]string{model.LdapCAKey, model.LdapClientKey, model.LdapClientCertKey})
	if err != nil {
		return nil, err
	}

	var info = &LdapCertInfo{}
	for _, config := range configs {
		if config.Key == model.LdapCAKey {
			info.CaUpdatedTimestamp = util.GetMillisecondTimestampByTime(config.UpdatedAt)
		} else if config.Key == model.LdapClientCertKey {
			info.ClientCertUpdatedTimestamp = util.GetMillisecondTimestampByTime(config.UpdatedAt)
		} else if config.Key == model.LdapClientKey {
			info.ClientKeyUpdatedTimestamp = util.GetMillisecondTimestampByTime(config.UpdatedAt)
		}
	}

	return info, nil
}
func (api *api) UpdateRadiusConf() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()
		if authErr := api.verifyAuthorization(ctx); authErr != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewNoAccess(http.StatusForbidden,
					fmt.Errorf("no acess: %w", authErr)))
			return
		}

		var conf model.RadiusServerConf
		err := util.DecodeJSONBody(w, r, &conf)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if err = conf.Check(); err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewCommonError(http.StatusBadRequest, err, "配置参数无效", "invalid config"))
			return
		}

		err = dal.SetConfig(ctx, api.rdb.Get(), model.RadiusConfKey, conf.Encode())
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(conf))
	}
}

func (api *api) GetRadiusConf() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()
		conf, err := api.getRadiusConf(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(*conf))
	}
}

func (api *api) getLdapConf(ctx context.Context) (*model.LdapServerConf, error) {
	conf, err := dal.GetConfig(ctx, api.rdb.Get(), model.LdapConfKey)
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	if conf == nil || err == gorm.ErrRecordNotFound {
		return &model.DefaultLdapServerConf, nil
	}

	var ldapConf model.LdapServerConf
	err = ldapConf.Decode(conf.Config)
	return &ldapConf, err
}

func (api *api) getRadiusConf(ctx context.Context) (*model.RadiusServerConf, error) {
	conf, err := dal.GetConfig(ctx, api.rdb.Get(), model.RadiusConfKey)
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	if conf == nil || err == gorm.ErrRecordNotFound {
		return &model.DefaultRadiusServerConf, nil
	}

	var radiusConf model.RadiusServerConf
	err = radiusConf.Decode(conf.Config)
	return &radiusConf, err
}

func (api *api) GetLoginOption() http.HandlerFunc {
	type rsp struct {
		Options        []string `json:"options"`
		CycleChangePwd bool     `json:"cycleChangePwd"`
		EmailEnabled   bool     `json:"emailEnabled"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		ldapConf, err := api.getLdapConf(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		radiusConf, err := api.getRadiusConf(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		var options []string
		if ldapConf == nil || !ldapConf.Enable {
			options = []string{LoginTypeNormal}
		} else if radiusConf == nil || !radiusConf.Enable {
			options = []string{LoginTypeNormal, LoginTypeLdap}
		} else {
			options = []string{LoginTypeNormal, LoginTypeLdap, LoginTypeRadius}
		}

		cycleChangePwd := false
		conf, err := dal.GetConfig(ctx, api.rdb.GetReadDB(), model.ConfLogin)
		if err != nil {
			if err != gorm.ErrRecordNotFound {
				apperror.RespAndLog(w, ctx, err)
				return
			}
		} else {
			result := loginConfigInfo{}
			if err = json.Unmarshal(conf.Config, &result); err != nil {
				apperror.RespAndLog(w, ctx, err)
				return
			}
			cycleChangePwd = result.CycleChangePwd
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(rsp{
			Options:        options,
			CycleChangePwd: cycleChangePwd,
			EmailEnabled:   env.GetEmailCheck(),
		}))
	}
}

func (api *api) LdapLogin() http.HandlerFunc {
	type req struct {
		Account      string `json:"account"`
		Password     string `json:"password"`
		CaptchaID    string `json:"captchaID"`
		CaptchaValue string `json:"captchaValue"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		decrypted, err := api.loginBodyDecrypt(ctx, r.Body)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("illeagal params: %w", err)))
			return
		}

		cliReq := &req{}
		if err = json.Unmarshal(decrypted, cliReq); err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if cliReq.Account == "" || cliReq.Password == "" {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("missing field 'password' or 'username'")))
			return
		}

		captchaService, ok := captcha.GetService()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		if captchaService.IsBreakerClosed() &&
			!captchaService.Verify(cliReq.CaptchaID, cliReq.CaptchaValue) {
			apperror.RespAndLog(w, ctx,
				apperror.NewCaptchaError(http.StatusBadRequest,
					fmt.Errorf("captcha value error")))
			return
		}

		ldapConf, err := api.getLdapConf(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		if ldapConf == nil || !ldapConf.Enable {
			apperror.RespAndLog(w, ctx, apperror.NewCommonError(http.StatusBadRequest,
				ErrNotSupportLoginType, "不支持ldap登陆", "not support ldap login"))
			return
		}

		var tlsConf = &tls.Config{}
		if ldapConf.ConnType != model.LdapModeNonTLS {
			tlsConf = api.getLdapTlsConfig(ctx, ldapConf.ServerNameOverride)
		}
		group, err := ldap.Login(cliReq.Account, cliReq.Password, ldapConf, tlsConf)
		if err != nil {
			if err == ldap.ErrUserPasswordNotMatch {
				apperror.RespAndLog(w, ctx,
					apperror.LoginError(http.StatusPreconditionFailed,
						fmt.Errorf("user and password not match: %w", err)))
				return
			}

			apperror.RespAndLog(w, ctx,
				apperror.NewCommonError(http.StatusPreconditionFailed, err, "ldap登陆失败", "ldap login failed"))
			return
		}

		ldapUsername := fmt.Sprintf("%s%s", LdapUsernamePrefix, cliReq.Account)
		api.externalLogin(ctx, w, &externalUserArg{
			username:    ldapUsername,
			accountType: AccountTypeLdap,
			group:       group,
			userAgent:   r.UserAgent(),
		})
	}
}

func (api *api) getLdapTlsConfig(ctx context.Context, serverName string) *tls.Config {
	var result = &tls.Config{ServerName: serverName}
	if result.ServerName == "" {
		result.InsecureSkipVerify = true
	}
	configs, err := dal.BatchGetConfig(ctx, api.rdb.GetReadDB(),
		[]string{model.LdapCAKey, model.LdapClientKey, model.LdapClientCertKey})
	if err != nil {
		logging.Get().Err(err).Msg("getLdapTlsConfig from db fail")
		return result
	}

	var ca, clientCert, clientKey []byte
	for _, config := range configs {
		if config.Key == model.LdapCAKey {
			ca = config.Config
		} else if config.Key == model.LdapClientCertKey {
			clientCert = config.Config
		} else if config.Key == model.LdapClientKey {
			clientKey = config.Config
		}
	}

	if len(ca) > 0 {
		clientCertPool := x509.NewCertPool()
		if clientCertPool.AppendCertsFromPEM(ca) {
			result.RootCAs = clientCertPool
		} else {
			logging.Get().Error().Msg("AppendCertsFromPEM fail")
		}
	}

	if len(clientCert) > 0 && len(clientKey) > 0 {
		cert, err := tls.X509KeyPair(clientCert, clientKey)
		if err != nil {
			logging.Get().Err(err).Msg("ldap cert X509KeyPair fail")
		} else {
			result.Certificates = []tls.Certificate{cert}
		}
	}

	return result
}

func (api *api) RadiusLogin() http.HandlerFunc {
	type req struct {
		Account      string `json:"account"`
		Password     string `json:"password"`
		CaptchaID    string `json:"captchaID"`
		CaptchaValue string `json:"captchaValue"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		// decrypt
		decrypted, err := api.loginBodyDecrypt(ctx, r.Body)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("illeagal params: %w", err)))
			return
		}

		cliReq := &req{}
		if err = json.Unmarshal(decrypted, cliReq); err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if cliReq.Account == "" || cliReq.Password == "" {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("missing field 'password' or 'username'")))
			return
		}

		captchaService, ok := captcha.GetService()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		if captchaService.IsBreakerClosed() &&
			!captchaService.Verify(cliReq.CaptchaID, cliReq.CaptchaValue) {
			apperror.RespAndLog(w, ctx,
				apperror.NewCaptchaError(http.StatusBadRequest,
					fmt.Errorf("captcha value error")))
			return
		}

		api.radiusLogin(ctx, w, cliReq.Account, cliReq.Password, "", r.UserAgent())
	}
}

func (api *api) RadiusResponseChallenge() http.HandlerFunc {
	type req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		State    string `json:"state"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		// decrypt
		decrypted, err := api.loginBodyDecrypt(ctx, r.Body)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("illeagal params: %w", err)))
			return
		}

		cliReq := &req{}
		if err = json.Unmarshal(decrypted, cliReq); err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if cliReq.Username == "" || cliReq.Password == "" || cliReq.State == "" {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("missing field 'password' or 'username' or 'state'")))
			return
		}

		api.radiusLogin(ctx, w, cliReq.Username, cliReq.Password, cliReq.State, r.UserAgent())
	}
}

func (api *api) radiusLogin(ctx context.Context, w http.ResponseWriter, account, password, challengeState, userAgent string) {
	ldapConf, err := api.getLdapConf(ctx)
	if err != nil {
		apperror.RespAndLog(w, ctx, err)
		return
	}

	if ldapConf == nil || !ldapConf.Enable {
		apperror.RespAndLog(w, ctx, apperror.NewCommonError(http.StatusBadRequest,
			ErrNotSupportLoginType, "不支持radius登陆", "not support radius login"))
		return
	}

	radiusConf, err := api.getRadiusConf(ctx)
	if err != nil {
		apperror.RespAndLog(w, ctx, err)
		return
	}

	if radiusConf == nil || !radiusConf.Enable {
		apperror.RespAndLog(w, ctx,
			apperror.NewCommonError(http.StatusBadRequest, ErrNotSupportLoginType, "不支持radius登陆", "not support radius login"))
		return
	}

	nextChallengeState, err := radius.Login(ctx, account, password, challengeState, radiusConf)
	if err != nil {
		if err == radius.ErrUserPasswordNotMatch {
			apperror.RespAndLog(w, ctx,
				apperror.LoginError(http.StatusPreconditionFailed,
					fmt.Errorf("user and password not match: %w", err)))
			return
		}

		apperror.RespAndLog(w, ctx,
			apperror.NewCommonError(http.StatusPreconditionFailed, err, "radius登陆失败", "radius login failed"))
		return
	}

	if nextChallengeState != "" {
		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(LoginResponse{
			ChallengeState: nextChallengeState,
			LicenseStatus:  license.ValidateLicense(false),
		}))
		return
	}

	var tlsConf = &tls.Config{}
	if ldapConf.ConnType != model.LdapModeNonTLS {
		tlsConf = api.getLdapTlsConfig(ctx, ldapConf.ServerNameOverride)
	}
	group, err := ldap.GetUserGroup(account, ldapConf, tlsConf)
	if err != nil {
		apperror.RespAndLog(w, ctx,
			apperror.NewCommonError(http.StatusPreconditionFailed, err, "获取ldap组失败", "get ldap group failed"))
		return
	}

	radiusUsername := fmt.Sprintf("%s%s", RadiusUsernamePrefix, account)
	api.externalLogin(ctx, w, &externalUserArg{
		username:    radiusUsername,
		group:       group,
		accountType: AccountTypeRadius,
		userAgent:   userAgent,
	})
}

type externalUserArg struct {
	username    string
	accountType string
	group       string
	userAgent   string
}

func (api *api) externalLogin(ctx context.Context, w http.ResponseWriter, arg *externalUserArg) {
	user, err := api.makeUserSessionByGroup(ctx, arg.username, arg.group)
	if err != nil {
		apperror.RespAndLog(w, ctx, err)
		return
	}

	tokenString, err := api.issueJWTToken(ctx, user, "", true)
	if err != nil {
		apperror.RespAndLog(w, ctx, ErrServiceNotReady)
		return
	}

	response.Ok(w, response.WithItem(LoginResponse{
		Username:      user.UserName,
		Account:       user.Account,
		Status:        "ok",
		Type:          arg.accountType,
		Token:         tokenString,
		Role:          user.Role,
		LicenseStatus: license.ValidateLicense(false),
	}))
}

func (api *api) makeUserSessionByGroup(ctx context.Context, username, group string) (*model.User, error) {
	ldapGroup, err := dal.GetLdapGroupByName(ctx, api.rdb.Get(), group)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			ldapGroup = &model.LdapGroup{Role: model.RoleTypeNormal, Modules: "[]"}
		} else {
			return nil, fmt.Errorf("get ldap group fail, err:%w", err)
		}
	}
	user := &model.User{
		UserName: username,
		Account:  username,
		Role:     ldapGroup.Role,
		ModuleID: convertModule(ldapGroup.Modules),
		Status:   model.UserStatusNormal,
	}
	return user, nil
}

// 旧代码使用的是字符串数组 暂时先适配旧代码逻辑
func convertModule(module string) string {
	var intArray []int
	_ = json.Unmarshal([]byte(module), &intArray)
	var strArray = make([]string, len(intArray))
	for i := range strArray {
		strArray[i] = strconv.Itoa(intArray[i])
	}
	result, _ := json.Marshal(strArray)
	return string(result)
}

const (
	maxLdapGroupBatchSize     = 10
	defaultLdapGroupBatchSize = 10
)

func (api *api) GetLdapGroupList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		groupDisplay, count, err := api.getLdapGroupList(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItems(groupDisplay), response.WithTotalItems(count))
	}
}

func (api *api) getLdapGroupList(ctx context.Context) ([]*model.LdapGroupDisplay, int64, error) {
	var groupDisplay []*model.LdapGroupDisplay
	count, err := dal.GetLdapGroupCount(ctx, api.rdb.GetReadDB())
	if err != nil {
		return groupDisplay, count, err
	}

	groups, err := dal.GetLdapGroupList(ctx, api.rdb.GetReadDB(), 0, 0)
	if err != nil {
		return groupDisplay, count, err
	}

	moduleIDs := model.GetModuleIDByGroups(groups)
	modules, err := dal.GetModules(ctx, api.rdb.GetReadDB(), moduleIDs)
	if err != nil {
		return groupDisplay, count, err
	}

	moduleHash := make(map[int]*model.ModuleGroup)
	for _, module := range modules {
		moduleHash[module.Id] = module
	}

	groupDisplay = make([]*model.LdapGroupDisplay, len(groups))
	for i := range groupDisplay {
		groupDisplay[i] = &model.LdapGroupDisplay{
			ID:   groups[i].ID,
			Role: groups[i].Role,
			Name: groups[i].Name,
		}
		groupModuleIDs := model.GetModuleIDByGroup(groups[i])
		groupDisplay[i].Modules = make([]*model.ModuleGroup, 0, len(groupModuleIDs))
		for _, id := range groupModuleIDs {
			if module := moduleHash[id]; module != nil {
				groupDisplay[i].Modules = append(groupDisplay[i].Modules, module)
			}
		}
	}

	return groupDisplay, count, nil
}

func (api *api) CreateLdapGroup() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()
		if authErr := api.verifyAuthorization(ctx); authErr != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewNoAccess(http.StatusForbidden,
					fmt.Errorf("no acess: %w", authErr)))
			return
		}

		var cliReq model.LdapGroupItem
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		group, modules, err := api.createLdapGroup(ctx, &cliReq)
		if err != nil {
			if err == CheckLdapGroupInterError {
				apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(http.StatusBadRequest, err))
				return
			}
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(model.LdapGroupDisplay{
			ID:      group.ID,
			Name:    group.Name,
			Role:    group.Role,
			Modules: modules,
		}), response.WithTarget(&response.TargetRef{
			Name: group.Name,
			ID:   strconv.Itoa(int(group.ID)),
			Link: "",
		}))
	}
}

func (api *api) createLdapGroup(ctx context.Context, item *model.LdapGroupItem) (*model.LdapGroup, []*model.ModuleGroup, error) {
	var group *model.LdapGroup

	item.Modules = util.FilterDuplicateIntArray(item.Modules)
	modules, err := api.checkLdapGroup(ctx, item.Name, item.Role, item.Modules)
	if err != nil {
		return group, modules, err
	}

	modulesJSONBytes, _ := json.Marshal(item.Modules)
	group = &model.LdapGroup{
		Name:    item.Name,
		Role:    item.Role,
		Modules: string(modulesJSONBytes),
	}

	err = dal.CreateLdapGroup(ctx, api.rdb.Get(), group)

	return group, modules, err
}

func (api *api) truncateLdapGroup(ctx context.Context) error {
	return dal.TruncateLdapGroup(ctx, api.rdb.Get())
}

func (api *api) UpdateLdapGroup() http.HandlerFunc {
	type req struct {
		ID      int32          `json:"id"`
		Name    string         `json:"name"`
		Role    model.RoleType `json:"role"`
		Modules []int          `json:"modules"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()
		if authErr := api.verifyAuthorization(ctx); authErr != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewNoAccess(http.StatusForbidden,
					fmt.Errorf("no acess: %w", authErr)))
			return
		}

		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		exist, err := dal.CheckLdapGroupExists(ctx, api.rdb.GetReadDB(), cliReq.ID)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}
		if !exist {
			apperror.RespAndLog(w, ctx,
				apperror.NewCommonError(http.StatusBadRequest, fmt.Errorf("groupID:%d not exists", cliReq.ID), "组不存在", "group not exists"))
			return
		}

		cliReq.Modules = util.FilterDuplicateIntArray(cliReq.Modules)
		modules, err := api.checkLdapGroup(ctx, cliReq.Name, cliReq.Role, cliReq.Modules)
		if err != nil {
			if err == CheckLdapGroupInterError {
				apperror.RespAndLog(w, ctx, err)
				return
			}
			apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(http.StatusBadRequest, err))
			return
		}

		modulesJSONBytes, _ := json.Marshal(cliReq.Modules)
		group := &model.LdapGroup{
			ID:      cliReq.ID,
			Name:    cliReq.Name,
			Role:    cliReq.Role,
			Modules: string(modulesJSONBytes),
		}

		err = dal.UpdateLdapGroup(ctx, api.rdb.Get(), group)
		if err != nil {
			if util.IsPostgresDuplicateError(err) {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, fmt.Errorf("duplicate name:%s", cliReq.Name), "组名已被占用", "group name occupied"))
				return
			}
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(model.LdapGroupDisplay{
			ID:      group.ID,
			Name:    group.Name,
			Role:    group.Role,
			Modules: modules,
		}), response.WithTarget(&response.TargetRef{
			Name: group.Name,
			ID:   strconv.Itoa(int(group.ID)),
			Link: "",
		}))
	}
}

var (
	CheckLdapGroupInterError = errors.New("checkLdapGroup internal error")
)

func (api *api) checkLdapGroup(ctx context.Context, name string, role model.RoleType, modules []int) ([]*model.ModuleGroup, error) {
	if len(name) == 0 || len(name) > 255 {
		return nil, fmt.Errorf("invalid name:%s", name)
	}

	if role != model.RoleTypeAdmin && role != model.RoleTypeSuperAdmin && role != model.RoleTypeNormal {
		return nil, fmt.Errorf("invalid role:%s", role)
	}

	var moduleGroups []*model.ModuleGroup
	if len(modules) > 0 {
		var err error
		moduleGroups, err = dal.GetModules(ctx, api.rdb.GetReadDB(), modules)
		if err != nil {
			return nil, CheckLdapGroupInterError
		}
		if len(modules) != len(moduleGroups) {
			return nil, fmt.Errorf("invalid module:%s", name)
		}
	}

	return moduleGroups, nil
}

func (api *api) DeleteLdapGroup() http.HandlerFunc {
	type req struct {
		ID int32 `json:"id"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()
		if authErr := api.verifyAuthorization(ctx); authErr != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewNoAccess(http.StatusForbidden,
					fmt.Errorf("no acess: %w", authErr)))
			return
		}

		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		var groupName string
		var groupID int32
		ldapGroup, err := dal.GetLdapGroupByID(ctx, api.rdb.Get(), cliReq.ID)
		if err == nil {
			groupName = ldapGroup.Name
			groupID = ldapGroup.ID
		}
		err = dal.DeleteLdapGroup(ctx, api.rdb.Get(), cliReq.ID)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithTarget(&response.TargetRef{
			Name: groupName,
			ID:   strconv.Itoa(int(groupID)),
			Link: "",
		}))
	}
}
