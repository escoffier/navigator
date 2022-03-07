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

	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/captcha"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/session"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/ldap"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/radius"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
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

		var conf model.LdapServerConf
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

		err = dal.SetConfig(ctx, api.rdb.Get(), model.LdapConfKey, conf.Encode())
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(conf))
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

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(*conf))
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
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return &model.DefaultLdapServerConf, nil
	}

	var ldapConf model.LdapServerConf
	err = ldapConf.Decode(conf.Config)
	return &ldapConf, err
}

func (api *api) getRadiusConf(ctx context.Context) (*model.RadiusServerConf, error) {
	conf, err := dal.GetConfig(ctx, api.rdb.Get(), model.RadiusConfKey)
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return &model.DefaultRadiusServerConf, nil
	}

	var radiusConf model.RadiusServerConf
	err = radiusConf.Decode(conf.Config)
	return &radiusConf, err
}

func (api *api) GetLoginOption() http.HandlerFunc {
	type rsp struct {
		Options []string `json:"options"`
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

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(rsp{Options: options}))
	}
}

func (api *api) LdapLogin() http.HandlerFunc {
	type req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		CaptchaID    string `json:"captchaID"`
		CaptchaValue string `json:"captchaValue"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()
		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if cliReq.Username == "" || cliReq.Password == "" {
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

		if !captchaService.Verify(cliReq.CaptchaID, cliReq.CaptchaValue) {
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
		group, err := ldap.Login(cliReq.Username, cliReq.Password, ldapConf, tlsConf)
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

		ldapUsername := fmt.Sprintf("%s%s", LdapUsernamePrefix, cliReq.Username)
		api.externalLogin(ctx, w, &externalUserArg{
			username:       ldapUsername,
			originUsername: cliReq.Username,
			accountType:    AccountTypeLdap,
			group:          group,
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
		Username     string `json:"username"`
		Password     string `json:"password"`
		CaptchaID    string `json:"captchaID"`
		CaptchaValue string `json:"captchaValue"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()
		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if cliReq.Username == "" || cliReq.Password == "" {
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

		if !captchaService.Verify(cliReq.CaptchaID, cliReq.CaptchaValue) {
			apperror.RespAndLog(w, ctx,
				apperror.NewCaptchaError(http.StatusBadRequest,
					fmt.Errorf("captcha value error")))
			return
		}

		api.radiusLogin(ctx, w, cliReq.Username, cliReq.Password, "")
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
		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
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

		api.radiusLogin(ctx, w, cliReq.Username, cliReq.Password, cliReq.State)
	}
}

func (api *api) radiusLogin(ctx context.Context, w http.ResponseWriter, username, password, challengeState string) {
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

	nextChallengeState, err := radius.Login(ctx, username, password, challengeState, radiusConf)
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
		}))
		return
	}

	var tlsConf = &tls.Config{}
	if ldapConf.ConnType != model.LdapModeNonTLS {
		tlsConf = api.getLdapTlsConfig(ctx, ldapConf.ServerNameOverride)
	}
	group, err := ldap.GetUserGroup(username, ldapConf, tlsConf)
	if err != nil {
		apperror.RespAndLog(w, ctx,
			apperror.NewCommonError(http.StatusPreconditionFailed, err, "获取ldap组失败", "get ldap group failed"))
		return
	}

	radiusUsername := fmt.Sprintf("%s%s", RadiusUsernamePrefix, username)
	api.externalLogin(ctx, w, &externalUserArg{
		username:       radiusUsername,
		originUsername: username,
		group:          group,
		accountType:    AccountTypeRadius,
	})
}

type externalUserArg struct {
	username       string
	originUsername string
	accountType    string
	group          string
}

func (api *api) externalLogin(ctx context.Context, w http.ResponseWriter, arg *externalUserArg) {
	userSession, err := api.makeUserSessionByGroup(ctx, arg.username, arg.group)
	if err != nil {
		apperror.RespAndLog(w, ctx, err)
		return
	}

	tokenString := api.saveJWTToken(arg.username, userSession.Role)
	sessionService, ok := session.GetService()
	if !ok {
		apperror.RespAndLog(w, ctx, ErrServiceNotReady)
		return
	}

	if err = sessionService.SaveUserSession(ctx, userSession); err != nil {
		apperror.RespAndLog(w, ctx, fmt.Errorf("save user session fail:%w", err))
		return
	}

	response.Ok(w, response.WithItem(LoginResponse{
		CurrentAuthority: arg.originUsername,
		Status:           "ok",
		Type:             arg.accountType,
		Token:            tokenString,
		Role:             userSession.Role,
	}))
}

func (api *api) makeUserSessionByGroup(ctx context.Context, username, group string) (*model.UserSession, error) {
	ldapGroup, err := dal.GetLdapGroupByName(ctx, api.rdb.Get(), group)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			ldapGroup = &model.LdapGroup{Role: model.RoleNormal, Modules: "[]"}
		} else {
			return nil, fmt.Errorf("get ldap group fail, err:%w", err)
		}
	}
	user := &model.UserSession{
		Username: username,
		External: true,
		Checked:  true,
		ModuleID: convertModule(ldapGroup.Modules),
		Role:     ldapGroup.Role,
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
		offset, err := param.QueryUint(r, "offset")
		if err != nil {
			offset = 0
		}

		limit, err := param.QueryUint(r, "limit")
		if err != nil {
			limit = defaultLdapGroupBatchSize
		}
		if limit > maxLdapGroupBatchSize {
			limit = maxLdapGroupBatchSize
		}

		count, err := dal.GetLdapGroupCount(ctx, api.rdb.GetReadDB())
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		groups, err := dal.GetLdapGroupList(ctx, api.rdb.GetReadDB(), int(offset), int(limit))
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		moduleIDs := model.GetModuleIDByGroups(groups)
		modules, err := dal.GetModules(ctx, api.rdb.GetReadDB(), moduleIDs)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		moduleHash := make(map[int]*model.ModuleGroup)
		for _, module := range modules {
			moduleHash[module.Id] = module
		}

		var groupDisplay = make([]*model.LdapGroupDisplay, len(groups))
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

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItems(groupDisplay), response.WithTotalItems(count))
	}
}

func (api *api) CreateLdapGroup() http.HandlerFunc {
	type req struct {
		Name    string `json:"name"`
		Role    string `json:"role"`
		Modules []int  `json:"modules"`
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
			Name:    cliReq.Name,
			Role:    cliReq.Role,
			Modules: string(modulesJSONBytes),
		}

		err = dal.CreateLdapGroup(ctx, api.rdb.Get(), group)
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
		}))
	}
}

func (api *api) UpdateLdapGroup() http.HandlerFunc {
	type req struct {
		ID      int32  `json:"id"`
		Name    string `json:"name"`
		Role    string `json:"role"`
		Modules []int  `json:"modules"`
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
		}))
	}
}

var (
	CheckLdapGroupInterError = errors.New("checkLdapGroup internal error")
)

func (api *api) checkLdapGroup(ctx context.Context, name, role string, modules []int) ([]*model.ModuleGroup, error) {
	if len(name) == 0 || len(name) > 255 {
		return nil, fmt.Errorf("invalid name:%s", name)
	}

	if role != model.RoleAdmin && role != model.RoleSuperAdmin && role != model.RoleNormal {
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

		err = dal.DeleteLdapGroup(ctx, api.rdb.Get(), cliReq.ID)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion))
	}
}
