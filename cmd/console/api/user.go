package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/jwtauth"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/session"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/usercenter"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
)

var (
	ErrNoAccess          = errors.New("access invalid")
	ErrSendEmailFail     = errors.New("send email fail")
	ErrUserAlreadyExists = fmt.Errorf("user already exists")
)

func (api *api) verifyAuthorization(ctx context.Context) error {
	token, claims, err := jwtauth.FromContext(ctx)

	if err != nil {
		return err
	}
	if token == nil || !token.Valid {
		return fmt.Errorf("Token empty or invalid")
	}

	username, _ := claims[JWTKeyUsername].(string)
	userRole, _ := claims[JWTKeyUserRole].(string)
	external, _ := claims[JWTKeyExternal].(bool)

	sessionService, ok := session.GetService()
	if !ok {
		return ErrServiceNotReady
	}

	userSession, err := sessionService.GetUserSession(ctx, api.rdb.GetReadDB(), username, external)
	if err != nil {
		return err
	}

	if userSession.Role == model.RoleNormal {
		return ErrNoAccess
	}

	if userRole == model.RoleAdmin || userRole == model.RoleSuperAdmin {
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
		config, err := dal.GetConfig(r.Context(), api.rdb.GetReadDB(), usercenter.ConfigKey)
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
		err = dal.SetConfig(r.Context(), api.rdb.Get(), usercenter.ConfigKey, configBytes)
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
		err = dal.SetAccountBanStatus(r.Context(), api.rdb.Get(), rq.User, true)
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
		err = dal.SetAccountBanStatus(r.Context(), api.rdb.Get(), rq.User, false)
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
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		rq := reqResetPwd{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if rq.OldPwd == "" || len(rq.Pwd) > 16 || len(rq.Pwd) < 8 || rq.Pwd == "" {
			RespAndLog(w, ctx,
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

		userSession, ok := model.GetSessionFromContext(ctx)
		if !ok {
			RespAndLog(w, ctx, errors.New("unexpected request: no user session"))
			return
		}

		if userSession.External {
			RespAndLog(w, ctx,
				NewCommonError(http.StatusBadRequest,
					errors.New("external user not suppoert resetPassword"),
					"外部用户不支持重置密码", "external user not suppoert resetPassword"))
			return
		}

		ok, _, err = dal.GetUserByPassword(ctx, api.rdb.Get(), userSession.Username, rq.OldPwd)
		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		if !ok {
			RespAndLog(w, ctx,
				NewPasswordNotMatchError(http.StatusBadRequest,
					fmt.Errorf("oldpwd error")))
			return
		}

		err = dal.UpdateUserPwd(ctx, api.rdb.Get(), userSession.Username, rq.Pwd)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
			return
		}

		response.Ok(w, response.WithItem(ResetPwdResponse{
			Success: true,
		}))
	}
}

func (api *api) userList() http.HandlerFunc {

	type UserListResponse struct {
		UserList []model.User `json:"userList"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		offset, limit := api.getOffsetAndLimit(r)

		docNum, userList, err := dal.SelectUserAll(ctx, api.rdb.GetReadDB(), limit, offset)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusInternalServerError,
					fmt.Errorf("database error: %w", err)))
			return
		}

		response.Ok(w,
			response.WithItems(userList),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

func (api *api) userModule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()
		user, ok := model.GetSessionFromContext(ctx)
		if !ok {
			RespAndLog(w, ctx, errors.New("unexpected request: no user info"))
			return
		}
		if user.External {
			mdgroup, err := dal.GetModuleGroup(ctx, api.rdb.GetReadDB(), user.ModuleID)
			if err != nil {
				RespAndLog(w, ctx, err)
			} else {
				response.Ok(w, response.WithItems(mdgroup))
			}
			return
		}

		if user.Username == model.UserSuperAdmin {
			moduleGroup, err := dal.GetAdminModuleGroup(ctx, api.rdb.GetReadDB())
			if err != nil {
				RespAndLog(w, ctx, err)
			} else {
				response.Ok(w, response.WithItems(moduleGroup))
			}
		} else {
			moduleGroup, err := dal.GetModuleGroup(ctx, api.rdb.GetReadDB(), user.ModuleID)
			if err == nil {
				response.Ok(w, response.WithItems(moduleGroup))
			} else {
				RespAndLog(w, ctx, RDBError(500, err))
			}
		}
	}
}

func (api *api) addUser() http.HandlerFunc {
	type reqAddUser struct {
		UserName string   `json:"userName" binding:"required,dive,max=32"`
		RoleName string   `json:"roleName" binding:"required,dive,oneof=admin normal"`
		ModuleID []string `json:"moduleID"`
	}

	type resp struct {
		Status string `json:"status"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var req reqAddUser
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		req.UserName = strings.TrimSpace(req.UserName)

		if req.UserName == "" || len(req.UserName) > 32 || (req.RoleName != model.RoleAdmin && req.RoleName != model.RoleNormal) {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("username or role error")))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		userSession, ok := model.GetSessionFromContext(ctx)
		if !ok {
			RespAndLog(w, r.Context(), errors.New("get user session fail"))
			return
		}

		if userSession.Role == model.RoleNormal {
			RespAndLog(w, r.Context(),
				NewNoAccess(http.StatusForbidden,
					fmt.Errorf("access invalid")))
			return
		}

		if env.GetEmailCheck() && !VerifyEmailFormat(req.UserName) {
			//check mail
			RespAndLog(w, r.Context(),
				EmailForMatError(http.StatusForbidden,
					fmt.Errorf("email format error")))
			return
		}

		err = api.rdb.Get().Transaction(func(tx *gorm.DB) error {
			innerErr := dal.InsertUser(ctx, tx, req.UserName, req.RoleName, req.ModuleID)
			if innerErr != nil {
				if util.IsPostgresDuplicateError(innerErr) {
					return ErrUserAlreadyExists
				}
				return innerErr
			}

			if env.GetEmailCheck() {
				emailHashCode := dal.RandStringBytesMaskImprSrcUnsafe(64)
				innerErr = dal.InsertEmail(ctx, tx, req.UserName, emailHashCode)
				if innerErr != nil {
					return innerErr
				}

				if !SendEmail(req.UserName, r.Host, emailHashCode) {
					return ErrSendEmailFail
				}
				return nil
			}

			return dal.ActiveUser(ctx, tx, req.UserName, model.DefaultPassword)
		})

		if err != nil {
			if err == ErrSendEmailFail {
				RespAndLog(w, ctx, SendmailError(http.StatusInternalServerError, ErrSendEmailFail))
				return
			}

			if err == ErrUserAlreadyExists {
				RespAndLog(w, ctx,
					UserExistError(http.StatusBadRequest, fmt.Errorf("user name already exist")))
				return
			}

			RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItem(resp{Status: "OK"}))
	}
}

func (api *api) editUser() http.HandlerFunc {
	type reqAddUser struct {
		UserName string   `json:"userName" binding:"required,dive,max=32"`
		RoleName string   `json:"roleName" binding:"required,dive,oneof=admin normal"`
		ModuleID []string `json:"moduleID"`
	}

	type resp struct {
		Status string `json:"status"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()
		var cliReq reqAddUser
		err := json.NewDecoder(r.Body).Decode(&cliReq)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		if cliReq.UserName == "" || cliReq.RoleName == "" || len(cliReq.UserName) > 32 || (cliReq.RoleName != model.RoleAdmin && cliReq.RoleName != model.RoleNormal) {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("username or role error")))
			return
		}

		opUser, ok := model.GetSessionFromContext(ctx)
		if !ok {
			RespAndLog(w, ctx, errors.New("unexpected request: no user info"))
			return
		}
		if opUser.Role == model.RoleNormal {
			RespAndLog(w, ctx,
				NewNoAccess(http.StatusForbidden,
					fmt.Errorf("access invalid")))
			return
		}

		exist, queryUser, err := dal.SelectUser(ctx, api.rdb.Get(), cliReq.UserName)
		if err != nil {
			RespAndLog(w, ctx,
				RDBError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}
		if !exist {
			RespAndLog(w, ctx,
				UserNotExistError(http.StatusBadRequest, fmt.Errorf("user name already exist:%+v", err)))
			return
		}
		if queryUser.Rule == model.RoleAdmin && cliReq.RoleName == model.RoleNormal {
			RespAndLog(w, r.Context(),
				NewNoAccess(http.StatusForbidden,
					fmt.Errorf("access invalid")))
			return
		}

		err = dal.UpdateUser(ctx, api.rdb.Get(), cliReq.UserName, cliReq.RoleName, cliReq.ModuleID)
		if err != nil {
			RespAndLog(w, ctx,
				RDBError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}

		sessionService, ok := session.GetService()
		if !ok {
			RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		var findUser *model.User
		ok, findUser, err = dal.SelectUser(ctx, api.rdb.Get(), cliReq.UserName)
		if err != nil || !ok {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("mongo err")))
			return
		}

		if err = sessionService.SaveUserSession(ctx, findUser.GenerateSession(false)); err != nil {
			logging.Get().Warn().Err(err)
		}

		response.Ok(w, response.WithItem(resp{Status: "OK"}))
	}
}

func VerifyEmailFormat(email string) bool {
	pattern := fmt.Sprintf(`\w+([-+.]\w+)*@%s`, env.GetEmailSuffix())
	reg, err := regexp.Compile(pattern)
	if err != nil {
		logging.Get().Err(err).Msgf("verify email compile expr error")
		return false
	}
	return reg.MatchString(email)
}
