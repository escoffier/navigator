package api

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/jwtauth"
	param "github.com/oceanicdev/chi-param"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/idp"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/session"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/usercenter"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
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

type loginConfigInfo struct {
	FirstLoginChangePwd bool  `json:"firstLoginChangePwd"` // 首次登录修改密码
	ResetLoginChangePwd bool  `json:"resetLoginChangePwd"` // 管理员重置密码后首次修改密码
	CycleChangePwd      bool  `json:"cycleChangePwd"`      // 周期更换密码
	CycleDay            int   `json:"cycleDay"`            // 最小1天
	RateLimitEnable     bool  `json:"rateLimitEnable"`     // enable  账号锁定机制
	RateLimitThreshold  int32 `json:"rateLimitThreshold"`  // 最小1天
}

func (api *api) getLoginConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		conf, err := dal.GetConfig(ctx, api.rdb.GetReadDB(), model.ConfLogin)
		if err != nil {
			if err != gorm.ErrRecordNotFound {
				RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("get config failed: %w", err)))
				return
			}

			response.Ok(w, response.WithItem(&loginConfigInfo{
				FirstLoginChangePwd: false,
				ResetLoginChangePwd: false,
				CycleChangePwd:      false,
				CycleDay:            90,
				RateLimitEnable:     false,
				RateLimitThreshold:  5,
			}))
			return
		}

		result := loginConfigInfo{}
		if err = json.Unmarshal(conf.Config, &result); err != nil {
			RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError,
				fmt.Errorf("json.Unmarshal: %w", err)))
			return
		}

		response.Ok(w, response.WithItem(&result))
	}
}

func (api *api) updateLoginConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("failed to decode json: %w", err)))
		}

		req := loginConfigInfo{}
		if err = json.Unmarshal(body, &req); err != nil {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if (req.CycleChangePwd && (req.CycleDay < 1 || req.CycleDay > 9999)) ||
			(req.RateLimitEnable && (req.RateLimitThreshold < 1 || req.RateLimitThreshold > 9999)) {
			RespAndLog(w, ctx, NewInvalidArgError(http.StatusBadRequest,
				fmt.Errorf("params error: %v", req)))
			return
		}

		err = api.rdb.Get().Transaction(func(tx *gorm.DB) error {
			if req.RateLimitEnable {
				usercenter.GetLimiter(r.Context()).UpdateThreshold(req.RateLimitThreshold)
				usercenter.GetLimiter(r.Context()).UpdateEnable(req.RateLimitEnable)
			}

			err = dal.SetConfig(ctx, tx, model.ConfLogin, body)
			if err != nil {
				return apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("set config failed: %w", err))
			}

			// 开启【周期更换登录密码】功能，重置所有用户的上次修改密码时间
			if req.CycleChangePwd {
				err = dal.UpdateUserPasswordToNow(ctx, api.rdb.Get())
				if err != nil {
					return apperror.NewAnError(http.StatusInternalServerError,
						fmt.Errorf("reset password failed: %w", err))
				}
			}

			return nil
		})

		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithTarget(&response.TargetRef{
			Name: model.GetUsernameFromContext(ctx),
			ID:   "",
			Link: "",
		}))
	}
}

func checkPwdFormat(pwd string) error {
	if l := len(pwd); l < 8 || l > 16 {
		return fmt.Errorf("the password must contain more than 8 or less than 16 characters")
	}

	var (
		matchCount int
		patterns   = []string{
			"[0-9]+",
			"[a-z]+",
			"[A-Z]+",
			"[~!@#$%^&*\\.]+",
		}
	)

	fn := func(pattern string) {
		m, err := regexp.MatchString(pattern, pwd)
		if err != nil {
			logging.Get().Error().Err(err).Msg(pattern)
			return
		}

		if m {
			matchCount++
		}
	}

	for _, pattern := range patterns {
		fn(pattern)
	}

	if matchCount < 2 {
		return fmt.Errorf("contains at least letters, digits, and special characters(~!@$%%^&*.). two kinds of combination")
	}

	return nil
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

		if rq.OldPwd == rq.Pwd {
			RespAndLog(w, ctx,
				NewPasswordSameWithOldError(http.StatusBadRequest,
					fmt.Errorf("unexpected request: new password same with old password")))
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

func (api *api) userEnable() http.HandlerFunc {
	type userEnableReq struct {
		Username string `json:"username"`
		Enable   bool   `json:"enable"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		user, ok := model.GetSessionFromContext(ctx)
		if !ok || (user.Role != model.RoleSuperAdmin && user.Role != model.RoleAdmin) {
			apperror.RespAndLog(w, ctx,
				apperror.NewNoAccess(http.StatusForbidden,
					fmt.Errorf("no access, role: %s", user.Role)))
			return
		}

		req := userEnableReq{}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if req.Username == "" {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("params illegal")))
			return
		}

		status := model.UserStatusNormal
		oldStatus := model.UserStatusDisabled
		if !req.Enable {
			status = model.UserStatusDisabled
			oldStatus = model.UserStatusNormal
		}
		err = api.rdb.Get().WithContext(ctx).Model(&model.User{}).
			Where("username = ? AND status = ?", req.Username, oldStatus).
			UpdateColumn("status", status).Error
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("database err: %w", err)))
		}

		response.Ok(w, response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%v", req.Username, req.Enable),
			ID:   "",
			Link: "",
		}))
	}
}

func (api *api) deleteUser() http.HandlerFunc {
	type deleteUserReq struct {
		Username string `json:"username"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		user, ok := model.GetSessionFromContext(ctx)
		if !ok || (user.Role != model.RoleSuperAdmin && user.Role != model.RoleAdmin) {
			apperror.RespAndLog(w, ctx,
				apperror.NewNoAccess(http.StatusForbidden,
					fmt.Errorf("no access, role: %s", user.Role)))
			return
		}

		req := deleteUserReq{}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if req.Username == "" {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("params illegal")))
			return
		}

		if req.Username == user.Username {
			RespAndLog(w, ctx, NewCommonError(http.StatusBadRequest,
				errors.New("delete failed. the user cannot delete itself"),
				"删除失败，不允许用户删除自身", "delete failed. the user cannot delete itself"))
			return
		}

		err = api.rdb.Get().WithContext(ctx).
			Where("username = ?", req.Username).
			Delete(&model.User{}).Error

		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("database err: %w", err)))
		}

		response.Ok(w, response.WithTarget(&response.TargetRef{
			Name: req.Username,
			ID:   "",
			Link: "",
		}))
	}
}

func (api *api) adminResetPwd() http.HandlerFunc {
	type adminResetPwdReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	type adminResetPwdResp struct {
		Password string `json:"password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		user, ok := model.GetSessionFromContext(ctx)
		if !ok || user.Role != model.RoleSuperAdmin {
			apperror.RespAndLog(w, ctx,
				apperror.NewNoAccess(http.StatusForbidden,
					fmt.Errorf("no access, role: %s", user.Role)))
			return
		}

		req := adminResetPwdReq{}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if req.Username == "" || req.Password == "" {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("params illegal")))
			return
		}

		found, u, err := dal.SelectUser(ctx, api.rdb.GetReadDB(), req.Username)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("database err: %w", err)))
			return
		}
		if !found {
			RespAndLog(w, ctx, UserNotExistError(http.StatusBadRequest, nil))
			return
		}

		ok, _, _ = dal.GetUserByPassword(ctx, api.rdb.GetReadDB(), user.Username, req.Password)
		if !ok {
			RespAndLog(w, ctx, NewCommonError(http.StatusBadRequest,
				errors.New("password error, authentication failed"),
				"密码错误，身份验证失败", "password error, authentication failed"))
			return
		}

		pwd, _ := util.RandPassword(16)
		updated := map[string]interface{}{
			"pwd":                fmt.Sprintf("%x", md5.Sum([]byte(pwd+u.Salt))),
			"last_change_pwd_at": time.Now().UnixMilli(),
		}
		// 自动解除账号锁定状态
		if u.Status == model.UserStatusLock {
			updated["status"] = model.UserStatusNormal
		}

		// 管理员重置密码后是否需要修改密码
		conf, err := dal.GetConfig(ctx, api.rdb.GetReadDB(), model.ConfLogin)
		if err != nil {
			if err != gorm.ErrRecordNotFound {
				logging.Get().Error().Err(err).Msg("")
				RespAndLog(w, ctx, err)
				return
			}
		} else {
			loginConf := loginConfigInfo{}
			if err = json.Unmarshal(conf.Config, &loginConf); err != nil {
				logging.Get().Error().Err(err).Msg("")
				RespAndLog(w, ctx, err)
				return
			}
			if loginConf.ResetLoginChangePwd {
				updated["must_change_pwd"] = true
			}
		}

		err = api.rdb.Get().WithContext(ctx).Model(&model.User{}).
			Where("username = ? ", req.Username).
			UpdateColumns(updated).Error
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("database err: %w", err)))
			return
		}

		response.Ok(w, response.WithItem(&adminResetPwdResp{
			Password: pwd,
		}), response.WithTarget(&response.TargetRef{
			Name: req.Username,
			ID:   "",
			Link: "",
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
		keyword, err := param.QueryString(r, "keyword")
		role, err := param.QueryString(r, "role")
		roles := strings.Split(role, ",")
		if len(role) == 0 {
			roles = []string{}
		}
		status, err := param.QueryString(r, "status")
		statusesStr := strings.Split(status, ",")
		if len(status) == 0 {
			statusesStr = []string{}
		}
		statuses := make([]int, 0)
		for i := range statusesStr {
			s, err := strconv.Atoi(statusesStr[i])
			if err != nil {
				continue
			}
			statuses = append(statuses, s)
		}
		moduleGroup, err := param.QueryString(r, "module_group")
		modules := strings.Split(moduleGroup, ",")
		if len(moduleGroup) == 0 {
			modules = []string{}
		}

		docNum, userList, err := dal.SelectUserAll(ctx, api.rdb.GetReadDB(), keyword, roles, statuses, modules, limit, offset)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusInternalServerError,
					fmt.Errorf("database error: %w", err)))
			return
		}

		response.Ok(w,
			response.WithItems(userList),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(int64(limit)),
			response.WithStartIndex(int64(offset)))
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

		if len(req.UserName) > 50 {
			RespAndLog(w, r.Context(),
				UserNameTooLongError(http.StatusBadRequest,
					fmt.Errorf("username too long")))
			return
		}

		if req.UserName == "" || (req.RoleName != model.RoleAdmin && req.RoleName != model.RoleNormal) {
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
			// check mail
			RespAndLog(w, r.Context(),
				EmailForMatError(http.StatusForbidden,
					fmt.Errorf("email format error")))
			return
		}

		// 首次登录是否需要修改密码
		loginConf := loginConfigInfo{}
		conf, err := dal.GetConfig(ctx, api.rdb.GetReadDB(), model.ConfLogin)
		if err != nil {
			if err != gorm.ErrRecordNotFound {
				logging.Get().Error().Err(err).Msg("")
				RespAndLog(w, ctx, err)
				return
			}
		} else {
			if err = json.Unmarshal(conf.Config, &loginConf); err != nil {
				logging.Get().Error().Err(err).Msg("")
				RespAndLog(w, ctx, err)
				return
			}
		}

		err = api.rdb.Get().Transaction(func(tx *gorm.DB) error {
			innerErr := dal.InsertUser(ctx, tx, req.UserName, req.RoleName, req.ModuleID, loginConf.FirstLoginChangePwd)
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

			_, innerErr = dal.ActiveUser(ctx, tx, req.UserName, model.DefaultPassword, loginConf.FirstLoginChangePwd)
			return innerErr
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
		if queryUser.Role == model.RoleAdmin && cliReq.RoleName == model.RoleNormal {
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

// superAdminInit init super admin account
func (a *api) superAdminInit() http.HandlerFunc {
	type superAdminInitReq struct {
		Pwd string `json:"pwd"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		req := superAdminInitReq{}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		// password strength check
		if err = checkPwdFormat(req.Pwd); err != nil {
			RespAndLog(w, r.Context(),
				NewPwdStrengthError(http.StatusBadRequest, err))
			return
		}

		has, err := dal.HasUser(ctx, a.rdb.GetReadDB())
		if err != nil {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}

		// not found user, it's first login
		// found user, this interface cannot be called
		if has {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewNoAccess(http.StatusBadRequest,
					fmt.Errorf("this interface cannot be called")))
			return
		}

		err = dal.CreateSuperAdmin(ctx, a.rdb.Get(), req.Pwd)
		if err != nil {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("create super admin failed: %w", err)))
			return
		}

		response.Ok(w)
	}
}

// updateIdpConfig update/set idp login config
func (a *api) updateIdpConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("failed to decode json: %w", err)))
		}

		req := idp.LoginConfig{}
		if err := json.Unmarshal(body, &req); err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if req.Enabled && (req.DiscoveryEndpoint == "" || req.ClientSecret == "" || req.ClientID == "") {
			RespAndLog(w, r.Context(),
				NewInvalidArgError(http.StatusBadRequest, fmt.Errorf("params error: %v", req)))
			return
		}

		// 默认一些参数
		if req.Platform = os.Getenv(idp.EnvIdpPlatform); req.Platform == "" {
			req.Platform = idp.DxPlatform
		}
		req.IdpProvider = idp.ProviderOIDC
		req.Scopes = "openid+profile+email"
		body, _ = json.Marshal(req)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		err = a.rdb.Get().Transaction(func(tx *gorm.DB) error {
			if err = idp.NewProviderAndRegister(&req, a.redisClient); err != nil {
				return apperror.NewCommonError(http.StatusBadRequest,
					fmt.Errorf("update idp config error: %w", err),
					"更新idp配置错误", "update idp config error")
			}

			if err = dal.SetConfig(ctx, tx, model.ConfIdpLogin, body); err != nil {
				return apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("set config failed: %w", err))
			}

			return nil
		})
		if err != nil {
			apperror.RespAndLog(w, r.Context(), err)
			return
		}

		response.Ok(w, response.WithTarget(&response.TargetRef{
			Name: model.GetUsernameFromContext(ctx),
			ID:   "",
			Link: "",
		}))
	}
}

func (a *api) getIdpConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		conf, err := dal.GetConfig(ctx, a.rdb.GetReadDB(), model.ConfIdpLogin)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				moduleGroup, err := dal.GetAdminModuleGroup(ctx, a.rdb.GetReadDB())
				if err != nil {
					RespAndLog(w, ctx, err)
					return
				}

				response.Ok(w, response.WithItem(idp.LoginConfig{
					Enabled:           false,
					DefaultAuth:       moduleGroup,
					PermissionMapping: []idp.SsoPermissionMappingItem{},
				}))
				return
			}
		}

		resp := idp.LoginConfig{}
		if err = json.Unmarshal(conf.Config, &resp); err != nil {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("unmarshal json failed: %w", err)))
			return
		}

		modules, err := dal.GetAllModules(ctx, a.rdb.GetReadDB())
		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		modulesSet := map[int]*model.ModuleGroup{}
		for i, v := range modules {
			modulesSet[v.Id] = modules[i]
		}

		for i, v := range resp.DefaultAuth {
			if m, ok := modulesSet[v.Id]; ok {
				resp.DefaultAuth[i] = *m
			}
		}

		for i, p := range resp.PermissionMapping {
			for j, v := range p.Auth {
				if m, ok := modulesSet[v.Id]; ok {
					resp.PermissionMapping[i].Auth[j] = *m
				}
			}
		}

		response.Ok(w, response.WithItem(resp))
	}
}
