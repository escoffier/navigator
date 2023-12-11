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
	"unicode"

	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/session"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/idp"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/usercenter"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
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
	user, ok := request.GetSessionFromContext(ctx)
	if !ok || (user.Role != model.RoleTypeSuperAdmin && user.Role != model.RoleTypePlatformAdmin) {
		return ErrNoAccess
	}

	return nil
}

const (
	VerySTRONG = "VerySTRONG" // 80分及以上 ,非常强
	STRONG     = "STRONG"     // 60-79分，强
	AVERAGE    = "AVERAGE"    // 50-59分，一般
	WEEK       = "WEEK"       // 0-49分，弱
)

type loginConfigInfo struct {
	FirstLoginChangePwd bool     `json:"firstLoginChangePwd"` // 首次登录修改密码
	ResetLoginChangePwd bool     `json:"resetLoginChangePwd"` // 管理员重置密码后首次修改密码
	CycleChangePwd      bool     `json:"cycleChangePwd"`      // 周期更换密码
	CycleDay            int      `json:"cycleDay"`            // 最小1天
	RateLimitEnable     bool     `json:"rateLimitEnable"`     // enable  账号锁定机制
	RateLimitThreshold  int32    `json:"rateLimitThreshold"`  // 最小1天
	MfaVerityLogin      bool     `json:"mfaVerityLogin"`      // 登录时，mfa认证开启
	PwdSecurityLevel    string   `json:"PwdSecurityLevel"`    // 密码强度，修改密码时使用 ，分为 非常强，强，易班，弱
	IPBlackList         []string `json:"iPBlackList"`         // ip黑名单
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
				MfaVerityLogin:      false,
				PwdSecurityLevel:    STRONG,
				IPBlackList:         nil,
			}))
			return
		}

		result := loginConfigInfo{}
		if err = json.Unmarshal(conf.Config, &result); err != nil {
			RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError,
				fmt.Errorf("json.Unmarshal: %w", err)))
			return
		}
		if result.PwdSecurityLevel == "" {
			result.PwdSecurityLevel = STRONG
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

			// save in mysql
			err = dal.SetConfig(ctx, tx, model.ConfLogin, body)
			if err != nil {
				return apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("set config failed: %w", err))
			}

			sessionService, ok := session.GetService()
			if !ok {
				return ErrServiceNotReady
			}
			// 删除redis中的信息
			if err = sessionService.DelLoginConf(ctx); err != nil {
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("delete loginConf failed: %w", err))
			}

			// 开启【周期更换登录密码】功能，重置所有用户的上次修改密码时间
			if req.CycleChangePwd {
				err = dal.UpdateUserPasswordToNow(ctx, api.rdb.Get())
				if err != nil {
					return apperror.NewAnError(http.StatusInternalServerError,
						fmt.Errorf("reset password failed: %w", err))
				}
			}

			// 关闭mfa认证的时候，需要将所有用户的密钥字段数据删除
			if !req.MfaVerityLogin {
				err = dal.DeleteUserMfaSecret(ctx, api.rdb.Get())
				if err != nil {
					return apperror.NewAnError(http.StatusInternalServerError,
						fmt.Errorf("delete mfasecret failed: %w", err))
				}
			}

			// 删除redis中黑名单信息
			if err = sessionService.DelBlackList(ctx); err != nil {
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("delete ipBlackList failed: %w", err))
			}
			return nil
		})

		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithTarget(&response.TargetRef{
			Name: request.GetUsernameFromContext(ctx),
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

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		userSession, ok := request.GetSessionFromContext(ctx)
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

		rq := reqResetPwd{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if rq.OldPwd == "" || rq.Pwd == "" {
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

		loginConf, err := getLoginConf(ctx, api.rdb)
		if err != nil {
			RespAndLog(w, ctx,
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("query login conf fails")))
			return
		}

		if !checkPWD(rq.Pwd, loginConf.PwdSecurityLevel) {
			RespAndLog(w, ctx,
				NewPwdSecurityLevelError(http.StatusBadRequest,
					fmt.Errorf("the password strength is not up to standard")))
			return
		}

		ok, _, err = dal.GetUserByAccountPwd(ctx, api.rdb.Get(), userSession.Account, rq.OldPwd)
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

		response.Ok(w)
	}
}

func (api *api) userEnable() http.HandlerFunc {
	type userEnableReq struct {
		Usernames []string `json:"usernames"`
		Enable    bool     `json:"enable"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		user, ok := request.GetSessionFromContext(ctx)
		if !ok || (user.Role != model.RoleTypeSuperAdmin && user.Role != model.RoleTypePlatformAdmin) {
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

		if len(req.Usernames) == 0 {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("params illegal")))
			return
		}

		users, err := dal.FindUserList(ctx, api.rdb.GetReadDB(), req.Usernames)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest, err))
			return
		}

		accounts := make([]string, 0)
		for _, u := range users {
			accounts = append(accounts, u.Account)
			if u.Role == model.SuperAdminUsername {
				RespAndLog(w, ctx, NewCommonError(http.StatusBadRequest,
					errors.New("superadmin user is not allowed"),
					"不允许操作超级管理员用户", "superadmin user is not allowed"))
				return
			}
		}

		status := model.UserStatusNormal
		oldStatus := model.UserStatusDisabled
		if !req.Enable {
			status = model.UserStatusDisabled
			oldStatus = model.UserStatusNormal
		}
		err = api.rdb.Get().WithContext(ctx).Model(&model.User{}).
			Where("username IN ? AND status = ?", req.Usernames, oldStatus).
			UpdateColumn("status", status).Error
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("database err: %w", err)))
		}

		response.Ok(w, response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("%s/%v", strings.Join(accounts, ","), req.Enable),
			ID:   "",
			Link: "",
		}))
	}
}

func (api *api) deleteUser() http.HandlerFunc {
	type deleteUserReq struct {
		Usernames []string `json:"usernames"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		user, ok := request.GetSessionFromContext(ctx)
		if !ok || (user.Role != model.RoleTypeSuperAdmin && user.Role != model.RoleTypePlatformAdmin) {
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

		if len(req.Usernames) == 0 {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("params illegal")))
			return
		}

		if util.ContainsString(req.Usernames, user.Username) {
			RespAndLog(w, ctx, NewCommonError(http.StatusBadRequest,
				errors.New("delete failed. the user cannot delete itself"),
				"删除失败，不允许用户删除自身", "delete failed. the user cannot delete itself"))
			return
		}

		users, err := dal.FindUserList(ctx, api.rdb.GetReadDB(), req.Usernames)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest, err))
			return
		}

		accounts := make([]string, 0)
		for _, u := range users {
			accounts = append(accounts, u.Account)
			if u.Role == model.SuperAdminUsername {
				RespAndLog(w, ctx, NewCommonError(http.StatusBadRequest,
					errors.New("failed to delete, superadmin user is not allowed"),
					"不允许删除超级管理员用户", "superadmin user is not allowed"))
				return
			}
		}

		err = api.rdb.Get().WithContext(ctx).
			Where("username IN ?", req.Usernames).
			Delete(&model.User{}).Error
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("database err: %w", err)))
			return
		}

		response.Ok(w, response.WithTarget(&response.TargetRef{
			Name: strings.Join(accounts, ","),
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

		user, ok := request.GetSessionFromContext(ctx)
		if !ok || (user.Role != model.RoleTypeSuperAdmin && user.Role != model.RoleTypePlatformAdmin) {
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

		ok, _, _ = dal.GetUserByAccountPwd(ctx, api.rdb.GetReadDB(), user.Account, req.Password)
		if !ok {
			RespAndLog(w, ctx, NewCommonError(http.StatusBadRequest,
				fmt.Errorf("password error, authentication failed: %s, %s", u.Account, req.Password),
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

		limiter := usercenter.GetLimiter(ctx)
		limiter.LoginSuccessClean(req.Username)

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
	type userListItem struct {
		UserName        string          `json:"userName"` // index
		Account         string          `json:"account"`
		Role            model.RoleType  `json:"role"` // typo; role
		ModuleId        json.RawMessage `json:"module_id"`
		CreatedAt       int64           `json:"create_at"`
		Creator         string          `json:"creator"`
		Platform        string          `json:"platform"`
		Status          int             `json:"status"`
		MustChangePwd   bool            `json:"mustChangePwd"`   // 该用户是否必须修改密码
		LastChangePwdAt int64           `json:"lastChangePwdAt"` // 上次修改密码的时间
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

		items := make([]userListItem, len(userList))
		for i, v := range userList {
			items[i].UserName = v.UserName
			items[i].Account = v.Account
			items[i].Role = v.Role
			items[i].CreatedAt = v.CreatedAt
			items[i].Creator = v.Creator
			items[i].Platform = v.Platform
			items[i].Status = v.Status
			items[i].MustChangePwd = v.MustChangePwd
			items[i].LastChangePwdAt = v.LastChangePwdAt

			if v.ModuleID == "" {
				items[i].ModuleId = json.RawMessage("[]")
			} else {
				items[i].ModuleId = json.RawMessage(v.ModuleID)
			}
		}

		response.Ok(w,
			response.WithItems(items),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(int64(limit)),
			response.WithStartIndex(int64(offset)))
	}
}

func (api *api) getProfile() http.HandlerFunc {
	type getProfileResp struct {
		Username  string          `json:"username"`
		Account   string          `json:"account"`
		Role      model.RoleType  `json:"role"`
		ModuleId  json.RawMessage `json:"module_id"`
		CreatedAt int64           `json:"create_at"`
		Platform  string          `json:"platform"`
		Status    int             `json:"status"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()
		username := request.GetUsernameFromContext(ctx)

		if username == "" {
			RespAndLog(w, ctx, NewInvalidAuthToken(http.StatusUnauthorized, fmt.Errorf("username is empty")))
			return
		}

		has, u, err := dal.SelectUser(ctx, api.rdb.GetReadDB(), username)
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			RespAndLog(w, ctx, err)
			return
		}

		if !has {
			RespAndLog(w, ctx, NewInvalidAuthToken(http.StatusUnauthorized, fmt.Errorf("username is not found")))
			return
		}

		if u.Status != model.UserStatusNormal {
			u.ModuleID = "[]"
		}

		response.Ok(w, response.WithItem(&getProfileResp{
			Username:  u.UserName,
			Account:   u.Account,
			Role:      u.Role,
			ModuleId:  json.RawMessage(u.ModuleID),
			CreatedAt: u.CreatedAt,
			Platform:  u.Platform,
			Status:    u.Status,
		}))
	}
}

func (api *api) addUser() http.HandlerFunc {
	type reqAddUser struct {
		Account  string         `json:"account" binding:"required,dive,max=32"`
		Role     model.RoleType `json:"role" binding:"required,dive,oneof=admin normal"`
		ModuleID []string       `json:"moduleID"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		userInfo, ok := request.GetSessionFromContext(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx,
				apperror.NewNoAccess(http.StatusForbidden, ErrNoAccess))
			return
		}

		var req reqAddUser
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		req.Account = strings.TrimSpace(req.Account)

		if len(req.Account) > 50 {
			RespAndLog(w, r.Context(),
				UserNameTooLongError(http.StatusBadRequest,
					fmt.Errorf("username too long")))
			return
		}

		if req.Role == model.RoleTypeSuperAdmin ||
			(userInfo.Role != model.RoleTypeSuperAdmin &&
				userInfo.Role != model.RoleTypePlatformAdmin) {
			RespAndLog(w, r.Context(),
				NewNoAccess(http.StatusForbidden, ErrNoAccess))
			return
		}

		if req.Account == "" {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("username or role error")))
			return
		}

		if env.GetEmailCheck() && !VerifyEmailFormat(req.Account) {
			// check mail
			RespAndLog(w, r.Context(),
				EmailForMatError(http.StatusBadRequest,
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
			newu, innerErr := dal.InsertInactiveUser(ctx, tx, req.Account, req.Role, req.ModuleID, loginConf.FirstLoginChangePwd, userInfo.Username)
			if innerErr != nil {
				if util.IsPostgresDuplicateError(innerErr) {
					return ErrUserAlreadyExists
				}
				return innerErr
			}

			if env.GetEmailCheck() {
				emailHashCode := dal.RandStringBytesMaskImprSrcUnsafe(64)
				innerErr = dal.InsertEmail(ctx, tx, newu.UserName, emailHashCode)
				if innerErr != nil {
					return innerErr
				}

				if !SendEmail(newu.Account, r.Host, emailHashCode) {
					return ErrSendEmailFail
				}
				return nil
			}

			_, innerErr = dal.ActiveUser(ctx, tx, newu.UserName, model.DefaultPassword, loginConf.FirstLoginChangePwd)
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

		response.Ok(w, response.WithTarget(&response.TargetRef{
			Name: req.Account,
			ID:   "",
			Link: "",
		}))
	}
}

func (api *api) editUser() http.HandlerFunc {
	type reqAddUser struct {
		UserName string   `json:"userName" binding:"required,dive,max=32"`
		Account  string   `json:"account"`
		ModuleID []string `json:"moduleID"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		userInfo, ok := request.GetSessionFromContext(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx,
				apperror.NewNoAccess(http.StatusForbidden, ErrNoAccess))
			return
		}

		var req reqAddUser
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		req.Account = strings.TrimSpace(req.Account)

		if len(req.Account) > 50 {
			RespAndLog(w, r.Context(),
				UserNameTooLongError(http.StatusBadRequest,
					fmt.Errorf("username too long")))
			return
		}

		if userInfo.Role != model.RoleTypeSuperAdmin &&
			userInfo.Role != model.RoleTypePlatformAdmin {
			RespAndLog(w, r.Context(),
				NewNoAccess(http.StatusForbidden, ErrNoAccess))
			return
		}

		ok, findUser, _ := dal.SelectUserByAccount(ctx, api.rdb.GetReadDB(), req.Account)
		if ok && findUser.UserName != req.UserName {
			RespAndLog(w, ctx,
				UserExistError(http.StatusBadRequest, fmt.Errorf("user name already exist")))
			return
		}

		err = dal.UpdateUser(ctx, api.rdb.Get(), req.UserName, req.Account, req.ModuleID)
		if err != nil {
			RespAndLog(w, ctx,
				RDBError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}

		response.Ok(w, response.WithTarget(&response.TargetRef{
			Name: req.UserName,
			ID:   "",
			Link: "",
		}))
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
		Account string `json:"account"`
		Pwd     string `json:"pwd"`
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

		if req.Account == "" {
			req.Account = model.SuperAdminUsername
		}

		// password strength check
		if !checkPWD(req.Pwd, STRONG) {
			RespAndLog(w, ctx,
				NewPwdSecurityLevelError(http.StatusBadRequest,
					fmt.Errorf("the password strength is not up to standard")))
			return
		}

		has, err := dal.HasSuperadminUser(ctx, a.rdb.GetReadDB())
		if err != nil {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}

		// not found user, it's first login
		// found super admin user, this interface cannot be called
		if has {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewNoAccess(http.StatusBadRequest,
					fmt.Errorf("this interface cannot be called")))
			return
		}

		err = dal.CreateSuperAdmin(ctx, a.rdb.Get(), req.Account, req.Pwd)
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
			Name: request.GetUsernameFromContext(ctx),
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

func (api *api) adminResetMfaSecret() http.HandlerFunc {
	type adminResetMfaSecret struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	type adminResetMfaSecretResp struct {
		Status string `json:"status"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		user, ok := request.GetSessionFromContext(ctx)
		if !ok || (user.Role != model.RoleTypeSuperAdmin && user.Role != model.RoleTypePlatformAdmin) {
			apperror.RespAndLog(w, ctx,
				apperror.NewNoAccess(http.StatusForbidden,
					fmt.Errorf("no access, role: %s", user.Role)))
			return
		}

		req := adminResetMfaSecret{}
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

		ok, _, _ = dal.GetUserByAccountPwd(ctx, api.rdb.GetReadDB(), user.Account, req.Password)
		if !ok {
			RespAndLog(w, ctx, NewCommonError(http.StatusBadRequest,
				fmt.Errorf("password error, authentication failed: %s, %s", u.Account, req.Password),
				"密码错误，身份验证失败", "password error, authentication failed"))
			return
		}

		update := map[string]interface{}{
			"mfa_secret": "",
			"MfaStatus":  false,
		}

		err = api.rdb.Get().WithContext(ctx).Model(&model.User{}).Where("username = ?", req.Username).
			Updates(update).Error
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("database err: %w", err)))
			return
		}
		response.Ok(w, response.WithItem(&adminResetMfaSecretResp{
			Status: "成功重置用户的mfa密钥",
		}), response.WithTarget(&response.TargetRef{
			Name: user.Account,
			ID:   "",
			Link: "",
		}))
	}
}

// PWD Strength
type Strategy struct {
	Sum       int  `json:"sum"`
	IsDigit   bool `json:"is_digit"`   // 是否包含数字
	IsUpper   bool `json:"is_upper"`   // 是否包含大写字母
	IsLower   bool `json:"is_lower"`   // 是否包含小写字母
	IsSpecial bool `json:"is_special"` // 是否包含特殊符号
}

func (strategy *Strategy) checkLength(s string) {
	data := []rune(s)
	if len(data) <= 4 {
		strategy.Sum += 0
	} else if len(data) <= 8 {
		strategy.Sum += 10
	} else {
		strategy.Sum += 20
	}
}

func (strategy *Strategy) checkLetters(s string) {
	var count1, count2 int
	for _, s := range s {
		if 'a' <= s && s <= 'z' {
			count1++
		}
		if 'A' <= s && s <= 'Z' {
			count2++
		}
	}

	if count1 == 0 && count2 == 0 {
		strategy.Sum += 0
		return
	}
	if count1 != 0 && count2 != 0 {
		strategy.IsUpper, strategy.IsLower = true, true
		strategy.Sum += 20
		return
	}
	strategy.IsLower = true
	strategy.Sum += 10
	return
}
func (strategy *Strategy) checkNumbers(s string) {
	var count int
	for _, s := range s {
		if '0' <= s && s <= '9' {
			count++
		}
	}
	if count == 0 {
		strategy.Sum += 0
	} else if count <= 2 {
		strategy.IsDigit = true
		strategy.Sum += 10
	} else {
		strategy.IsDigit = true
		strategy.Sum += 15
	}
}

func (strategy *Strategy) checkRepeat(s string) {
	m := make(map[rune]bool)
	for _, r := range s {
		if m[r] {
			strategy.Sum += 5
			return
		}
		m[r] = true
	}
	strategy.Sum += 10
	return
}

func (strategy *Strategy) checkSpecialCharacter(s string) {
	var count int
	for _, i := range s {
		if unicode.IsSymbol(i) || unicode.IsPunct(i) {
			count++
		}
	}
	if count == 0 {
		strategy.Sum += 0
		return
	} else if count == 1 {
		strategy.IsSpecial = true
		strategy.Sum += 10
		return
	} else {
		strategy.IsSpecial = true
		strategy.Sum += 20
		return
	}
}
func checkBody(s string) int {
	strategy := &Strategy{}
	strategy.checkLength(s)
	strategy.checkLetters(s)
	strategy.checkNumbers(s)
	strategy.checkSpecialCharacter(s)
	strategy.checkRepeat(s)

	if strategy.IsLower && strategy.IsUpper && strategy.IsDigit && strategy.IsSpecial {
		strategy.Sum += 15
	} else if strategy.IsDigit && strategy.IsSpecial && strategy.IsLower {
		strategy.Sum += 10
	} else if strategy.IsDigit && strategy.IsLower {
		strategy.Sum += 5
	} else {
		strategy.Sum += 0
	}
	return strategy.Sum
}

func checkPWD(pwd, pwdSecurityLevel string) bool {
	score := checkBody(pwd)
	if pwdSecurityLevel == "" {
		pwdSecurityLevel = STRONG
	}
	switch pwdSecurityLevel {
	case VerySTRONG:
		if score < 80 {
			return false
		}
	case AVERAGE:
		if score < 50 {
			return false
		}
	case WEEK:
		if score < 0 {
			return false
		}
	case STRONG:
		fallthrough
	default:
		if score < 60 {
			return false
		}
	}
	return true
}
