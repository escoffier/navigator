package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/jwtauth"
	"github.com/patrickmn/go-cache"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/usercenter"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

var (
	ErrNoAccess = errors.New("access invalid")
	ErrSendEmailFail = errors.New("send email fail")
)

func (api *api) verifyAuthorization(ctx context.Context) error {
	token, claims, err := jwtauth.FromContext(ctx)

	if err != nil {
		return err
	}
	if token == nil || !token.Valid {
		return fmt.Errorf("Token empty or invalid")
	}

	username, _ := claims[JWT_KEY_USERNAME].(string)
	userRole, _ := claims[JWT_KEY_USERROLE].(string)

	userPtr, ok := api.userCache.Get(username)
	if !ok {
		testWithLogJson("jwt-jwtAccessCheck()", "user get error")
		return fmt.Errorf("User not in cache")
	}

	u, _ := userPtr.(*model.User)
	if u.Rule == model.RoleNormal {
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
		config, err := dal.GetConfig(r.Context(), api.postgresDB, usercenter.ConfigKey)
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
		err = dal.SetConfig(r.Context(), api.postgresDB, usercenter.ConfigKey, configBytes)
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
		err = dal.SetAccountBanStatus(r.Context(), api.postgresDB, rq.User, true)
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
		err = dal.SetAccountBanStatus(r.Context(), api.postgresDB, rq.User, false)
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
		rq := reqResetPwd{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if rq.OldPwd == "" || len(rq.Pwd) > 16 || len(rq.Pwd) < 8 || rq.Pwd == "" {
			RespAndLog(w, r.Context(),
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

		user := r.Context().Value(userKey).(*model.User)

		if dal.GetSaltedPwd(rq.OldPwd, user.Salt) != user.Pwd {
			RespAndLog(w, r.Context(),
				NewPasswordNotMatchError(http.StatusBadRequest,
					fmt.Errorf("oldpwd error")))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		err = dal.UpdateUserPwd(ctx, api.postgresDB, user.UserName, rq.Pwd)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
			return
		}

		userPtr, ok := api.userCache.Get(user.UserName)
		if !ok {
			testWithLogJson("jwt-jwtAccessCheck()", "user get error")
			RespAndLog(w, r.Context(),
				NewSessionExpired(http.StatusUnauthorized,
					fmt.Errorf("User not in cache")))
			return
		}

		u, _ := userPtr.(*model.User)
		api.userCache.Set(user.UserName, u, cache.DefaultExpiration)

		response.Ok(w, response.WithItem(ResetPwdResponse{
			Success: true,
		}))
	}
}

func (api *api) loadUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		u, err := dal.GetUserByMongo(ctx, api.mongodb.Get())
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
			return
		}
		for _, v := range u {
			bool, _, _ := dal.SelectUser(ctx, api.postgresDB, v.UserName)
			if !bool {
				err := dal.InsertUser(ctx, api.postgresDB, v.UserName, model.RoleNormal, []string{"1"})
				if err != nil {
					RespAndLog(w, ctx,
						PostgresError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
					return
				}

				err = dal.ActiveUser(ctx, api.postgresDB, v.UserName, v.Pwd)
				if err != nil {
					RespAndLog(w, ctx,
						PostgresError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
					return
				}
			}

		}

		response.Ok(w, response.WithItem(resp{
			Status: "OK",
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

		docNum, userList, err := dal.SelectUserAll(ctx, api.postgresDB, limit, offset)
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
		token, claims, err := jwtauth.FromContext(r.Context())

		if err != nil {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("Error when getting token & claims from context: %w", err)))
			return
		}
		if token == nil || !token.Valid {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("Token empty or invalid")))
			return
		}

		username, _ := claims[JWT_KEY_USERNAME].(string)
		_, u, err := dal.SelectUser(r.Context(), api.postgresDB, username)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("user Error not exist")))
			return
		}

		if username == model.UserSuperAdmin {

			mdgroup := dal.GetAdminModuleGroup(r.Context(), api.postgresDB)
			response.Ok(w, response.WithItems(mdgroup))
		} else {

			//get model
			mdgroup, err := dal.GetModuleGroup(r.Context(), api.postgresDB, u.ModuleID)
			if err == nil {
				response.Ok(w, response.WithItems(mdgroup))
			} else {
				RespAndLog(w, r.Context(), PostgresError(500, err))
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

		if req.UserName == "" || len(req.UserName) > 32 || (req.RoleName != model.RoleAdmin && req.RoleName != model.RoleNormal) {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("username or role error")))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		user, err := api.GetUserInfoFromRequest(r)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		if user.Rule == model.RoleNormal {
			RespAndLog(w, r.Context(),
				NewNoAccess(http.StatusForbidden,
					fmt.Errorf("access invalid")))
			return
		}

		if api.emailOpts.Check && !VerifyEmailFormat(req.UserName, api.emailOpts) {
			//check mail
			RespAndLog(w, r.Context(),
				EmailForMatError(http.StatusForbidden,
					fmt.Errorf("email format error")))
			return
		}

		var duplicate bool
		var sendMailFail bool
		err = api.postgresDB.Get().Transaction(func(tx *gorm.DB) error {
			innerErr := dal.InsertUserV2(ctx, api.postgresDB, req.UserName, req.RoleName, req.ModuleID)
			if innerErr != nil {
				if dal.IsPostgresDuplicateError(innerErr) {
					duplicate = true
					return nil
				}
				return innerErr
			}

			if api.emailOpts.Check {
				emailHashCode := dal.RandStringBytesMaskImprSrcUnsafe(64)
				innerErr = dal.InsertEmail(ctx, api.postgresDB, req.UserName, emailHashCode)
				if innerErr != nil {
					return innerErr
				}

				if sendMailFail = !model.SendEmail(req.UserName, r.Host, emailHashCode, api.emailOpts); sendMailFail {
					return ErrSendEmailFail
				}
				return nil
			}

			return dal.ActiveUser(ctx, api.postgresDB, req.UserName, model.DefaultPassword)
		})

		if err != nil {
			if sendMailFail {
				RespAndLog(w, ctx, SendmailError(http.StatusInternalServerError, ErrSendEmailFail))
				return
			}

			RespAndLog(w, ctx, err)
			return
		}

		if duplicate {
			RespAndLog(w, ctx,
				UserExistError(http.StatusInternalServerError, fmt.Errorf("user name already exist")))
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
		rq := reqAddUser{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		if rq.UserName == "" || rq.RoleName == "" || len(rq.UserName) > 32 || (rq.RoleName != model.RoleAdmin && rq.RoleName != model.RoleNormal) {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("username or role error")))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		token, claims, err := jwtauth.FromContext(ctx)

		if err != nil {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("Error when getting token & claims from context: %w", err)))
			return
		}
		if token == nil || !token.Valid {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("Token empty or invalid")))
			return
		}

		username, _ := claims[JWT_KEY_USERNAME].(string)

		userPtr, ok := api.userCache.Get(username)
		if !ok {
			testWithLogJson("jwt-jwtAccessCheck()", "user get error")
			RespAndLog(w, r.Context(),
				NewSessionExpired(http.StatusUnauthorized,
					fmt.Errorf("User not in cache")))
			return
		}

		u, _ := userPtr.(*model.User)
		if u.Rule == model.RoleNormal {
			RespAndLog(w, r.Context(),
				NewNoAccess(http.StatusForbidden,
					fmt.Errorf("access invalid")))
			return
		}

		exist, queryUser, err := dal.SelectUser(ctx, api.postgresDB, rq.UserName)
		if err != nil {
			RespAndLog(w, ctx,
				PostgresError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}
		if !exist {
			RespAndLog(w, ctx,
				UserNotExistError(http.StatusInternalServerError, fmt.Errorf("user name already exist:%+v", err)))
			return
		}
		if queryUser.Rule == model.RoleAdmin && rq.RoleName == model.RoleNormal {
			RespAndLog(w, r.Context(),
				NewNoAccess(http.StatusForbidden,
					fmt.Errorf("access invalid")))
			return
		}

		err = dal.UpdateUser(r.Context(), api.postgresDB, rq.UserName, rq.RoleName, rq.ModuleID)
		if err != nil {
			RespAndLog(w, ctx,
				PostgresError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}

		var findUser *model.User
		_, findUser, err = dal.SelectUser(ctx, api.postgresDB, rq.UserName)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("mongo err: %w", err)))
			return
		}

		api.userCache.Set(rq.UserName, findUser, UserSessionExpiration)
		response.Ok(w, response.WithItem(resp{Status: "OK"}))
	}
}

func (api *api) GetUserInfoFromRequest(r *http.Request) (*model.User, error) {
	token, claims, err := jwtauth.FromContext(r.Context())

	if err != nil {
		return nil, NewInvalidAuthToken(http.StatusUnauthorized,
			fmt.Errorf("error when getting token & claims from context: %w", err))
	}

	if token == nil || !token.Valid {
		return nil, NewInvalidAuthToken(http.StatusUnauthorized,
			fmt.Errorf("token empty or invalid"))
	}

	username, ok := claims[JWT_KEY_USERNAME].(string)
	if !ok {
		return nil, fmt.Errorf("unexpected username")
	}

	userPtr, ok := api.userCache.Get(username)
	if !ok {
		testWithLogJson("jwt-jwtAccessCheck()", "user get error")
		return nil, NewSessionExpired(http.StatusUnauthorized,
			fmt.Errorf("user not in cache"))
	}

	result, ok := userPtr.(*model.User)
	if !ok {
		return nil, fmt.Errorf("unexpected user")
	}

	return result, nil
}

func VerifyEmailFormat(email string, opts *flag.EmailOpts) bool {
	pattern := fmt.Sprintf(`\w+([-+.]\w+)*@%s`, opts.Suffix)
	reg, err := regexp.Compile(pattern)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("verify email compile expr error")
		return false
	}
	return reg.MatchString(email)
}
