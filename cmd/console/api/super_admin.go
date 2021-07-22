package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/jwtauth"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

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
		rq := reqAddUser{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		if rq.UserName == "" || rq.RoleName == "" || len(rq.UserName) > 32 || (rq.RoleName != "admin" && rq.RoleName != "normal") {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("username or role error")))
			return
		}

		if _, ok := api.optUserMap[rq.UserName]; ok {
			RespAndLog(w, r.Context(),
				BusyRequestError(http.StatusBadRequest,
					fmt.Errorf("request busy")))
			return
		}

		// FIX: concurrency write map
		api.optUserMap[rq.UserName] = struct{}{}
		defer delete(api.optUserMap, rq.UserName)

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

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

		tx := api.postgresDB.Get().Begin()
		exist, _, err := dal.SelectUser(ctx, api.postgresDB, rq.UserName)
		if err != nil {
			tx.Rollback()
			RespAndLog(w, ctx,
				PostgresError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}
		if exist {
			tx.Rollback()
			RespAndLog(w, ctx,
				UserExistError(http.StatusInternalServerError, fmt.Errorf("user name already exist")))
			return
		}

		if api.emailOpts.Check {
			//check mail
			if !VerifyEmailFormat(rq.UserName, api.emailOpts) {
				RespAndLog(w, r.Context(),
					EmailForMatError(http.StatusForbidden,
						fmt.Errorf("email format error")))
				return
			}
			emailHashCode := dal.RandStringBytesMaskImprSrcUnsafe(64)
			bool := model.SendEmail(rq.UserName, r.Host, emailHashCode, api.emailOpts)
			if !bool {
				tx.Rollback()
				RespAndLog(w, ctx,
					SendmailError(http.StatusInternalServerError, fmt.Errorf("send email error")))
				return
			}
			err = dal.InsertEmail(r.Context(), api.postgresDB, rq.UserName, emailHashCode)
			if err != nil {
				tx.Rollback()
				RespAndLog(w, ctx,
					PostgresError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
				return
			}

			err = dal.InsertUser(r.Context(), api.postgresDB, rq.UserName, rq.RoleName, rq.ModuleID)
			if err != nil {
				tx.Rollback()
				RespAndLog(w, ctx,
					PostgresError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
				return
			}
		} else {
			err := dal.InsertUser(r.Context(), api.postgresDB, rq.UserName, rq.RoleName, rq.ModuleID)
			if err != nil {
				RespAndLog(w, ctx,
					PostgresError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
				return
			}

			err = dal.ActiveUser(r.Context(), api.postgresDB, rq.UserName, model.DefaultPassword)
			if err != nil {
				RespAndLog(w, ctx,
					PostgresError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
				return
			}
		}

		tx.Commit()
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

func VerifyEmailFormat(email string, opts *flag.EmailOpts) bool {
	pattern := fmt.Sprintf(`\w+([-+.]\w+)*@%s`, opts.Suffix)
	reg, err := regexp.Compile(pattern)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("verify email compile expr error")
		return false
	}
	return reg.MatchString(email)
}
