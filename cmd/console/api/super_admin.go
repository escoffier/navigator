package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/jwtauth"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) superAdmin() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/userList", api.userList())
		r.Post("/resetPassword", api.resetPassword())
		r.Get("/userModule", api.userModule())
		r.Post("/addUser", api.addUser())
		r.Post("/delSuperUser", api.delSuperUser())
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

		docNum, userList, err := model.SelectUserAll(api.postgresDB, limit, offset)
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
		_, u, err := model.SelectUser(api.postgresDB, username)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("user Error not exist")))
			return
		}

		if username == model.SUPER_ADMIN {

			mdgroup := model.GetAdminModuleGroup(api.postgresDB)
			response.Ok(w, response.WithItems(mdgroup))
		} else {

			//get model
			mdgroup := model.GetModuleGroup(api.postgresDB, u.ModuleID)

			response.Ok(w, response.WithItems(mdgroup))
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
		if u.Rule == "normal" {
			RespAndLog(w, r.Context(),
				NewNoAccess(http.StatusForbidden,
					fmt.Errorf("access invalid")))
			return

		}

		tx := api.postgresDB.Begin()
		exist, _, err := model.SelectUser(api.postgresDB, rq.UserName)
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
			emailHashCode := model.RandStringBytesMaskImprSrcUnsafe(64)
			bool := model.SendEmail(rq.UserName, r.Host, emailHashCode, api.emailOpts)
			if !bool {
				tx.Rollback()
				RespAndLog(w, ctx,
					SendmailError(http.StatusInternalServerError, fmt.Errorf("send email error")))
				return
			}
			err = model.InsertEmail(api.postgresDB, rq.UserName, emailHashCode)
			if err != nil {
				tx.Rollback()
				RespAndLog(w, ctx,
					PostgresError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
				return
			}

			err = model.InsertUser(api.postgresDB, rq.UserName, rq.RoleName, rq.ModuleID)
			if err != nil {
				tx.Rollback()
				RespAndLog(w, ctx,
					PostgresError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
				return
			}
		} else {
			err := model.InsertUser(api.postgresDB, rq.UserName, rq.RoleName, rq.ModuleID)
			if err != nil {
				RespAndLog(w, ctx,
					PostgresError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
				return
			}

			err = model.ActiveUser(api.postgresDB, rq.UserName, model.DEFAULT_PWD)
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

func (api *api) delSuperUser() http.HandlerFunc {
	type resp struct {
		Status string `json:"status"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		token, claims, err := jwtauth.FromContext(r.Context())

		if err != nil {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("Error when get token & claims from context: %w", err)))
			return
		}
		if token == nil || !token.Valid {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("Token empty or invalid")))
			return
		}

		username, _ := claims[JWT_KEY_USERNAME].(string)
		if username != model.ROLE_SUPERADMIN {
			RespAndLog(w, r.Context(),
				NewInvalidAuthToken(http.StatusUnauthorized,
					fmt.Errorf("user error auth forbidden")))
			return
		}

		err = model.DelSuperUser(api.postgresDB, username)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
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
		if rq.UserName == "" || rq.RoleName == "" || len(rq.UserName) > 32 || (rq.RoleName != "admin" && rq.RoleName != "normal") {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("username or role error")))
			return
		}

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
		if u.Rule == "normal" {
			RespAndLog(w, r.Context(),
				NewNoAccess(http.StatusForbidden,
					fmt.Errorf("access invalid")))
			return
		}

		exist, queryUser, err := model.SelectUser(api.postgresDB, rq.UserName)
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
		if queryUser.Rule == model.ROLE_ADMIN && rq.RoleName == model.ROLE_NORMAL {
			RespAndLog(w, r.Context(),
				NewNoAccess(http.StatusForbidden,
					fmt.Errorf("access invalid")))
			return
		}

		err = model.UpdateUser(api.postgresDB, rq.UserName, rq.RoleName, rq.ModuleID)
		if err != nil {
			RespAndLog(w, ctx,
				PostgresError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}

		var findUser *model.User
		_, findUser, err = model.SelectUser(api.postgresDB, rq.UserName)
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
	reg := regexp.MustCompile(pattern)
	return reg.MatchString(email)
}
