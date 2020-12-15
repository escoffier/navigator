package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

const (
	ACTION_UPDATE = "update"
	ACTION_ADD    = "add"
	ACTION_DELETE = "delete"
)

func (api *api) superAdmin() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/userList", api.userList())
		r.Post("/resetPassword", api.resetPassword())
		r.Post("/roleList", api.roleList())
		r.Post("/accessList", api.accessList())
		r.Post("/addUser", api.addUser())
		r.Post("/setUserRole", api.setUserRole())
		r.Post("/setRoleAccess", api.setRoleAccess())
	}
}

func (api *api) userList() http.HandlerFunc {
	type reqUserList struct {
		Page  int64 `json:"page"`
		Limit int64 `json:"limit"`
	}
	type UserListResponse struct {
		UserList []model.User `json:"userList"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		rq := reqUserList{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		userList, err := model.SelectUserAll(ctx, api.mongodb, rq.Limit, rq.Page)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusInternalServerError,
					fmt.Errorf("database error: %w", err)))
			return
		}

		for i := range userList {
			_, roleNames, err := model.SelectRelaUserRole(ctx, api.mongodb, userList[i].UserName, "")
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
				return
			}
			userList[i].RoleNameList = roleNames
		}

		response.Ok(w, response.WithItems(userList))
	}
}

// func (api *api) resetPassword() http.HandlerFunc {
// 	type reqResetPwd struct {
// 		Pwd string `json:"pwd"`
// 	}
// 	type ResetPwdResponse struct {
// 		Success bool `json:"success"`
// 	}

// 	return func(w http.ResponseWriter, r *http.Request) {
// 		rq := reqResetPwd{}
// 		err := json.NewDecoder(r.Body).Decode(&rq)
// 		if err != nil {
// 			RespAndLog(w, r.Context(),
// 				NewMalformedRequestError(http.StatusBadRequest,
// 					fmt.Errorf("failed to decode json: %w", err)))
// 			return
// 		}

// 		user := r.Context().Value(userKey).(*User)

// 		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
// 		defer cancel()

// 		_, err = model.UpdateUserPwd(ctx, api.mongodb, user.Username, rq.Pwd)
// 		if err != nil {
// 			RespAndLog(w, ctx,
// 				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database err: %w", err)))
// 			return
// 		}

// 		response.Ok(w, response.WithItem(ResetPwdResponse{
// 			Success: true,
// 		}))
// 	}
// }

func (api *api) roleList() http.HandlerFunc {
	type reqRoleList struct {
		Page  int64 `json:"page"`
		Limit int64 `json:"limit"`
	}
	type ModListResponse struct {
		RoleList []model.Role `json:"roleList"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		rq := reqRoleList{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		roleList, err := model.SelectRoleAll(ctx, api.mongodb, rq.Limit, rq.Page)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}

		for i := range roleList {
			_, accessNameList, err := model.SelectRelaRoleAccess(ctx, api.mongodb, roleList[i].RoleName, "")
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
				return
			}
			roleList[i].AccessNameList = accessNameList
		}

		response.Ok(w, response.WithItems(roleList))

	}
}

func (api *api) accessList() http.HandlerFunc {
	type reqAccessList struct {
		Page  int64 `json:"page"`
		Limit int64 `json:"limit"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		rq := reqAccessList{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		accessList, err := model.SelectAccessAll(ctx, api.mongodb, rq.Limit, rq.Page)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}
		response.Ok(w, response.WithItems(accessList))

	}
}

func (api *api) addUser() http.HandlerFunc {
	type reqAddUser struct {
		UserName string `json:"userName"`
		RoleName string `json:"roleName"`
		Title    string `json:"title"`
	}
	type AddUserListResponse struct {
		Success bool `json:"success"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		rq := reqAddUser{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		_, exist, err := model.SelectUser(ctx, api.mongodb, rq.UserName)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}
		if exist {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("user name already exist")))
			return
		}

		_, u, err := model.InsertUser(ctx, api.mongodb, rq.UserName, rq.Title)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}

		_, err = model.InsertRelaUserRole(ctx, api.mongodb, rq.UserName, rq.RoleName)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}
		response.Ok(w, response.WithItem(u))
	}
}

func (api *api) setUserRole() http.HandlerFunc {
	type reqSetUserLevel struct {
		UserName string `json:"userName"`
		RoleName string `json:"roleName"`
		Action   string `json:"action"`
	}
	type SetUserLevelResponse struct {
		Success bool `json:"success"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		rq := reqSetUserLevel{}
		err := json.NewDecoder(r.Body).Decode(&rq)

		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if rq.UserName == "" || rq.RoleName == "" {
			RespAndLog(w, r.Context(),
				NewFieldError(http.StatusBadRequest, fmt.Errorf("couldn't find param")))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		switch rq.Action {
		case ACTION_UPDATE:
			_, err = model.UpdateRelaUserRole(ctx, api.mongodb, rq.UserName, rq.RoleName)
		default:
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					NewFieldError(http.StatusBadRequest, fmt.Errorf("action param wrong"))))
			return
		}

		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}

		response.Ok(w, response.WithItem(SetUserLevelResponse{
			Success: true,
		}))

	}
}

func (api *api) setRoleAccess() http.HandlerFunc {
	type reqSetModLevel struct {
		RoleName   string `json:"roleName"`
		AccessName string `json:"accessName"`
		Action     string `json:"action"`
	}
	type SetRoleAccessResponse struct {
		Success bool `json:"success"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		rq := reqSetModLevel{}
		err := json.NewDecoder(r.Body).Decode(&rq)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if rq.RoleName == "" || rq.AccessName == "" {
			RespAndLog(w, r.Context(), errors.New("param empty"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		switch rq.Action {
		case ACTION_ADD:
			_, ss, err := model.SelectRelaRoleAccess(ctx, api.mongodb, rq.RoleName, rq.AccessName)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
				return
			} else if len(ss) > 0 {
				RespAndLog(w, ctx,
					NewMalformedRequestError(http.StatusInternalServerError, errors.New("the Access is already Exist")))
				return
			}

			_, err = model.InsertRelaRoleAccess(ctx, api.mongodb, rq.RoleName, rq.AccessName)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
				return
			}

		case ACTION_DELETE:
			_, err = model.DeleteRelaRoleAccess(ctx, api.mongodb, rq.RoleName, rq.AccessName)

		default:
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("invalid action")))
			return
		}

		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}

		response.Ok(w, response.WithItem(SetRoleAccessResponse{
			Success: true,
		}))

	}
}
