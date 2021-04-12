package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

const (
	JWT_KEY_USERNAME = "user_name"
)

// User defines the obj in the userCache
type User struct {
	Username string
	Name     string `json:"name"`
	UserID   string `json:"userid"`
	Email    string `json:"email"`
	Title    string `json:"title"`
	Group    string `json:"group"`
	Avatar   string `json:"avatar"`
}

// LoginResponse is the response of the login API
type LoginResponse struct {
	CurrentAuthority string `json:"currentAuthority"`
	Status           string `json:"status"`
	Type             string `json:"type"`
	Token            string `json:"token"`
}

func (api *api) restAuth() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/login", api.login())
		r.Post("/forgetpwd", api.forgetPwd())
		r.Post("/activeuser", api.activeUser())
		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth))
			r.Post("/logout", api.logout())
		})
		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth))
			r.Use(jwtAccessCheck(api.postgresDB, api.userCache))
			r.Get("/user", user)
		})
	}
}

// @Summary Login API
// @Description Login by username/password
// @ID v1-auth-login
// @Accept json
// @Produce json
// @Param username body string true "Username"
// @Param password body string true "Password"
// @Success 200 {object} api.LoginResponse "Login response"
// @Router /api/v1/auth/login [post]
func (api *api) login() http.HandlerFunc {
	type credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		creds := &credentials{}
		err := json.NewDecoder(r.Body).Decode(creds)

		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		if creds.Username == "" || creds.Password == "" {
			// Handle case where  username or password are missing
			// We probably should have some validation helper instead of nested
			// ifs like this.
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("missing field 'password' or 'username'"),
					Suberror{"username", ""}, Suberror{"password", ""}))
			return
		}

		var (
			findUser *model.User
			ok       bool
		)

		ok, findUser, err = model.LoginCheckByPostgres(api.postgresDB, creds.Username, creds.Password)
		if err != nil {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusInternalServerError,
					fmt.Errorf("mongo err: %w", err)))
			return
		} else if !ok {
			RespAndLog(w, r.Context(),
				LoginError(http.StatusPreconditionFailed,
					fmt.Errorf("Couldn't find Username: %w", err)))
			return
		}

		// matched password
		// generated a jwt, set cookie and put it in the userCache
		jwtmc := jwt.MapClaims{
			JWT_KEY_USERNAME: creds.Username,
		}
		jwtauth.SetIssuedNow(jwtmc)
		_, tokenString, _ := api.tokenAuth.Encode(jwtmc)

		api.userCache.Set(creds.Username, findUser, UserSessionExpiration)

		response.Ok(w, response.WithItem(LoginResponse{
			CurrentAuthority: findUser.UserName,
			Status:           "ok",
			Type:             "account",
			Token:            tokenString,
		}))
	}
}

type resp struct {
	Status string `json:"status"`
}

// @Summary Logout API
// @Description Logout
// @ID v1-auth-logout
// @Produce json
// @Router /api/v1/auth/logout [post]
func (api *api) logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		_, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		token, claims, err := jwtauth.FromContext(r.Context())
		if err != nil || token == nil || !token.Valid {
			response.Ok(w)
			return
		}

		// check if we can find the user's session
		username := claims[JWT_KEY_USERNAME].(string)
		api.userCache.Delete(username)
		response.Ok(w)
	}
}

// @Summary User API
// @Description Get current user
// @ID v1-auth-user
// @Produce json
// @Success 200 {object} api.User "Current user"
// @Router /api/v1/auth/user [get]
func user(w http.ResponseWriter, r *http.Request) {
	u := r.Context().Value(userKey).(*User)
	response.Ok(w, response.WithItem(*u))
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
				NewMalformedRequestError(http.StatusRequestedRangeNotSatisfiable, fmt.Errorf("hashcode is not empty")))
			return
		}

		username, ok := model.CheckHashCode(api.postgresDB, ru.HashCode)
		if !ok {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusRequestedRangeNotSatisfiable, fmt.Errorf("hashcode is error")))
			return
		}

		// active user
		err = model.ActiveUser(api.postgresDB, username, ru.Pwd)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("database error:%+v", err)))
			return
		}

		response.Ok(w, response.WithItem(resp{
			Status: fmt.Sprintf("%v", "OK"),
		}))
	}
}

func testWithLogJson(middle string, payload interface{}) {
	pre := "{super-admin} -> "
	middle = middle + " -> "
	jso, err := json.Marshal(payload)
	if err != nil {
		logging.GetLogger().Debug().Msg(pre + middle + " json err:" + err.Error())
	} else {
		logging.GetLogger().Debug().Msg(pre + middle + string(jso))
	}
}

func (api *api) forgetPwd() http.HandlerFunc {

	type reqForgetUser struct {
		Username string `json:"username" binding:"required,max=32"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		rf := reqForgetUser{}
		err := json.NewDecoder(r.Body).Decode(&rf)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		exist, _, err := model.SelectUser(api.postgresDB, rf.Username)
		if err != nil {
			RespAndLog(w, ctx,
				PostgresError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}
		if !exist {
			RespAndLog(w, ctx,
				UserNotExistError(http.StatusPreconditionFailed, fmt.Errorf("user not exist")))
			return
		}

		emailHashCode := model.RandStringBytesMaskImprSrcUnsafe(64)

		bool := model.SendEmail(rf.Username, r.Host, emailHashCode, api.emailOpts)
		if !bool {
			RespAndLog(w, ctx,
				SendmailError(http.StatusNotFound, fmt.Errorf("send email error")))
			return
		}

		err = model.InsertEmail(api.postgresDB, rf.Username, emailHashCode)
		if err != nil {
			RespAndLog(w, ctx,
				PostgresError(http.StatusInternalServerError, fmt.Errorf("database error: %w", err)))
			return
		}

		response.Ok(w, response.WithItem(resp{
			Status: fmt.Sprintf("%v", "OK"),
		}))
	}

}
