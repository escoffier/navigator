package api

import (
	"encoding/json"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/bcrypt"

	"gitlab.com/piccolo_su/vegeta/pkg/locale"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
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
}

func (api *api) restAuth() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/login", api.login())
		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth))
			r.Post("/logout", api.logout())
		})
		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth))
			r.Use(jwtAuthenticator(api.userCache))
			r.Get("/user", user)
		})
	}
}

// @Summary Login API
// @Description Login by username/password
// @ID v1-rest-auth-login
// @Accept json
// @Produce json
// @Param username body string true "Username"
// @Param password body string true "Password"
// @Success 200 {object} api.LoginResponse "Login response"
// @Router /api/v1/rest-auth/login [post]
func (api *api) login() http.HandlerFunc {
	type credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		creds := &credentials{}
		err := json.NewDecoder(r.Body).Decode(creds)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("Failed to decode json")
			response.Bad(w, response.WithMessage(locale.Error(locale.MalformedRequestError, r)))
			return
		}

		if creds.Username == "" {
			logging.GetLogger().Info().Err(err).Msg("Missing field 'username'")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("username", ""))
			return
		}

		if creds.Password == "" {
			logging.GetLogger().Info().Err(err).Msg("Missing field 'password'")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("password", ""))
			return
		}

		// compare the password, defaults to admin:admin till Mongo integration
		hashed, _ := bcrypt.GenerateFromPassword([]byte("admin"), 8)
		errUsername := bcrypt.CompareHashAndPassword(hashed, []byte(creds.Username))
		errPassword := bcrypt.CompareHashAndPassword(hashed, []byte(creds.Password))
		if errUsername != nil || errPassword != nil {
			logging.GetLogger().Info().Err(err).Msg("Invalid username or password")
			response.Unauthorized(w, response.WithMessage(locale.Error(locale.InvalidUsernameOrPasswordError, r)))
			return
		}

		// matched password
		// generated a jwt, set cookie and put it in the userCache
		jwtmc := jwt.MapClaims{"username": creds.Username}
		jwtauth.SetIssuedNow(jwtmc)
		_, tokenString, _ := api.tokenAuth.Encode(jwtmc)
		http.SetCookie(w, &http.Cookie{
			Name:     "jwt",
			Value:    tokenString,
			Path:     "/",
			Expires:  time.Now().Add(7 * 24 * time.Hour),
			HttpOnly: true,
		})
		api.userCache.Set(
			creds.Username,
			&User{
				Username: creds.Username,
				Name:     "管理员",
				UserID:   "00000001",
				Email:    "admin@tensorsecurity.io",
				Title:    "系统管理员",
				Group:    "事业群－平台部－技术部－集群管理",
				Avatar: "http://icons.iconarchive.com/icons/oxygen-icons.org/oxygen/48/" +
					"Places-user-identity-icon.png",
			},
			cache.DefaultExpiration)

		response.Ok(w, response.WithItem(LoginResponse{
			CurrentAuthority: "admin",
			Status:           "ok",
			Type:             "account",
		}))
	}
}

// @Summary Logout API
// @Description Logout
// @ID v1-rest-auth-logout
// @Produce json
// @Success 200 {object} response.EmptyResponse "Logout response"
// @Router /api/v1/rest-auth/logout [post]
func (api *api) logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, claims, err := jwtauth.FromContext(r.Context())
		if err != nil || token == nil || !token.Valid {
			response.Ok(w)
			return
		}

		// check if we can find the user's session
		username := claims["username"].(string)
		api.userCache.Delete(username)

		// invalidate the JWT in the cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "jwt",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
		})
		response.Ok(w)
	}
}

// @Summary User API
// @Description Get current user
// @ID v1-rest-auth-user
// @Produce json
// @Success 200 {object} api.User "Current user"
// @Router /api/v1/rest-auth/user [get]
func user(w http.ResponseWriter, r *http.Request) {
	u := r.Context().Value(userKey).(*User)
	response.Ok(w, response.WithItem(*u))
}
