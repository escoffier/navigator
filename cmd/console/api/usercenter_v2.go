package api

import (
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
)

func (api *api) userCenter() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/login", api.login())
		r.Post("/forgetpwd", api.forgetPwd())
		r.Post("/activeuser", api.activeUser())
		r.Post("/loadUser", api.loadUser())
		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth))
			r.Post("/logout", api.logout())
		})
		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth))
			r.Use(jwtAccessCheck(api.postgresDB, api.userCache))
			r.Get("/user", user)
			r.Get("/userList", api.userList())
			r.Get("/userModule", api.userModule())
			r.Post("/addUser", api.addUser())
			r.Post("/editUser", api.editUser())
			r.Post("/delSuperUser", api.delSuperUser())
			r.Post("/resetPassword", api.resetPassword())
		})
	}
}
