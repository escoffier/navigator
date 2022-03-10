package api

import (
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
)

func (api *api) userCenter() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/config/loginOption", api.GetLoginOption())
		r.Get("/login/secret", api.getLoginSecret())
		r.Post("/login", api.login())
		r.Post("/ldapLogin", api.LdapLogin())
		r.Post("/radiusLogin", api.RadiusLogin())
		r.Post("/radiusResponseChallenge", api.RadiusResponseChallenge())
		r.Post("/createCaptcha", api.createCaptcha())
		r.Post("/getCaptchaImage", api.getCaptchaImage())
		r.Get("/getCaptchaValue", api.getCaptchaValue())
		r.Post("/forgetpwd", api.forgetPwd())
		r.Post("/activeuser", api.activeUser())
		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth), authenticator, jwtAccessCheck(api.rdb))
			r.Post("/logout", api.logout())
		})
		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(api.tokenAuth), authenticator, jwtAccessCheck(api.rdb))
			r.Post("/config/ldap", api.UpdateLdapConf())
			r.Get("/config/ldap", api.GetLdapConf())
			r.Post("/config/ldap/cert", api.UpdateLdapCert())
			r.Get("/config/ldap/cert", api.GetLdapCertInfo())
			r.Post("/config/radius", api.UpdateRadiusConf())
			r.Get("/config/radius", api.GetRadiusConf())
			r.Get("/openapi/token", api.getOpenAPIToken())
			r.Get("/userList", api.userList())
			r.Get("/userModule", api.userModule())
			r.Post("/addUser", api.addUser())
			r.Post("/editUser", api.editUser())
			r.Post("/resetPassword", api.resetPassword())
			r.Post("/loginConfig", api.setConfig())
			r.Get("/loginConfig", api.readConfig())
			r.Post("/user/ban", api.userBan())
			r.Post("/user/unban", api.userUnban())
			r.Get("/ldapGroup", api.GetLdapGroupList())
			r.Post("/ldapGroup", api.CreateLdapGroup())
			r.Put("/ldapGroup", api.UpdateLdapGroup())
			r.Delete("/ldapGroup", api.DeleteLdapGroup())
		})
	}
}
