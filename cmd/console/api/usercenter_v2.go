package api

import (
	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/audit"
)

func (api *api) userCenter() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/config/loginOption", api.GetLoginOption())
		r.Get("/login/secret", api.getLoginSecret())
		r.Group(func(r chi.Router) {
			r.Use(licenseVerify)
			if !api.httpAuditDisabled {
				ecCli, err := api.esCli.Get()
				if err == nil {
					r.Use(audit.ESAudit(ecCli))
				}
			}
			r.Post("/login", api.login())
			r.Post("/ldapLogin", api.LdapLogin())
			r.Post("/radiusLogin", api.RadiusLogin())
			r.Get("/idp/login/url", api.getIdpLoginUrl())
			r.Post("/idp/login", api.idpLogin())
		})
		r.Post("/radiusResponseChallenge", api.RadiusResponseChallenge())
		r.Post("/createCaptcha", api.createCaptcha())
		r.Get("/getCaptchaValue", api.getCaptchaValue())
		r.Post("/forgetpwd", api.forgetPwd())
		r.Post("/activeuser", api.activeUser())
		r.Post("/superAdminInit", api.superAdminInit())
		r.Group(func(r chi.Router) {
			r.Use(verifier(api.tokenAuth), bypassAuthenticator(api.rdb), authenticator(api.rdb), jwtAccessCheck(api.rdb))
			r.Post("/logout", api.logout())
		})
		r.Group(func(r chi.Router) {
			r.Use(verifier(api.tokenAuth), bypassAuthenticator(api.rdb), authenticator(api.rdb), jwtAccessCheck(api.rdb))
			if !api.httpAuditDisabled {
				ecCli, err := api.esCli.Get()
				if err == nil {
					r.Use(audit.ESAudit(ecCli))
				}
			}
			r.Post("/config/ldap", api.UpdateLdapConf())
			r.Get("/config/ldap", api.GetLdapConf())
			r.Post("/config/ldap/cert", api.UpdateLdapCert())
			r.Get("/config/ldap/cert", api.GetLdapCertInfo())
			r.Post("/config/radius", api.UpdateRadiusConf())
			r.Get("/config/radius", api.GetRadiusConf())
			r.Get("/config/idp", api.getIdpConfig())
			r.Put("/config/idp", api.updateIdpConfig())
			r.Get("/config/login", api.getLoginConfig())
			r.Put("/config/login", api.updateLoginConfig())
			r.Get("/openapi/token", api.getOpenAPIToken())
			r.Get("/userList", api.userList())
			r.Get("/profile", api.getProfile())
			r.Get("/userModule", api.userModule())
			r.Post("/addUser", api.addUser())
			r.Post("/editUser", api.editUser())
			r.Post("/resetPassword", api.resetPassword())
			r.Post("/enable", api.userEnable())
			r.Delete("/delete", api.deleteUser())
			r.Post("/admin/resetpwd", api.adminResetPwd())
		})
	}
}
