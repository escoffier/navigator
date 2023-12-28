package api

import (
	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/audit"
	"gitlab.com/piccolo_su/vegeta/pkg/middleware"
)

func (api *api) userCenter() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/config/loginOption", api.GetLoginOption())
		r.Get("/login/secret", api.getLoginSecret())
		r.Get("/login/getVerifyAppURL", api.getVerifyAppURL())
		r.Group(func(r chi.Router) {
			r.Use(middleware.LicenseVerify)
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
			r.Get("/idp/dxhost", api.geDxHost())
		})
		r.Post("/radiusResponseChallenge", api.RadiusResponseChallenge())
		r.Post("/createCaptcha", api.createCaptcha())
		r.Get("/getCaptchaValue", api.getCaptchaValue())
		r.Post("/forgetpwd", api.forgetPwd())
		r.Post("/activeuser", api.activeUser())
		r.Post("/getMfaBindImage", api.BindGetMFASecret())
		r.Post("/bindMfaVerify", api.BindMfaSecretVerify())
		r.Post("/loginMfaVerify", api.LoginMfaSecretVerify())
		r.Post("/superAdminInit", api.superAdminInit())
		r.Group(func(r chi.Router) {
			r.Use(middleware.Authenticator(api.tokenManager, api.rdb))
			r.Get("/profile", api.getProfile())
			r.Post("/resetPassword", api.resetPassword())
			r.Post("/logout", api.logout())
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.Authenticator(api.tokenManager, api.rdb), middleware.Access(api.rdb))
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
			r.Post("/addUser", api.addUser())
			r.Post("/editUser", api.editUser())
			r.Post("/enable", api.userEnable())
			r.Delete("/delete", api.deleteUser())
			r.Post("/admin/resetpwd", api.adminResetPwd())
			// 管理员重置用户的mfa绑定
			r.Post("/admin/resetMfaSecret", api.adminResetMfaSecret())
		})
	}
}
