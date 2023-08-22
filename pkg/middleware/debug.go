//go:build debug

package middleware

import (
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
	"gitlab.com/piccolo_su/vegeta/pkg/token"
	"gitlab.com/security-rd/go-pkg/databases"
)

func Authenticator(manager token.Manager, db *databases.RDBInstance) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := request.WithSession(r.Context(), token.Payload{
				Username:   model.SuperAdminUsername,
				Account:    "debug",
				Role:       model.RoleTypeSuperAdmin,
				Platform:   "",
				ModuleID:   "",
				External:   false,
				Status:     model.UserStatusNormal,
				Eigenvalue: "fake",
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func LicenseVerify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
