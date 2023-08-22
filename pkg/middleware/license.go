//go:build !debug

package middleware

import (
	"fmt"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/license"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
)

func LicenseVerify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := license.ValidateLicense(false)
		if !status.IsValid() {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewInvalidLicenseError(http.StatusPreconditionFailed,
					fmt.Errorf("license valid: %v", status)))
			return
		}

		// license is valid, pass it through
		next.ServeHTTP(w, r)
	})
}
