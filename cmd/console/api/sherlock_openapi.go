package api

import (
	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"k8s.io/apimachinery/pkg/util/proxy"
	"net/http"
	"net/url"
	"strings"
)

func (api *api) sherlockOpenAPI() func(chi.Router) {
	return func(r chi.Router) {
		sherlockHandler := func(w http.ResponseWriter, r *http.Request) {
			su, err := url.Parse(api.sherlockURL)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("SHERLOCK_URL error")
				response.RespError(w, http.StatusInternalServerError, response.WithMessage(http.StatusText(http.StatusInternalServerError)))
			}

			u := r.URL
			u.Host = su.Host
			u.Scheme = su.Scheme
			u.Path = strings.Replace(r.URL.Path, "/openapi/v1/platform/sherlock", "/api/v1", 1)

			logging.GetLogger().Debug().Str("url", u.String()).Msg("proxy")

			r.Header.Set("X-Username", model.GetUsernameFromContext(r.Context()))
			httpProxy := proxy.NewUpgradeAwareHandler(u, http.DefaultTransport, false, false, &errorResponder{})
			httpProxy.ServeHTTP(w, r)
		}
		r.HandleFunc("/*", sherlockHandler)
	}
}
