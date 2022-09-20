package api

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/security-rd/go-pkg/pb"
	"k8s.io/apimachinery/pkg/util/proxy"
)

type errorResponder struct{}

func (e *errorResponder) Error(w http.ResponseWriter, req *http.Request, err error) {
	logging.GetLogger().Error().Err(err).Msg("proxy to Sherlock err")
	response.RespError(w, http.StatusInternalServerError, response.WithMessage(http.StatusText(http.StatusInternalServerError)))
}

func (api *api) sherlock() func(chi.Router) {
	return func(r chi.Router) {
		// proxy palace
		r.HandleFunc("/palace/*", func(w http.ResponseWriter, r *http.Request) {
			su, err := url.Parse(api.sherlockURL)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("SHERLOCK_URL error")
				response.RespError(w, http.StatusInternalServerError, response.WithMessage(http.StatusText(http.StatusInternalServerError)))
			}

			u := r.URL
			u.Host = su.Host
			u.Scheme = su.Scheme
			u.Path = strings.Replace(r.URL.Path, "/api/v2/platform/sherlock", "/api/v1", 1)

			logging.GetLogger().Debug().Str("url", u.String()).Msg("proxy")

			r.Header.Set("X-Username", model.GetUsernameFromContext(r.Context()))
			httpProxy := proxy.NewUpgradeAwareHandler(u, http.DefaultTransport, false, false, &errorResponder{})
			httpProxy.ServeHTTP(w, r)
		})
	}
}

type syslogSetting struct {
	Enable   bool   `json:"enable"`
	Network  string `json:"network"`
	Addr     string `json:"addr"`
	Severity string `json:"severity"`
	Facility string `json:"facility"`
	Tag      string `json:"tag"`
}

func convertSyslogSettingFromPb(setting *pb.SyslogSetting) *syslogSetting {
	return &syslogSetting{
		Enable:   setting.Enable,
		Network:  setting.Network,
		Addr:     setting.Addr,
		Severity: setting.Severity,
		Facility: setting.Facility,
		Tag:      setting.Tag,
	}
}

func convertSyslogSettingToPb(setting *syslogSetting) *pb.SyslogSetting {
	return &pb.SyslogSetting{
		Enable:   setting.Enable,
		Network:  setting.Network,
		Addr:     setting.Addr,
		Severity: setting.Severity,
		Facility: setting.Facility,
		Tag:      setting.Tag,
	}
}
