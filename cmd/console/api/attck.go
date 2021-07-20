package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/config"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) ATTCK() func(router chi.Router) {
	return func(r chi.Router) {
		r.Get("/latestData", api.getATTCKLatestData())
	}
}

func (api *api) getATTCKLatestData() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := config.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		curDataVersion, err := param.QueryUint32(r, "curDataVersion")
		if err != nil {
			curDataVersion = 0
		}
		curSettingVersion, err := param.QueryUint32(r, "curSettingVersion")
		if err != nil {
			curSettingVersion = 0
		}

		info, err := service.GetATTCKConfData(ctx, curDataVersion, curSettingVersion)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItem(*info), response.WithApiVersion(versionAPIVersion))
	}
}
