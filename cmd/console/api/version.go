package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/attck"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	softNameEnv           = "SOFT_NAME"
	defaultSoftName       = "tensor"
	softVersionEnv        = "SOFT_VERSION"
	defaultSoftVersion    = "v1.9"
	versionAPIVersion     = "2.0"
	defaultVersionTimeout = time.Second * 5
)

var (
	ErrServiceNotReady = errors.New("service not ready")
)

func (api *api) version() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/system", api.getSystemVersion())
		r.Get("/ATTCK", api.getATTCKVersion())
		r.Get("/ATTCKHistory", api.getATTCKVersionHistory())
		r.Get("/ATTCKVersionList", api.getATTCKVersionList())
	}
}

func (api *api) getSystemVersion() http.HandlerFunc {
	type rsp struct {
		SoftName string `json:"softName"`
		Version  string `json:"version"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		response.Ok(w, response.WithItem(rsp{
			SoftName: util.GetEnvWithDefault(softNameEnv, defaultSoftName),
			Version:  util.GetEnvWithDefault(softVersionEnv, defaultSoftVersion),
		}),
			response.WithApiVersion(versionAPIVersion))
	}
}

func (api *api) getATTCKVersion() http.HandlerFunc {
	type rsp struct {
		Version        string `json:"version"`
		LastUpdateTime int64  `json:"lastUpdateTime"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultVersionTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		version, err := service.GetATTCKVersion(ctx)
		if err != nil {
			if err == dal.ErrATTCKConfDataNotFound {
				response.Ok(w, response.WithItem(rsp{}), response.WithApiVersion(versionAPIVersion))
				return
			}
			apperror.RespAndLog(w, ctx, err)
			return
		}
		response.Ok(w, response.WithItem(rsp{
			LastUpdateTime: util.GetMillisecondTimestampByTime(version.CreatedAt),
			Version:        version.VString(),
		}), response.WithApiVersion(versionAPIVersion))
	}
}

func (api *api) getATTCKVersionHistory() http.HandlerFunc {
	type history struct {
		Version   string `json:"version"`
		User      string `json:"user"`
		Timestamp int64  `json:"timestamp"`
	}

	const (
		defaultLimit = 10
	)

	convert := func(items []*model.ATTCKConfVersion) []*history {
		result := make([]*history, len(items))
		for i := range items {
			result[i] = &history{
				Version:   items[i].VString(),
				User:      items[i].Username,
				Timestamp: util.GetMillisecondTimestampByTime(items[i].CreatedAt),
			}
		}

		return result
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultVersionTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		offset, err := param.QueryUint(r, "offset")
		if err != nil {
			logging.GetLogger().Warn().Msgf("parse offset fail, err:%s", err.Error())
			offset = 0
		}

		limit, err := param.QueryUint(r, "limit")
		if err != nil {
			logging.GetLogger().Warn().Msgf("parse limit fail, err:%s", err.Error())
			limit = defaultLimit
		}

		version, err := param.QueryString(r, "version")
		if err != nil {
			logging.GetLogger().Warn().Msgf("parse version fail, err:%s", err.Error())
			version = ""
		}

		total, items, err := service.GetATTCKVersionHistory(ctx, int(offset), int(limit), strings.TrimSpace(version))
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItems(convert(items)),
			response.WithTotalItems(total),
			response.WithApiVersion(versionAPIVersion))
	}
}

func (api *api) getATTCKVersionList() http.HandlerFunc {
	type version struct {
		Name     string `json:"name"`
		Version1 uint16 `json:"version1"`
		Version2 uint16 `json:"version2"`
	}

	convert := func(items []*model.ATTCKConfVersion) []*version {
		result := make([]*version, len(items))
		for i := range items {
			result[i] = &version{
				Name:     items[i].VString(),
				Version1: items[i].Version1,
				Version2: items[i].Version2,
			}
		}

		return result
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultVersionTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		items := service.GetATTCKVersionList(ctx)

		response.Ok(w, response.WithItems(convert(items)),
			response.WithTotalItems(int64(len(items))),
			response.WithApiVersion(versionAPIVersion))
	}
}
