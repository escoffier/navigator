package api

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	param "github.com/oceanicdev/chi-param"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/config"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) config() func(chi.Router) {
	return func(r chi.Router) {
		r.Put("/ATTCK", api.updateATTCKConf())
		r.Get("/ATTCK/ruleList", api.getATTCKRuleList())
		r.Post("/ATTCK/ruleSwitch", api.updateRuleSwitch())
	}
}

const (
	defaultConfigTimeout = time.Second * 5
)

func (api *api) updateATTCKConf() http.HandlerFunc {
	type rsp struct {
		Version        string `json:"version"`
		LastUpdateTime int64  `json:"lastUpdateTime"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := config.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		username := getUsername(ctx)
		err := r.ParseMultipartForm(100 << 20)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("ParseMultipartForm fail, err:%w", err)))
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("read file fail, err:%w", err)))
			return
		}

		data, err := ioutil.ReadAll(file)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		logging.GetLogger().Debug().Msgf("filename:%s, content:%s", header.Filename, string(data))

		item, err := service.UpdateConfig(ctx, username, data)
		if err != nil {
			if err == config.ErrInvalidRuleData {
				apperror.RespAndLog(w, ctx,
					apperror.NewFieldError(http.StatusBadRequest, err))
				return
			}

			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItem(rsp{
			Version:        item.Version,
			LastUpdateTime: util.GetMillisecondTimestampByTime(item.CreatedAt),
		}), response.WithApiVersion(versionAPIVersion))
	}
}

func getUsername(ctx context.Context) string {
	token, claims, err := jwtauth.FromContext(ctx)
	if err != nil || token == nil || !token.Valid {
		return ""
	}

	// check if we can find the user's session
	username, ok := claims[JWTKeyUsername].(string)
	if ok {
		return username
	}

	return ""
}

func (api *api) getATTCKRuleList() http.HandlerFunc {
	const (
		defaultLimit = 10
	)

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := config.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		offset, err := param.QueryUint(r, "offset")
		if err != nil {
			offset = 0
		}

		limit, err := param.QueryUint(r, "limit")
		if err != nil {
			limit = defaultLimit
		}

		query, err := param.QueryString(r, "query")
		if err != nil {
			query = ""
		}

		var severityFilter, hthreatsFilter map[uint8]struct{}
		severityFilterStr, err := param.QueryString(r, "severityFilter")
		if err == nil && len(severityFilterStr) > 0 {
			severityFilter = parseFilter(severityFilterStr)
		}

		hthreatsFilterStr, err := param.QueryString(r, "hthreatsFilter")
		if err == nil && len(hthreatsFilterStr) > 0 {
			hthreatsFilter = parseFilter(hthreatsFilterStr)
		}

		total, ruleList, err := service.GetRuleList(ctx, &config.GetRuleListArg{
			Offset:         int(offset),
			Limit:          int(limit),
			SeverityFilter: severityFilter,
			HthreatsFilter: hthreatsFilter,
			Query:          query,
			Lang:           string(lang.Language(ctx)),
		})
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w,
			response.WithItems(ruleList),
			response.WithTotalItems(total),
			response.WithApiVersion(versionAPIVersion))
	}
}

func parseFilter(filterStr string) map[uint8]struct{} {
	filter := make(map[uint8]struct{})
	items := strings.Split(filterStr, ",")
	for _, str := range items {
		value, _err := strconv.Atoi(str)
		if _err == nil {
			filter[uint8(value)] = struct{}{}
		}
	}
	return filter
}

func (api *api) updateRuleSwitch() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := config.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		var items []*model.ATTCKRuleSwitch
		err := util.DecodeJSONBody(w, r, &items)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		switches, err := service.UpdateRuleSettings(ctx, items)
		if err != nil {
			if err == dal.ErrRuleNotExists {
				apperror.RespAndLog(w, ctx,
					apperror.NewFieldError(http.StatusBadRequest, err))
				return
			}
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItems(switches), response.WithApiVersion(versionAPIVersion))
	}
}
