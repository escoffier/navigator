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
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/attck"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	defaultConfigTimeout = time.Second * 5
)

func (api *api) ATTCKOpen() func(router chi.Router) {
	return func(r chi.Router) {
		r.Get("/latestData", api.getATTCKLatestData())

	}
}

func (api *api) ATTCK() func(router chi.Router) {
	return func(r chi.Router) {
		r.Put("/conf", api.updateATTCKConf())
		r.Get("/ruleList", api.getATTCKRuleList())
		r.Post("/ruleSwitch", api.updateRuleSwitch())
		r.Get("/customInitConfig", api.getCustomInitConfig())
		r.Get("/customConfigs/configs", api.getCustomConfigs())
		r.Put("/customConfigs/configs/edit", api.editCustomConfigs())
		r.Put("/customConfigs/configs/append", api.addCustomConfigs())
		r.Delete("/customConfigs/config/{id}", api.deleteCustomConfig())
	}
}

func (api *api) getCustomInitConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		lang := r.Header.Get("Accept-Language")
		if lang == "" {
			lang = "zh"
		}

		iconfs, err := service.GetCustomInitConfig(ctx, lang)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError,
				fmt.Errorf("get error %v", err)))
			return
		}

		response.Ok(w, response.WithItems(iconfs),
			response.WithTotalItems(int64(len(iconfs))))
	}
}

func (api *api) getCustomConfigs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		queryOpt := attck.CustomConfigsQueryOption{}

		lang := r.Header.Get("Accept-Language")
		if lang == "" {
			lang = "zh"
		}

		ruleKey, paramErr := param.QueryString(r, "rule")
		if paramErr == nil && len(ruleKey) > 0 {
			queryOpt.RuleKey = ruleKey
		} else if paramErr != nil && paramErr != param.ErrInvalidParam {
			logging.Get().Warn().Err(paramErr).Msg("fail to parse rule")
		}

		ruleCategories, paramErr := param.QueryString(r, "ruleCategory")
		if paramErr == nil && len(ruleCategories) > 0 {
			queryOpt.RuleCategories = strings.Split(ruleCategories, ",")
		} else if paramErr != nil && paramErr != param.ErrInvalidParam {
			logging.Get().Warn().Err(paramErr).Msg("fail to parse ruleCategory")
		}

		id, paramErr := param.QueryUint64(r, "id")
		if paramErr == nil && id > 0 {
			queryOpt.ID = id
		} else if paramErr != nil && paramErr != param.ErrInvalidParam {
			logging.Get().Warn().Err(paramErr).Msg("fail to parse id")
		}

		customKeys, paramErr := param.QueryString(r, "customKey")
		if paramErr == nil && len(customKeys) > 0 {
			queryOpt.CconfigKeys = strings.Split(customKeys, ",")
		} else if paramErr != nil && paramErr != param.ErrInvalidParam {
			logging.Get().Warn().Err(paramErr).Msg("fail to parse customKey")
		}

		offset, paramErr := param.QueryInt(r, "offset")
		if paramErr != nil || offset < 0 {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("illegal offset %v", paramErr)))
			return
		}
		limit, paramErr := param.QueryInt(r, "limit")
		if paramErr != nil || limit < 0 {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("illegal limit %v", paramErr)))
			return
		}

		query, paramErr := param.QueryString(r, "query")
		if paramErr == nil || len(query) > 0 {
			queryOpt.Query = query
		} else if paramErr != nil && paramErr != param.ErrInvalidParam {
			logging.Get().Warn().Err(paramErr).Msg("fail to parse customKey")
		}
		queryOpt.Statuses = []model.CconfigStatus{model.StatusOK, model.StatusPending, model.StatusExpired}

		configs, totalCnt, err := service.GetCustomConfigs(ctx, queryOpt, limit, offset, lang)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError,
				fmt.Errorf("get error %v", err)))
			return
		}

		response.Ok(w, response.WithItems(configs),
			response.WithStartIndex(int64(offset)),
			response.WithItemsPerPage(int64(limit)),
			response.WithTotalItems(int64(totalCnt)))
	}
}

func (api *api) editCustomConfigs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		lang := r.Header.Get("Accept-Language")
		if lang == "" {
			lang = "zh"
		}
		var cconfigsList []*attck.CconfigUpdateItem
		jerr := util.DecodeJSONBody(w, r, &cconfigsList)
		if jerr != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("parse body error %v", jerr)))
			return
		}

		err := service.BatchEditCustomConfigs(ctx, cconfigsList)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError,
				fmt.Errorf("get error %v", err)))
			return
		}
		b := strings.Builder{}
		for i, c := range cconfigsList {
			b.WriteByte('"')
			if len(c.RuleKey) > 0 {
				rinfo, exist := service.GetRuleInfo(ctx, c.RuleKey)
				if exist && rinfo != nil {
					b.WriteString(rinfo.Name[lang])
				} else {
					b.WriteString(c.RuleKey)
				}
			} else if c.ID > 0 {
				opt := attck.CustomConfigsQueryOption{
					ID: c.ID,
				}
				list, _, err := service.GetCustomConfigs(ctx, opt, 1, 0, "zh")
				if err == nil && len(list) == 1 {
					b.WriteString(list[0].Rule.Name)
				} else if err != nil {
					logging.Get().Warn().Err(err).Msg("get rule error")
					b.WriteString(strconv.FormatUint(c.ID, 10))
				} else {
					b.WriteString(strconv.FormatUint(c.ID, 10))
				}
			}

			b.WriteByte('"')
			if i < len(cconfigsList)-1 {
				b.WriteString(", ")
			}
		}
		response.Ok(w, response.WithTarget(&response.TargetRef{ID: fmt.Sprintf("%d", 0), Name: b.String()}))
	}
}

func (api *api) addCustomConfigs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		lang := r.Header.Get("Accept-Language")
		if lang == "" {
			lang = "zh"
		}
		var cconfigsList []*attck.CconfigUpdateItem
		jerr := util.DecodeJSONBody(w, r, &cconfigsList)
		if jerr != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("parse body error %v", jerr)))
			return
		}

		err := service.BatchAddCustomConfigs(ctx, cconfigsList)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError,
				fmt.Errorf("get error %v", err)))
			return
		}

		b := strings.Builder{}
		for i, c := range cconfigsList {
			b.WriteByte('"')
			if len(c.RuleKey) > 0 {
				rinfo, exist := service.GetRuleInfo(ctx, c.RuleKey)
				if exist && rinfo != nil {
					b.WriteString(rinfo.Name[lang])
				} else {
					b.WriteString(c.RuleKey)
				}
			} else if c.ID > 0 {
				opt := attck.CustomConfigsQueryOption{
					ID: c.ID,
				}
				list, _, err := service.GetCustomConfigs(ctx, opt, 1, 0, "zh")
				if err == nil && len(list) == 1 {
					b.WriteString(list[0].Rule.Name)
				} else if err != nil {
					logging.Get().Warn().Err(err).Msg("get rule error")
					b.WriteString(strconv.FormatUint(c.ID, 10))
				} else {
					b.WriteString(strconv.FormatUint(c.ID, 10))
				}
			}
			b.WriteByte('"')
			if i < len(cconfigsList)-1 {
				b.WriteString(", ")
			}
		}

		response.Ok(w, response.WithTarget(&response.TargetRef{ID: fmt.Sprintf("%d", 0), Name: b.String()}))
	}
}

func (api *api) deleteCustomConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}
		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("nil id")))
			return
		}
		id, perr := strconv.ParseUint(idStr, 10, 64)
		if perr != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("id parse error: %v. input: %s", perr, idStr)))
			return
		}
		err := service.UpdateCustomConfigStatus(ctx, id, model.StatusDeleted)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError,
				fmt.Errorf("get error %v", err)))
			return
		}
		opt := attck.CustomConfigsQueryOption{
			ID: id,
		}
		list, _, err := service.GetCustomConfigs(ctx, opt, 1, 0, "zh")
		ruleName := "unknown"
		if err == nil && len(list) == 1 {
			ruleName = list[0].Rule.Name
		} else if err != nil {
			logging.Get().Warn().Err(err).Msg("get rule error")
		}
		response.Ok(w, response.WithTarget(&response.TargetRef{ID: fmt.Sprintf("%d", 0), Name: fmt.Sprintf("\"%s\"", ruleName)}))
	}
}

func (api *api) getATTCKLatestData() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		version1, err := param.QueryUint16(r, "curVersion")
		if err != nil {
			// 老版本的holmes和cluster-manager不会传该参数，默认版本号为 1
			version1 = 1
		}
		curDataVersion, err := param.QueryUint64(r, "curDataVersion")
		if err != nil {
			curDataVersion = 0
		}
		curSettingVersion, err := param.QueryUint64(r, "curSettingVersion")
		if err != nil {
			curSettingVersion = 0
		}

		info, err := service.GetATTCKConfData(ctx, curDataVersion, curSettingVersion, version1)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItem(*info), response.WithApiVersion(versionAPIVersion))
	}
}

func (api *api) updateATTCKConf() http.HandlerFunc {
	type rsp struct {
		Version        string `json:"version"`
		LastUpdateTime int64  `json:"lastUpdateTime"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
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

		logging.Get().Debug().Msgf("filename:%s", header.Filename)
		item, err := service.UpdateConfig(ctx, username, data)
		if err != nil {
			if err == attck.ErrInvalidRuleData {
				apperror.RespAndLog(w, ctx,
					apperror.NewFieldError(http.StatusBadRequest, err))
				return
			}
			if err == attck.ErrVersionNotUpper {
				apperror.RespAndLog(w, ctx,
					apperror.NewAttackVersionNotUpperErr(http.StatusBadRequest, err))
				return
			}

			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItem(rsp{
			Version:        item.VString(),
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
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		version1, err := param.QueryUint16(r, "version1")
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
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

		total, ruleList, err := service.GetRuleList(ctx, &attck.GetRuleListArg{
			Offset:         int(offset),
			Limit:          int(limit),
			SeverityFilter: severityFilter,
			HthreatsFilter: hthreatsFilter,
			Query:          query,
			Lang:           string(lang.Language(ctx)),
		}, version1)
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
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		var items struct {
			Items    []*model.ATTCKRuleSwitch `json:"items"`
			Version1 uint16                   `json:"version1"`
		}
		err := util.DecodeJSONBody(w, r, &items)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		switches, err := service.UpdateRuleSettings(ctx, items.Items, items.Version1)
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
