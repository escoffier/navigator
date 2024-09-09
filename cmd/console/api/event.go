package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/event"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const defaultTimeout = time.Second * 3

func (api *api) event() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/config", api.configEventConfig())
		// r.Get("/config", api.getEventConfig())
		r.Get("/eventTypes", api.getEventTypes())
		r.Get("/noauth/config", api.getEventConfig())
	}
}

func (api *api) getEventConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()

		svc, ok := event.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get event config service failed")))
			return
		}

		eventConfig, err := svc.GetConfig(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItem(eventConfig))
	}
}

func (api *api) configEventConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()

		config := event.EventNotifyConfig{}
		err := util.DecodeJSONBody(w, r, &config)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		svc, ok := event.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get event config service failed")))
			return
		}

		err = svc.Config(ctx, config)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithTarget(&response.TargetRef{
			Description:   "编辑事件通知配置",
			DescriptionEN: "Edit configuration of event notify",
		}))
	}
}

type EventType struct {
	Key   string `json:"value"`
	Label string `json:"label"`
}

var EventTypeMap = map[string][]EventType{
	"en": {
		{"ATT&CK", "ATT&CK"},
		{"Watson", "Watson"},
		{"DriftPrevention", "DriftPrevention"},
		{"ImmuneDefense", "ImmuneDefense"},
		{"Malware", "Malware"},
	},
	"zh": {
		{"ATT&CK", "ATT&CK"},
		{"Watson", "主动防御"},
		{"DriftPrevention", "偏移防御"},
		{"ImmuneDefense", "免疫防御"},
		{"Malware", "病毒木马"},
	},
}

func (api *api) getEventTypes() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		// defer cancel()

		lang := r.Header.Get("Accept-Language")

		// lang := request.LanguageFromCtx(c)
		var result []EventType
		if lang == "zh" {
			result = EventTypeMap["zh"]
		} else {
			result = EventTypeMap["en"]
		}

		response.Ok(w, response.WithItems(result))
		// encoding.HandleSuccessList(c, int64(len(result)), result)
	}
}
