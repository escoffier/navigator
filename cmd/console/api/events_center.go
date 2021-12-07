package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/pb"
	"google.golang.org/grpc/status"
)

const (
	eventCenterDefaultTimeout = time.Second * 5
	eventCenterAPIVersion     = "2.0"
)

const (
	maxEventBatchSize  = 100
	maxSignalBatchSize = 20
)

func (api *api) eventsCenter() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/", api.getEvents())
		r.Get("/updates", api.checkEventUpdates())
		r.Get("/rules", api.getRules())
		r.Get("/signals", api.getSignals())
		r.Get("/statistics", api.getStatistics())
		r.Get("/signalProcessTree", api.getSignalProcessTree())
		r.Get("/config", api.getEventCenterConfig())
		r.Post("/config", api.updateEventCenterConfig())
		r.Get("/config/syslog", api.GetEventCenterSyslogConfig())
		r.Post("/config/syslog", api.SetEventCenterSyslogConfig())
		r.Get("/warn", api.checkNeedAlert())
	}
}

var (
	hashSortBy = map[string]pb.SortBy{
		"timestamp": pb.SortBy_Timestamp,
		"severity":  pb.SortBy_Severity,
	}

	hashSortOrder = map[string]pb.SortOrder{
		"desc": pb.SortOrder_Desc,
		"asc":  pb.SortOrder_Asc,
	}
)

func (api *api) getEvents() http.HandlerFunc {
	type History struct {
		PodUID    string            `json:"podUid"`
		PodName   string            `json:"podName"`
		Timestamp int64             `json:"timestamp"`
		CustomKV  map[string]string `json:"customKV"`
	}

	type Rule struct {
		Name           string            `json:"name"`
		Module         string            `json:"module"`
		Category       string            `json:"category"`
		Description    string            `json:"description"`
		Severity       uint32            `json:"severity"`
		CustomKV       map[string]string `json:"customKV"`
		DisplayAdapter map[string]string `json:"displayAdapter"`
	}

	type Event struct {
		ID        int32      `json:"id"`
		Cluster   string     `json:"cluster"`
		Namespace string     `json:"namespace"`
		NodeType  string     `json:"nodeType"`
		NodeKey   string     `json:"nodeKey"`
		Rule      *Rule      `json:"rule"`
		History   []*History `json:"history"`
		Timestamp int64      `json:"timestamp"`
	}

	convert := func(pbEvents []*pb.AssociationEvent) []*Event {
		var events = make([]*Event, 0, len(pbEvents))
		for _, event := range pbEvents {
			timeWindowEvent, ok := event.Detail.Content.(*pb.EventDetail_TimeWindow)
			if !ok {
				continue
			}

			detail := timeWindowEvent.TimeWindow

			var history = make([]*History, 0, len(detail.History))
			for _, h := range detail.History {
				history = append(history, &History{
					PodUID:    h.PodUID,
					PodName:   h.PodName,
					Timestamp: h.Timestamp,
					CustomKV:  h.CustomKV,
				})
			}
			events = append(events, &Event{
				ID:        event.ID,
				Cluster:   detail.Cluster,
				Namespace: detail.Namespace,
				NodeType:  detail.NodeType,
				NodeKey:   detail.NodeKey,
				Rule: &Rule{
					Name:           event.Rule.Name,
					Module:         event.Rule.Module,
					Category:       event.Rule.Category,
					Description:    event.Rule.Description,
					CustomKV:       event.Rule.CustomKV,
					DisplayAdapter: event.Rule.DisplayAdapter,
					Severity:       event.Rule.Severity,
				},
				History:   history,
				Timestamp: event.Timestamp,
			})
		}

		return events
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), eventCenterDefaultTimeout)
		defer cancel()

		offset, limit := api.getOffsetAndLimit(r)
		if limit > maxEventBatchSize {
			limit = maxEventBatchSize
		}

		sortBy, err := api.sortByFromQuery(r, model.GetDefaultAlertSortableName(), model.GetAlertSortableNames()...)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		sortOrder, err := api.sortOrderFromQuery(r, "desc")
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		kind := r.URL.Query().Get("kind")

		id, _ := param.QueryInt(r, "id")
		rsp, err := api.ecCli.GetAssociationEvents(ctx, &pb.GetAssociationEventsReq{
			ID:         int32(id),
			Offset:     int32(offset),
			Limit:      int32(limit),
			SortOrder:  hashSortOrder[sortOrder],
			SortBy:     hashSortBy[sortBy],
			RuleFilter: kind,
			Lang:       string(lang.Language(ctx)),
		})
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("GetEvents fail, err:%s", err.Error())))
			return
		}

		response.Ok(w,
			response.WithApiVersion(eventCenterAPIVersion),
			response.WithItems(convert(rsp.Events)))
	}
}

func (api *api) checkEventUpdates() http.HandlerFunc {
	type checkEventUpdatesRsp struct {
		HasUpdates    bool   `json:"hasUpdates"`
		NewCursor     int64  `json:"newCursor"`
		UpdatesNumStr string `json:"updatesNumStr"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), eventCenterDefaultTimeout)
		defer cancel()

		currentCursor, err := param.QueryInt64(r, "cursor")
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(http.StatusBadRequest, err))
			return
		}

		rsp, err := api.ecCli.CheckEventUpdate(ctx, &pb.CheckEventUpdateReq{
			Timestamp: currentCursor,
		})
		if err != nil {
			logging.GetLogger().Warn().Msgf("CheckEventUpdate fail, err: %s", err.Error())
			resp := checkEventUpdatesRsp{
				HasUpdates:    false,
				NewCursor:     0,
				UpdatesNumStr: "0",
			}
			response.Ok(w, response.WithApiVersion(eventCenterAPIVersion), response.WithItem(resp))
			return
		}

		resp := checkEventUpdatesRsp{
			HasUpdates:    rsp.HasUpdates,
			NewCursor:     rsp.NewestTimestamp,
			UpdatesNumStr: rsp.UpdateNumStr,
		}

		response.Ok(w, response.WithApiVersion(eventCenterAPIVersion), response.WithItem(resp))
	}
}

func (api *api) getRules() http.HandlerFunc {
	type RuleItem struct {
		Name           string `json:"name"`
		DisplayAdapter string `json:"displayAdapter"`
	}
	type Category struct {
		Name           string      `json:"name"`
		DisplayAdapter string      `json:"displayAdapter"`
		Rules          []*RuleItem `json:"rules"`
	}
	type Module struct {
		Name           string      `json:"name"`
		DisplayAdapter string      `json:"displayAdapter"`
		Categories     []*Category `json:"categories"`
	}

	type getRulesRsp struct {
		Modules []*Module `json:"modules"`
	}

	convert := func(rsp *pb.GetRuleCategoriesRsp) *getRulesRsp {
		result := &getRulesRsp{
			Modules: make([]*Module, 0, len(rsp.Modules)),
		}
		for _, module := range rsp.Modules {
			m := &Module{
				Name:           module.Name,
				DisplayAdapter: module.NameAdapter,
				Categories:     make([]*Category, 0, len(module.Categories)),
			}
			for _, category := range module.Categories {
				c := &Category{
					Name:           category.Name,
					DisplayAdapter: category.NameAdapter,
					Rules:          make([]*RuleItem, 0, len(category.Items)),
				}

				for _, item := range category.Items {
					c.Rules = append(c.Rules, &RuleItem{
						Name:           item.Name,
						DisplayAdapter: item.NameAdapter,
					})
				}
				m.Categories = append(m.Categories, c)
			}

			result.Modules = append(result.Modules, m)
		}

		return result
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), eventCenterDefaultTimeout)
		defer cancel()
		rsp, err := api.ecCli.GetRuleCategories(ctx, &pb.GetRuleCategoriesReq{
			Lang: string(lang.Language(ctx)),
		})

		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("GetRuleCategories fail, err:%s", err.Error())))
			return
		}

		response.Ok(w, response.WithApiVersion(eventCenterAPIVersion), response.WithItem(*convert(rsp)))
	}
}

type rule struct {
	Name           string            `json:"name"`
	Module         string            `json:"module"`
	Category       string            `json:"category"`
	Description    string            `json:"description"`
	Severity       uint32            `json:"severity"`
	CustomKV       map[string]string `json:"customKV"`
	DisplayAdapter map[string]string `json:"displayAdapter"`
}

type signal struct {
	ID        string            `json:"id"`
	Cluster   string            `json:"cluster"`
	Namespace string            `json:"namespace"`
	NodeType  string            `json:"nodeType"`
	NodeKey   string            `json:"nodeKey"`
	Rule      *rule             `json:"rule"`
	PodUID    string            `json:"podUid"`
	PodName   string            `json:"podName"`
	CustomKV  map[string]string `json:"customKV"`
	Timestamp int64             `json:"timestamp"`
}

func (api *api) getSignals() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), eventCenterDefaultTimeout)
		defer cancel()

		offsetID, err := param.QueryString(r, "offsetID")
		if err != nil {
			offsetID = ""
		}

		limit, err := param.QueryUint(r, "limit")
		if err != nil {
			limit = maxSignalBatchSize
		}

		if limit > maxSignalBatchSize {
			limit = maxSignalBatchSize
		}

		startTimestamp, err := param.QueryInt64(r, "startTimestamp")
		if err != nil {
			startTimestamp = 0
		}

		endTimestamp, err := param.QueryInt64(r, "endTimestamp")
		if err != nil {
			endTimestamp = 0
		}

		if startTimestamp > endTimestamp || startTimestamp < 0 {
			apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(http.StatusBadRequest, fmt.Errorf("invalid time range")))
			return
		}

		sortOrder, err := api.sortOrderFromQuery(r, "desc")
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		var filter map[string]string
		filterStr, err := param.QueryString(r, "filter")
		if err == nil && filterStr != "" {
			logging.GetLogger().Debug().Msgf("filter:%s", filterStr)
			err = json.Unmarshal([]byte(filterStr), &filter)
			if err != nil {
				logging.GetLogger().Warn().Msgf("invalid filter:%s", filterStr)
				apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(http.StatusBadRequest, err))
				return
			}
		}

		req := &pb.GetSignalsReq{
			OffsetSignalID: offsetID,
			Limit:          uint32(limit),
			SortOrder:      hashSortOrder[sortOrder],
			Filter:         filter,
			Lang:           string(lang.Language(ctx)),
		}

		if startTimestamp > 0 && endTimestamp > 0 {
			req.TimeFilter = &pb.TimeFilter{
				StartTimestamp: startTimestamp,
				EndTimestamp:   endTimestamp,
			}
		}

		rsp, err := api.ecCli.GetSignals(ctx, req)

		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("GetSignals fail, err:%s", err.Error())))
			return
		}

		response.Ok(w,
			response.WithApiVersion(eventCenterAPIVersion),
			response.WithItems(convertSignals(rsp.Signals)))
	}
}

func (api *api) getStatistics() http.HandlerFunc {
	type statisticsItem struct {
		StartTimestamp int64  `json:"startTimestamp"`
		EndTimestamp   int64  `json:"endTimestamp"`
		Count          uint32 `json:"count"`
	}

	type getStatisticsRsp struct {
		DaysStatistics  []*statisticsItem `json:"daysStatistics"`
		HoursStatistics []*statisticsItem `json:"hoursStatistics"`
	}

	convert := func(rsp *pb.GetStatisticsRsp) *getStatisticsRsp {
		result := &getStatisticsRsp{
			DaysStatistics:  make([]*statisticsItem, 0, len(rsp.DayStatistics)),
			HoursStatistics: make([]*statisticsItem, 0, len(rsp.HourStatistics)),
		}

		for i := range rsp.DayStatistics {
			result.DaysStatistics = append(result.DaysStatistics, &statisticsItem{
				StartTimestamp: rsp.DayStatistics[i].BeginTimestamp,
				EndTimestamp:   rsp.DayStatistics[i].EndTimestamp,
				Count:          rsp.DayStatistics[i].Count,
			})
		}

		for i := range rsp.HourStatistics {
			result.HoursStatistics = append(result.HoursStatistics, &statisticsItem{
				StartTimestamp: rsp.HourStatistics[i].BeginTimestamp,
				EndTimestamp:   rsp.HourStatistics[i].EndTimestamp,
				Count:          rsp.HourStatistics[i].Count,
			})
		}

		return result
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), eventCenterDefaultTimeout)
		defer cancel()

		days, hours, err := getStatisticsParam(r)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, fmt.Errorf("invalid args")))
			return
		}

		rsp, err := api.ecCli.GetStatistics(ctx, &pb.GetStatisticsReq{Days: uint32(days), Hours: uint32(hours)})
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("GetStatistics fail, err:%s", err.Error())))
			return
		}

		response.Ok(w, response.WithApiVersion(eventCenterAPIVersion), response.WithItem(*convert(rsp)))
	}
}

const (
	maxStatisticsDays  = 30
	maxStatisticsHours = 24
)

func getStatisticsParam(r *http.Request) (days, hours uint, err error) {
	days, err = param.QueryUint(r, "days")
	if err != nil {
		return 0, 0, err
	}

	hours, err = param.QueryUint(r, "hours")
	if err != nil {
		return 0, 0, err
	}

	if days > maxStatisticsDays {
		days = maxStatisticsDays
	}

	if hours > maxStatisticsHours {
		hours = maxStatisticsHours
	}

	return days, hours, err
}

func (api *api) getSignalProcessTree() http.HandlerFunc {
	type processNode struct {
		ProcessName  string         `json:"processName"`
		PProcessName string         `json:"pProcessName"`
		PID          string         `json:"pid"`
		PPID         string         `json:"ppid"`
		Signals      []*signal      `json:"signals"`
		Children     []*processNode `json:"children"`
	}

	var convert func(node *pb.ProcessNode) *processNode
	convert = func(node *pb.ProcessNode) *processNode {
		result := &processNode{
			ProcessName:  node.ProcessName,
			PProcessName: node.PProcessName,
			PID:          node.PID,
			PPID:         node.PPID,
			Signals:      convertSignals(node.Signals),
			Children:     make([]*processNode, 0, len(node.Children)),
		}

		for _, child := range node.Children {
			result.Children = append(result.Children, convert(child))
		}

		return result
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), eventCenterDefaultTimeout)
		defer cancel()

		cluster, err := param.QueryString(r, "cluster")
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, fmt.Errorf("invalid cluster")))
			return
		}

		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, fmt.Errorf("invalid namespace")))
			return
		}

		podName, err := param.QueryString(r, "podName")
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, fmt.Errorf("invalid podName")))
			return
		}

		timestamp, err := param.QueryInt64(r, "timestamp")
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, fmt.Errorf("invalid timestamp")))
			return
		}

		rsp, err := api.ecCli.GetATTCKPodProcessSignalTree(ctx, &pb.GetATTCKPodProcessSignalTreeReq{
			Cluster:   cluster,
			Namespace: namespace,
			PodName:   podName,
			Timestamp: timestamp,
			Lang:      string(lang.Language(ctx)),
		})
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("GetATTCKPodProcessSignalTree fail, err:%s", err.Error())))
			return
		}

		var items = make([]*processNode, 0, len(rsp.Nodes))
		for _, node := range rsp.Nodes {
			items = append(items, convert(node))
		}

		response.Ok(w, response.WithApiVersion(eventCenterAPIVersion), response.WithItems(items))
	}
}

func convertSignals(signals []*pb.Signal) []*signal {
	result := make([]*signal, 0, len(signals))
	for _, item := range signals {
		result = append(result, &signal{
			ID:        item.ID,
			Cluster:   item.Cluster,
			Namespace: item.Namespace,
			NodeType:  item.NodeType,
			NodeKey:   item.NodeKey,
			Rule: &rule{
				Name:           item.Rule.Name,
				Module:         item.Rule.Module,
				Category:       item.Rule.Category,
				Description:    item.Rule.Description,
				Severity:       item.Severity,
				CustomKV:       item.Rule.CustomKV,
				DisplayAdapter: item.Rule.DisplayAdapter,
			},
			PodUID:    item.PodUID,
			PodName:   item.PodName,
			CustomKV:  item.CustomKV,
			Timestamp: item.Timestamp,
		})
	}
	return result
}

func (api *api) getEventCenterConfig() http.HandlerFunc {
	type rsp struct {
		WarnSeverity     uint32   `json:"warnSeverity"`
		MailNotification bool     `json:"mailNotification"`
		Mails            []string `json:"mails"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), eventCenterDefaultTimeout)
		defer cancel()
		setting, err := api.ecCli.GetNotifySettings(ctx, &pb.GetNotifySettingsReq{})
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("GetNotifySettings fail, err:%s", err.Error())))
			return
		}

		response.Ok(w, response.WithApiVersion(eventCenterAPIVersion), response.WithItem(rsp{
			WarnSeverity:     setting.ThresholdSeverity,
			Mails:            setting.Emails,
			MailNotification: setting.EmailNotification,
		}))
	}
}

func (api *api) updateEventCenterConfig() http.HandlerFunc {
	type req struct {
		WarnSeverity     uint32   `json:"warnSeverity"`
		MailNotification bool     `json:"mailNotification"`
		Mails            []string `json:"mails"`
	}

	checkReq := func(r req) bool {
		if r.WarnSeverity > 10 {
			return false
		}

		if r.MailNotification && len(r.Mails) == 0 {
			return false
		}

		return true
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), dataDefaultTimeout)
		defer cancel()
		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if !checkReq(cliReq) {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, fmt.Errorf("invalid req")))
			return
		}

		_, err = api.ecCli.UpdateNotifySettings(ctx, &pb.UpdateNotifySettingsReq{
			EmailNotification: cliReq.MailNotification,
			Emails:            cliReq.Mails,
			ThresholdSeverity: cliReq.WarnSeverity,
		})
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("UpdateNotifySettings fail, err:%s", err.Error())))
			return
		}

		response.Ok(w, response.WithItem(cliReq), response.WithApiVersion(eventCenterAPIVersion))
	}
}

func (api *api) checkNeedAlert() http.HandlerFunc {
	type rsp struct {
		NeedAlert bool `json:"needAlert"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), eventCenterDefaultTimeout)
		defer cancel()

		timestamp, err := param.QueryInt64(r, "timestamp")
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(http.StatusBadRequest, err))
			return
		} else if timestamp < 0 {
			apperror.RespAndLog(w, ctx, fmt.Errorf("timestamp invalid"))
			return
		}

		interval, err := param.QueryInt64(r, "interval")
		if err != nil || interval < 0 {
			apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(http.StatusBadRequest, err))
			return
		}

		result, err := api.ecCli.CheckNeedAlert(ctx, &pb.CheckNeedAlertReq{
			Timestamp: timestamp,
			Interval:  interval,
		})

		if err != nil {
			logging.GetLogger().Warn().Msgf("CheckEventUpdate fail, err: %s", err.Error())
			response.Ok(w, response.WithApiVersion(eventCenterAPIVersion), response.WithItem(rsp{}))
			return
		}

		response.Ok(w, response.WithApiVersion(eventCenterAPIVersion), response.WithItem(rsp{
			NeedAlert: result.NeedAlert,
		}))
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

func (api *api) GetEventCenterSyslogConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), eventCenterDefaultTimeout)
		defer cancel()

		setting, err := api.ecCli.GetSyslogSettings(ctx, &pb.GetSyslogSettingsReq{})
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("GetSyslogSettings fail, err:%s", err.Error())))
			return
		}

		response.Ok(w, response.WithApiVersion(eventCenterAPIVersion), response.WithItem(*convertSyslogSettingFromPb(setting.Setting)))
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

func (api *api) SetEventCenterSyslogConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), eventCenterDefaultTimeout)
		defer cancel()
		var setting syslogSetting
		err := util.DecodeJSONBody(w, r, &setting)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		_, err = api.ecCli.UpdateSyslogSettings(ctx, &pb.UpdateSyslogSettingsReq{Setting: convertSyslogSettingToPb(&setting)})
		if err != nil {
			if s, ok := status.FromError(err); ok && s.Code() == 400 {
				apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(http.StatusBadRequest, err))
				return
			}

			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(eventCenterAPIVersion), response.WithItem(setting))
	}
}
