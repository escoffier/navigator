package api

import (
	"context"
	"fmt"
	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"net/http"
	"time"
)

const (
	eventCenterDefaultTimeout = time.Second * 5
	eventCenterApiVersion     = "2.0"
)

const (
	maxEventBatchSize = 100
)

func (api *api) eventsCenter() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/", api.getEvents())
		r.Get("/updates", api.checkEventUpdates())
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

	hashKind = map[model.AlertKind]pb.EventKind{
		model.AlertKindReverseShellAttack:         pb.EventKind_ReverseShellAttack,
		model.AlertKindComplianceCheck:            pb.EventKind_ComplianceCheck,
		model.AlertKindVulnerabilityExploitAttack: pb.EventKind_VulnerabilityExploitAttack,
		model.AlertKindDriftPrevention:            pb.EventKind_DriftPrevention,
		model.AlertKindSeccompProfile:             pb.EventKind_SeccompProfile,
		model.AlertKindAttck:                      pb.EventKind_Attck,
	}
)

func convertSeverityToString(severity uint32) string {
	switch severity {
	case 0:
		return redclair.SeverityNone
	case 1, 2:
		return redclair.SeverityNegligible
	case 3, 4:
		return redclair.SeverityLow
	case 5, 6:
		return redclair.SeverityMedium
	case 7, 8:
		return redclair.SeverityHigh
	default:
		return redclair.SeverityCritical
	}
}

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
		Severity       string            `json:"severity"`
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

	convert := func(pbEvents []*pb.Event) []*Event {
		var events = make([]*Event, 0, len(pbEvents))
		for _, event := range pbEvents {
			var history = make([]*History, 0, len(event.History))
			for _, h := range event.History {
				history = append(history, &History{
					PodUID:    h.PodUID,
					PodName:   h.PodName,
					Timestamp: h.Timestamp,
					CustomKV:  h.CustomKV,
				})
			}
			events = append(events, &Event{
				ID:        event.ID,
				Cluster:   event.Cluster,
				Namespace: event.Cluster,
				NodeType:  event.NodeType,
				NodeKey:   event.NodeKey,
				Rule: &Rule{
					Name:           event.Rule.Name,
					Module:         event.Rule.Module,
					Category:       event.Rule.Category,
					Description:    event.Rule.Description,
					CustomKV:       event.Rule.CustomKV,
					DisplayAdapter: event.Rule.DisplayAdapter,
					Severity:       convertSeverityToString(event.Rule.Severity),
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
			apperror.RespAndLog(w, r.Context(), err)
			return
		}

		sortOrder, err := api.sortOrderFromQuery(r, "desc")
		if err != nil {
			apperror.RespAndLog(w, r.Context(), err)
			return
		}

		kind, err := model.AlertKindFromQuery(r)
		if err != nil {
			apperror.RespAndLog(w, r.Context(), err)
			return
		}

		rsp, err := api.ecCli.GetEvents(ctx, &pb.GetEventsReq{
			Offset:    int32(offset),
			Limit:     int32(limit),
			SortOrder: hashSortOrder[sortOrder],
			SortBy:    hashSortBy[sortBy],
			Kind:      hashKind[kind],
			Lang:      string(lang.Language(ctx)),
		})
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("GetEvents fail, err:%s", err.Error())))
			return
		}

		response.Ok(w,
			response.WithApiVersion(eventCenterApiVersion),
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
			apperror.RespAndLog(w, r.Context(), err)
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
			response.Ok(w, response.WithItem(resp))
			return
		}

		resp := checkEventUpdatesRsp{
			HasUpdates:    rsp.HasUpdates,
			NewCursor:     rsp.NewestTimestamp,
			UpdatesNumStr: rsp.UpdateNumStr,
		}

		response.Ok(w, response.WithApiVersion(eventCenterApiVersion), response.WithItem(resp))
	}
}
