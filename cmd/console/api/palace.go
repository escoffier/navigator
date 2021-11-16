package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/palace"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) palace() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/assoc_graph_events", api.getAssocGraphEvents())
		r.Get("/event/{evtID}/process_tree", api.getProcessTree())
		r.Get("/event/{evtID}/signals", api.getAGEventSignals())
	}
}

func (api *api) getAssocGraphEvents() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			limit = 10
			offset = 0
		}

		palaceSvc, ok := palace.Get()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("init palace error")))
			return
		}
		events, totalCnt, err := palaceSvc.GetAssociatedEvents(ctx, *dal.Sort().With("updated_at"), offset, limit)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(events), response.WithTotalItems(totalCnt))
	}
}

func (api *api) getProcessTree() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()

		evtIDStr := chi.URLParam(r, "evtID")
		if evtIDStr == "" {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error evtID")))
			return
		}
		evtID, err := strconv.ParseInt(evtIDStr, 10, 64)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, err))
			return
		}
		palaceSvc, ok := palace.Get()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("no limit or offset given in params")))
			return
		}
		tree, err := palaceSvc.GetProcessTree(ctx, evtID)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItem(tree))
	}
}

func (api *api) getAGEventSignals() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			limit = 10
			offset = 0
		}

		evtIDStr := chi.URLParam(r, "evtID")
		if evtIDStr == "" {
			RespAndLog(w, ctx, NewAnError(400, errors.New("error evtID")))
			return
		}
		evtID, err := strconv.ParseInt(evtIDStr, 10, 64)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(400, err))
			return
		}
		palaceSvc, ok := palace.Get()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("no limit or offset given in params")))
			return
		}

		query := dal.NewSignalsQuery()
		selections, err := param.QueryStringArray(r, "selection")
		if err == nil {
			query = query.WithAggrKeys(selections)
		}

		signals, totalCnt, err := palaceSvc.GetSignalsOfEvent(ctx, evtID, query, offset, limit)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(signals), response.WithTotalItems(totalCnt))
	}
}
