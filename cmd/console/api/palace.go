package api

import (
	"github.com/go-chi/chi"
)

func (api *api) palace() func(chi.Router) {
	return func(r chi.Router) {
		// deprecated
		// r.Get("/assoc_graph_events", api.getAssocGraphEvents())
		// r.Get("/event/{evtID}/process_tree", api.getProcessTree())
		// r.Get("/event/{evtID}/signals", api.getAGEventSignals())
	}
}

//
// func (api *api) getAssocGraphEvents() http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		ctx := context.Background()
//
// 		limitStr, err := param.QueryString(r, "limit")
// 		if err != nil {
// 			limitStr = "10"
// 		}
// 		limit, err := strconv.Atoi(limitStr)
// 		if err != nil {
// 			RespAndLog(w, ctx, NewAnError(400, errors.New("error limit")))
// 			return
// 		}
// 		offsetStr, err := param.QueryString(r, "offset")
// 		if err != nil {
// 			offsetStr = "0"
// 		}
// 		offsetID, err := strconv.ParseInt(offsetStr, 10, 64)
// 		if err != nil {
// 			offsetID = 0
// 		}
//
// 		palaceSvc, ok := palace.Get()
// 		if !ok {
// 			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("init palace error")))
// 			return
// 		}
// 		events, totalCnt, err := palaceSvc.GetAssociatedEvents(ctx, offsetID, limit)
// 		if err != nil {
// 			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
// 			return
// 		}
// 		response.Ok(w, response.WithItems(events), response.WithTotalItems(totalCnt))
// 	}
// }
//
// func (api *api) getProcessTree() http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		ctx := context.Background()
//
// 		evtIDStr := chi.URLParam(r, "evtID")
// 		if evtIDStr == "" {
// 			RespAndLog(w, ctx, NewAnError(400, errors.New("error evtID")))
// 			return
// 		}
// 		evtID, err := strconv.ParseInt(evtIDStr, 10, 64)
// 		if err != nil {
// 			RespAndLog(w, ctx, NewAnError(400, err))
// 			return
// 		}
// 		palaceSvc, ok := palace.Get()
// 		if !ok {
// 			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("no limit or offset given in params")))
// 			return
// 		}
// 		tree, err := palaceSvc.GetProcessTree(ctx, evtID)
// 		if err != nil {
// 			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
// 			return
// 		}
// 		response.Ok(w, response.WithItem(tree))
// 	}
// }
//
// func (api *api) getAGEventSignals() http.HandlerFunc {
//
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		ctx := context.Background()
//
// 		limitStr, err := param.QueryString(r, "limit")
// 		if err != nil {
// 			limitStr = "10"
// 		}
// 		limit, err := strconv.Atoi(limitStr)
// 		if err != nil {
// 			RespAndLog(w, ctx, NewAnError(400, errors.New("error limit")))
// 			return
// 		}
// 		offsetStr, err := param.QueryString(r, "offset_ts")
// 		if err != nil {
// 			offsetStr = "0"
// 		}
// 		offsetTS, err := strconv.ParseInt(offsetStr, 10, 64)
// 		if err != nil {
// 			offsetTS = 0
// 		}
// 		var offsetTime time.Time
// 		if offsetTS > 0 {
// 			offsetTime = time.Unix(offsetTS, 0)
// 		}
//
// 		evtIDStr := chi.URLParam(r, "evtID")
// 		if evtIDStr == "" {
// 			RespAndLog(w, ctx, NewAnError(400, errors.New("error evtID")))
// 			return
// 		}
// 		evtID, err := strconv.ParseInt(evtIDStr, 10, 64)
// 		if err != nil {
// 			RespAndLog(w, ctx, NewAnError(400, err))
// 			return
// 		}
// 		palaceSvc, ok := palace.Get()
// 		if !ok {
// 			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("no limit or offset given in params")))
// 			return
// 		}
// 		language := r.Header.Get("Accept-Language")
// 		if language == "" {
// 			language = "zh"
// 		}
//
// 		query := dal.NewSignalsQuery()
// 		selections, err := param.QueryStringArray(r, "selection")
// 		if err == nil {
// 			query = query.WithAggrKeys(selections)
// 		}
//
// 		signals, totalCnt, err := palaceSvc.GetSignalsOfEvent(ctx, evtID, query, offsetTime, limit, language)
// 		if err != nil {
// 			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
// 			return
// 		}
// 		response.Ok(w, response.WithItems(signals), response.WithTotalItems(totalCnt))
// 	}
// }
