package api

import (
	"fmt"
	"net/http"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) runtimeDetection() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/rules", api.listRules())
		r.Post("/rules/{ruleID}/on", api.enableRule())
		r.Post("/rules/{ruleID}/off", api.disableRule())
		r.Get("/alerts", api.listAlerts())
	}
}

// @Summary List runtime detection alerts
// @Description List runtime detection alerts
// @ID v1-runtime-detection-alerts-get
// @Produce json
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Router /api/v1/runtime/detection/alerts [get]
func (api *api) listAlerts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		offset, limit := api.getOffsetAndLimit(r)

		alerts, docNum, err := api.alertService.ListAlerts(ctx, offset, limit)
		if err != nil {
			RespAndLog(w, r,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to list alerts: %w", err)))
			return
		}

		response.Ok(w,
			response.WithItems(alerts),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

// @Summary List runtime detection rules
// @Description List runtime detection rules
// @ID v1-runtime-detection-rules-get
// @Produce json
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Router /api/v1/runtime/detection/rules [get]
func (api *api) listRules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		offset, limit := api.getOffsetAndLimit(r)

		rules, docNum, err := api.ruleService.ListRules(ctx, offset, limit)
		if err != nil {
			RespAndLog(w, r,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to list rules: %w", err)))
			return
		}

		response.Ok(w,
			response.WithItems(rules),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

// @Summary Enable single rule
// @Description Enable single rule
// @ID v1-runtime-detection-rule-enable
// @Produce json
// @Param ruleID path string true "ruleID"
// @Router /api/v1/runtime/detection/rule/{ruleID}/on [post]
func (api *api) enableRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		ruleID := chi.URLParam(r, "ruleID")
		if ruleID == "" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("ruleID param missing"),
					Suberror{"ruleID", ""}))
			return
		}

		err := api.ruleService.EnableRule(ctx, ruleID)
		if err != nil {
			RespAndLog(w, r,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to enable rule %s: %w", ruleID, err)))
			return
		}

		response.Ok(w)
	}
}

// @Summary Disable single rule
// @Description Disable single rule
// @ID v1-runtime-detection-rule-disable
// @Produce json
// @Param ruleID path string true "ruleID"
// @Router /api/v1/runtime/detection/rule/{ruleID}/off [post]
func (api *api) disableRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		ruleID := chi.URLParam(r, "ruleID")
		if ruleID == "" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("ruleID param missing"),
					Suberror{"ruleID", ""}))
			return
		}

		err := api.ruleService.DisableRule(ctx, ruleID)
		if err != nil {
			RespAndLog(w, r,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to disable rule %s: %w", ruleID, err)))
			return
		}

		response.Ok(w)
	}
}
