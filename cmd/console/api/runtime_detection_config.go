package api

import (
	"errors"
	"fmt"
	"net/http"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) runtimeDetectionConfig() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/rules", api.listRules())
		r.Post("/rules/{ruleID}/enable", api.enableRule())
		r.Post("/rules/{ruleID}/disable", api.disableRule())
	}
}

// @Summary List runtime detection rules
// @Description List runtime detection rules
// @ID v1-runtime-detection-rules-get
// @Produce json
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Router /api/v1/runtimeDetectionConfig/rules [get]
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
// @Router /api/v1/runtimeDetectionConfig/rule/{ruleID}/enable [post]
func (api *api) enableRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		ruleID, err := getRuleIDFromURL(r)
		if err != nil {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("ruleID param missing"),
					Suberror{"ruleID", ""}))
			return
		}

		queryRule, err := api.ruleService.EnableRule(ctx, ruleID)
		if err != nil {
			RespAndLog(w, r,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to enable rule %s: %w", ruleID, err)))
			return
		}

		response.Ok(w, response.WithItem(*queryRule))
	}
}

// @Summary Disable single rule
// @Description Disable single rule
// @ID v1-runtime-detection-rule-disable
// @Produce json
// @Param ruleID path string true "ruleID"
// @Router /api/v1/runtimeDetectionConfig/rule/{ruleID}/disable [post]
func (api *api) disableRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		ruleID, err := getRuleIDFromURL(r)
		if err != nil {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("ruleID param missing"),
					Suberror{"ruleID", ""}))
			return
		}

		queryRule, err := api.ruleService.DisableRule(ctx, ruleID)
		if err != nil {
			RespAndLog(w, r,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("Failed to disable rule %s: %w", ruleID, err)))
			return
		}

		response.Ok(w, response.WithItem(*queryRule))
	}
}

func getRuleIDFromURL(r *http.Request) (primitive.ObjectID, error) {
	ruleID := chi.URLParam(r, "ruleID")
	if ruleID == "" {
		return primitive.NilObjectID, errors.New("ruleID is not provided")
	}
	return primitive.ObjectIDFromHex(ruleID)
}
