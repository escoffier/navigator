package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (api *api) alert() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/", api.listAlerts())
		r.Post("/{alertID}/acknowledge", api.acknowledgeAlert())
	}
}

// @Summary Acknowledge alert
// @Description Acknowledge alert
// @ID v1-alert-acknowledge-post
// @Produce json
// @Param clusterID path string true "alertID"
// @Router /api/v1/alerts/{alertID}/acknowledge [post]
func (api *api) acknowledgeAlert() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		alertObjectID, err := getAlertIDFromURL(r)
		if err != nil {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read alertID: %w", err),
					Suberror{"alertID", ""}))
			return
		}

		queryAlert, err := api.alertService.AcknowledgeAlert(ctx, alertObjectID)
		if err != nil {
			RespAndLog(w, r, fmt.Errorf("Couldn't acknowledge alert: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*queryAlert))
	}
}

// @Summary List  alerts
// @Description List  alerts
// @ID v1-alerts-get
// @Produce json
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param onlyNotAcknowledged query bool false "only not acknowledged alerts"
// @Router /api/v1/alerts/ [get]
func (api *api) listAlerts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		offset, limit := api.getOffsetAndLimit(r)

		onlyNotAcknowledged, err := param.QueryBool(r, "onlyNotAcknowledged")
		if err != nil {
			onlyNotAcknowledged = false
		}

		alerts, docNum, err := api.alertService.ListAlerts(ctx, offset, limit, onlyNotAcknowledged)
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

func getAlertIDFromURL(r *http.Request) (primitive.ObjectID, error) {
	alertID := chi.URLParam(r, "alertID")
	if alertID == "" {
		return primitive.NilObjectID, errors.New("alertID is not provided")
	}
	return primitive.ObjectIDFromHex(alertID)
}
