package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) audit() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/config", api.getAuditConfig())
		r.Put("/config", api.updateAuditConfig())
	}
}

// @Summary Get audit config
// @Description Get audit config
// @ID v1-audit-config-get
// @Produce json
// @Router /api/v1/audit/config [get]
func (api *api) getAuditConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		auditConfig, err := api.auditService.GetAuditConfig(ctx)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't get audit config: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*auditConfig))
	}
}

// @Summary Update audit config
// @Description Update audit config
// @ID v1-audit-config-put
// @Produce json
// @Param hotStorageDays body int true "hotStorageDays"
// @Param coldStorageDays body int true "coldStorageDays"
// @Router /api/v1/audit/config [put]
func (api *api) updateAuditConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		var upAuditConfig model.AuditConfig

		err := util.DecodeJSONBody(w, r, &upAuditConfig)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		updatedAuditConfig, err := api.auditService.UpdateAuditConfig(ctx, &upAuditConfig)

		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't update audit config: %w", err)))
			return
		}
		response.Ok(w, response.WithItem(*updatedAuditConfig))
	}
}
