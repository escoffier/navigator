package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cron"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// @Summary Get cron configured for this checkType and cluster
// @Description Get cron configured for this checkType and cluster
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterID path string true "cluster ID"
// @Router /api/v1/scap/{checkType}/{clusterID}/cron [get]
func (api *api) getCron() http.HandlerFunc {
	type respStruct struct {
		CronString string `json:"cronString,omitempty"`
		LastRun    int    `json:"lastRun,omitempty"`
		CreateTime int64  `json:"createAt,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		resp := respStruct{}

		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		clusterID := chi.URLParam(r, "clusterKey")
		if clusterID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("Couldn't read ClusterID")))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value")))
			return
		}

		cronService, _ := cron.Get(ctx)
		cronTask, err := cronService.GetCron(ctx, clusterID, checkType)
		if err == nil {
			resp.CronString = cronTask.CronTime
			resp.CreateTime = cronTask.CreatedAt
		}

		response.Ok(w, response.WithItem(resp))
	}
}

// @Summary Update cron configured for this checkType and cluster
// @Description Update cron configured for this checkType and cluster. To disable, send empty string.
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterID path string true "cluster ID"
// @Param cronString body string true "new crontab string to assign; empty string to disable"
// @Router /api/v1/scap/{checkType}/{clusterID}/cron [put]
func (api *api) putCron() http.HandlerFunc {
	type req struct {
		NewCronString string `json:"cronString"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		clusterID := chi.URLParam(r, "clusterKey")
		if clusterID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("Couldn't read ClusterID")))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
				Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		var req req
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		cronService, _ := cron.Get(ctx)
		err = cronService.UpdateCron(api.ctx, clusterID, checkType, req.NewCronString)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to update cron: %w", err))
			return
		}

		response.Ok(w)
	}
}
