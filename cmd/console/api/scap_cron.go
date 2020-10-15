package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
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
	}
	return func(w http.ResponseWriter, r *http.Request) {
		resp := respStruct{}

		ctx, cancel := api.getTimeoutCtx(time.Second * 60)
		defer cancel()

		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read ClusterID: %w", err),
					Suberror{"clusterID", ""}))
			return
		}

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkType param missing"),
					Suberror{"checkType", ""}))
			return
		}

		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
					Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		cronConfig, err := api.cronService.GetCron(ctx, clusterObjectID, checkType)
		if err != nil {
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get cron: %w", err)))
			return
		}
		resp.CronString = cronConfig

		response.Ok(w, response.WithItem(resp))
	}
}

// @Summary Update cron configured for this checkType and cluster
// @Description Update cron configured for this checkType and cluster. To disable, send empty string.
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterID path string true "cluster ID"
// @Param newCronString body string true "new crontab string to assign; empty string to disable"
// @Router /api/v1/scap/{checkType}/{clusterID}/cron [put]
func (api *api) putCron() http.HandlerFunc {
	type req struct {
		NewCronString string `json:"newCronString"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read ClusterID: %w", err),
					Suberror{"clusterID", ""}))
			return
		}

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkType param missing"),
					Suberror{"checkType", ""}))
			return
		}

		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
					Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		var req req
		err = util.DecodeJSONBody(w, r, &req)
		if err != nil {
			RespAndLog(w, r,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		err = api.cronService.UpdateCron(api.ctx, clusterObjectID, checkType, req.NewCronString)
		if err != nil {
			RespAndLog(w, r, fmt.Errorf("Failed to update cron: %w", err))
			return
		}

		response.Ok(w)
	}
}
