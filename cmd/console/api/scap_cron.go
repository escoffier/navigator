package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/locale"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

// @Summary Get cron configured for this checkType and cluster
// @Description Get cron configured for this checkType and cluster
// @ID v1-scap-check
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
			logging.GetLogger().Info().Err(err).Msg("Couldn't read ClusterID")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("clusterID", ""))
			return
		}

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			logging.GetLogger().Info().Msg("checkType param missing")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return
		}

		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			logging.GetLogger().Info().Msg("invalid checkType param value (allowed: kube/docker/host)")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", checkType))
			return
		}

		cronConfig, err := api.cronService.GetCron(ctx, clusterObjectID, checkType)
		if err != nil {
			logging.GetLogger().Info().Msg("failed to get cron")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		resp.CronString = cronConfig

		response.Ok(w, response.WithItem(resp))
	}
}

// @Summary Update cron configured for this checkType and cluster
// @Description Update cron configured for this checkType and cluster. To disable, send empty string.
// @ID v1-scap-check
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
		ctx, cancel := api.getTimeoutCtx(time.Second * 100)
		defer cancel()

		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("Couldn't read ClusterID")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("clusterID", ""))
			return
		}

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			logging.GetLogger().Info().Msg("checkType param missing")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return
		}

		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			logging.GetLogger().Info().Msg("invalid checkType param value (allowed: kube/docker/host)")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return
		}

		var req req
		err = decodeJSONBody(w, r, &req)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("Failed to decode json")
			response.Bad(w, response.WithMessage(locale.Error(locale.MalformedRequestError, r)))
			return
		}

		err = api.cronService.UpdateCron(ctx, clusterObjectID, checkType, req.NewCronString)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("Failed to update cron")
			apperror.RespondWithSuggested(w, r, err)
			return
		}

		response.Ok(w)
	}
}
