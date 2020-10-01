package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/locale"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"go.mongodb.org/mongo-driver/bson"
)

// @Summary Get cron configured for this checkType and cluster
// @Description Get cron configured for this checkType and cluster
// @ID v1-scap-check
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterID path string true "cluster ID"
// @Router /api/v1/scap/{checkType}/{clusterID}/cron
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
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return
		}

		// get kube client for this cluster
		cluster, err := api.getClusterFromMongo(ctx, clusterObjectID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to get cluster from Mongo")
			apperror.RespondWithSuggested(w, r, err)
			return
		}

		if checkType == "kube" {
			resp.CronString = cluster.CronConfig.KubeBenchCronString
		} else if checkType == "docker" {
			resp.CronString = cluster.CronConfig.DockerBenchCronString
		} else if checkType == "host" {
			resp.CronString = cluster.CronConfig.HostBenchCronString
		}

		response.Ok(w, response.WithItem(resp))
	}
}

// @Summary Get cron configured for this checkType and cluster
// @Description Get cron configured for this checkType and cluster. To disable, send empty string.
// @ID v1-scap-check
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterID path string true "cluster ID"
// @Param newCronString body string true "new crontab string to assign; empty string to disable"
// @Router /api/v1/scap/{checkType}/{clusterID}/cron
func (api *api) postCron() http.HandlerFunc {
	type req struct {
		NewCronString string `json:"newCronString"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
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

		// get kube client for this cluster
		cluster, err := api.getClusterFromMongo(ctx, clusterObjectID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to get cluster from Mongo")
			apperror.RespondWithSuggested(w, r, err)
			return
		}

		if checkType == "kube" {
			cluster.CronConfig.KubeBenchCronString = req.NewCronString
		} else if checkType == "docker" {
			cluster.CronConfig.DockerBenchCronString = req.NewCronString
		} else if checkType == "host" {
			cluster.CronConfig.HostBenchCronString = req.NewCronString
		}

		filter := bson.M{"_id": clusterObjectID}
		cluster.ID = clusterObjectID
		update := bson.M{"$set": cluster}

		mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
		defer mongoCtxCancel()
		_, err = api.scapper.MongoDB.Collection(clusterCol).UpdateOne(mongoCtx, filter, update)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't update document")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}

		response.Ok(w)
	}
}
