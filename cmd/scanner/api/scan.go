package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"go.mongodb.org/mongo-driver/bson/primitive"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// ScanResultResponse is the response for scan result
type ScanResultResponse struct {
	ImageName string `json:"imageName"`
	DBId      string `json:"dbId"`
}

func (api *api) scan() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/one", api.scanOne())
	}
}

// @Summary Scan one image
// @Description Scan one image
// @ID v1-scan-one-post
// @Produce json
// @Router /api/v1/scan/one [post]
func (api *api) scanOne() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var scanReq model.ScannerReq
		err := util.DecodeJSONBody(w, r, &scanReq)
		if err != nil {
			RespAndLog(w, r,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		scanReqRedacted := scanReq
		scanReqRedacted.Authorization = "<redacted>"
		log.Info().Str("request", fmt.Sprintf("%+v", scanReqRedacted)).Msgf("Received scan request")

		repoimage := strings.Split(scanReq.Repository, "/") // e.g. library/mongo
		repository := ""
		image := repoimage[len(repoimage)-1]
		if len(repoimage) > 1 {
			repository = repoimage[0]
		}

		task := model.ScanTask{
			Status:     model.ScanStatusInProgress,
			StartedAt:  time.Now().Unix(),
			Image:      image,
			Tag:        scanReq.Tag,
			Repository: repository,
			URL:        scanReq.URL,
			// ImageDigest: digestImage, // TODO not sure about handling this
			ForceRescan: false, // TODO not sure if ForceRescan needed
			// TODO potentially adjust fields of this struct
		}

		// persist the task to Mongo
		ctx, cancel := context.WithTimeout(api.ctx, 10*time.Second)
		defer cancel()

		task.ID = primitive.NewObjectIDFromTimestamp(time.Now())
		_, err = api.mongodb.Collection(model.ScanTasksCollection).InsertOne(ctx, task)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't insert document")
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't update cluster: %w", err)))
			return
		}

		// add the task to redclair
		api.redclair.AddScanTask(task)

		response.Ok(w, response.WithItem(task))
	}
}
