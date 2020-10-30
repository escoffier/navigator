package api

import (
	"context"
	"fmt"
	"net/http"
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
		r.Post("/harborScanAll", api.harborScanAll())
		r.Post("/forceInvalidateCache", api.forceInvalidateCache())
	}
}

// @Summary Force layer cache invalidation.
// @Description Force layer cache invalidation. Then reinitialize it.
// @Produce json
// @Router /api/v1/scan/forceInvalidateCache [post]
func (api *api) forceInvalidateCache() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		log.Warn().Msg("/api/v1/scan/forceInvalidateCache is exposed for development purpose.")

		err := api.redclair.ForceInvalidateCache(ctx)
		if err != nil {
			RespAndLog(w, r, fmt.Errorf("Failed to force cache invalidation: %w", err))
			return
		}

		log.Info().Msg("Successfully invalidated cache")
		response.Ok(w)
	}
}

// @Summary Trigger scan of all images in Harbor.
// @Description Trigger scan of all images in Harbor. This API is exposed for testing purpose.
// @Produce json
// @Router /api/v1/scan/harborScanAll [post]
func (api *api) harborScanAll() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		log.Warn().Msg("/api/v1/scan/harborScanAll is exposed for testing purpose. " +
			"Consider removing or disabling it, as it uses Harbor admin credentials.")

		err := api.harbor.ScanAll(ctx)
		if err != nil {
			RespAndLog(w, r, fmt.Errorf("Failed to trigger full scan in Harbor: %w", err))
			return
		}

		log.Info().Msg("Successfully triggered full scan in Harbor")
		response.Ok(w)
	}
}

// @Summary Scan one image
// @Description Scan one image
// @ID v1-scan-one-post
// @Produce json
// @Router /api/v1/scan/one [post]
func (api *api) scanOne() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

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

		harborResultsLink, err := api.harbor.GetHarborScanResultsLink(ctx, scanReq.Repository, scanReq.Digest)
		if err != nil {
			RespAndLog(w, r, fmt.Errorf("Failed to obtain harbor results link: %w", err))
			return
		}

		task := model.ScanTask{
			Status:        model.ScanStatusInProgress,
			StartedAt:     time.Now().Unix(),
			Repository:    scanReq.Repository,
			Tag:           scanReq.Tag,
			URL:           scanReq.URL,
			HarborURL:     harborResultsLink,
			Authorization: scanReq.Authorization,
			ImageDigest:   scanReq.Digest,
		}

		// persist the task to Mongo
		mongoCtx, mongoCancel := context.WithTimeout(ctx, 10*time.Second)
		defer mongoCancel()

		task.ID = primitive.NewObjectIDFromTimestamp(time.Now())
		_, err = api.mongodb.Collection(model.ScanTasksCollection).InsertOne(mongoCtx, task)
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
