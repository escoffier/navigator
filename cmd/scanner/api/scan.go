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
		r.Post("/harbor/scanAll", api.harborScanAll())
		r.Get("/harbor/scanConfigURL", api.harborGetScanConfigURL())
		r.Post("/dev/forceInvalidateCache", api.forceInvalidateCache())
	}
}

// @Summary Force layer cache invalidation.
// @Description Force layer cache invalidation. Then reinitialize it.
// @Produce json
// @Router /api/v1/scan/dev/forceInvalidateCache [post]
func (api *api) forceInvalidateCache() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		log.Warn().Msg("/api/v1/scan/forceInvalidateCache is exposed for development purpose.")

		err := api.redclair.ForceInvalidateCache(ctx)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to force cache invalidation: %w", err))
			return
		}

		log.Info().Msg("Successfully invalidated cache")
		response.Ok(w)
	}
}

// @Summary Trigger scan of all images in Harbor.
// @Description Trigger scan of all images in Harbor. This API is exposed for testing purpose.
// @Router /api/v1/scan/harbor/scanAll [post]
func (api *api) harborScanAll() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		err := api.harbor.ScanAll(ctx)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to trigger full scan in Harbor: %w", err))
			return
		}

		log.Info().Msg("Successfully triggered full scan in Harbor")
		response.Ok(w)
	}
}

// @Summary Get link to scan configuration screen in Harbor.
// @Description Get link to scan configuration screen in Harbor.
// @Router /api/v1/scan/harbor/scanConfigURL [get]
func (api *api) harborGetScanConfigURL() http.HandlerFunc {
	type respT struct {
		Href string `json:"href"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		_, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		scanConfigLink := api.harbor.GetHarborFullScanConfigURL()

		resp := respT{
			Href: scanConfigLink,
		}

		response.Ok(w, response.WithItem(resp))
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
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		scanReqRedacted := scanReq
		scanReqRedacted.Authorization = "<redacted>"
		log.Info().Str("request", fmt.Sprintf("%+v", scanReqRedacted)).Msgf("Received scan request")

		harborResultsLink, err := api.harbor.GetHarborScanResultsLink(ctx, scanReq.Repository, scanReq.Digest)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to obtain harbor results link: %w", err))
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
		task.AuditTimestamp = time.Now()
		_, err = api.mongodb.Collection(model.ScanTasksCollection).InsertOne(mongoCtx, task)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't insert document")
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't update cluster: %w", err)))
			return
		}

		// add the task to redclair
		api.redclair.AddScanTask(task)

		response.Ok(w, response.WithItem(task))
	}
}
