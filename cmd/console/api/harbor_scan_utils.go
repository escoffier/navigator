package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/cache"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// @Summary Trigger scan of all images in Harbor.
// @Description Trigger scan of all images in Harbor.
// @Router /api/v1/scanner/harbor/scanAllNow [post]
func (api *api) harborScanAllNow() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		err := api.harborClient.ScanAll(ctx)
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
// @Router /api/v1/scanner/harbor/scanConfig [get]
func (api *api) harborScanConfig() http.HandlerFunc {
	type respT struct {
		Href string `json:"href"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		_, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		scanConfigLink := api.harborClient.GetHarborFullScanConfigURL()

		resp := respT{
			Href: scanConfigLink,
		}

		response.Ok(w, response.WithItem(resp))
	}
}

// @Summary Get scan all status.
// @Description Get scan all status.
// @Router /api/v1/scanner/harbor/scanStatus [get]
func (api *api) harborScanStatus() http.HandlerFunc {
	type respT struct {
		ScanAllStatus harbor.ScanAllStatus `json:"harborStatus"`
		IsAborted     bool                 `json:"isAborted"` // if true, we are currently in the process of aborting harbor scan all job. Abort button should be disabled.
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		var status harbor.ScanAllStatus

		// We take this value from redis cache, so that cached data is in sync with harbor view
		// on the frontend. If any err, then take the value provided by harbor
		redisCtx, redisCtxCancel := context.WithTimeout(ctx, util.RedisTimeout)
		defer redisCtxCancel()

		cachedStatus, err := api.redisClient.Get(
			redisCtx, cache.ScannedImagesCountCacheKey).Result()
		if err != nil {
			logging.GetLogger().
				Warn().
				Err(err).
				Msg("Failed to get harbor status from cache")
			status, err = api.harborClient.GetScanAllStatus(ctx)
			if err != nil {
				RespAndLog(w, ctx, fmt.Errorf("Failed to get current status of scan all: %w", err))
				return
			}
		} else {
			err = json.Unmarshal([]byte(cachedStatus), status)
			if err != nil {
				logging.GetLogger().
					Warn().
					Err(err).
					Msg("Failed to unmarshal status from cache")
				status, err = api.harborClient.GetScanAllStatus(ctx)
				if err != nil {
					RespAndLog(w, ctx, fmt.Errorf("Failed to get current status of scan all: %w", err))
					return
				}
			}
		}

		resp := respT{
			ScanAllStatus: status,
			IsAborted:     atomic.LoadInt32(&api.abortAnyNewScansBool) != 0,
		}

		response.Ok(w, response.WithItem(resp))
	}
}

// @Summary Abort current and future scan tasks for currently running Harbor scan all job.
// @Description Abort current and future scan tasks for currently running Harbor scan all job.
// @Router /api/v1/scanner/harbor/abortScanAll [post]
func (api *api) harborAbortScanAll() http.HandlerFunc {
	type respT struct {
		ScanAllStatus harbor.ScanAllStatus `json:"harborStatus"`
		IsAborted     bool                 `json:"isAborted"` // if true, we are currently in the process of aborting harbor scan all job. Abort button should be disabled.
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		status, err := api.harborClient.GetScanAllStatus(ctx)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to get current status of scan all job: %w", err))
			return
		}

		if status.IsOngoing {
			atomic.StoreInt32(&api.abortAnyNewScansBool, 1)
			logging.GetLogger().Info().Msg("From now on, aborting in-progress and new scan tasks")

			go func() {
				defer func() {
					atomic.StoreInt32(&api.abortAnyNewScansBool, 0)
					logging.GetLogger().Info().Msg("No longer aborting in-progress and new scan tasks")
				}()

				for status.IsOngoing {
					select {
					case <-time.After(time.Second * 5):
						status, err = api.harborClient.GetScanAllStatus(ctx)
						if err != nil {
							logging.GetLogger().Error().Err(err).Msg("Failed to get current status of scan all job")
							return
						}
					}
				}
			}()
		}

		resp := respT{
			ScanAllStatus: status,
			IsAborted:     atomic.LoadInt32(&api.abortAnyNewScansBool) != 0,
		}

		response.Ok(w, response.WithItem(resp))
	}
}
