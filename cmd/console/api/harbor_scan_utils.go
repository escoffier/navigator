package api

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
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

		// TODO we need a cache here or we need to refactor to manage scan tasks by ourselves.
		status, err := api.harborClient.GetScanAllStatus(ctx)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to get current status of scan all: %w", err))
			return
		}
		Doingnum, Waitnum := dal.GetAllVirusScanStatus(ctx, api.scannerURL)
		status.Total = status.Total + Doingnum + Waitnum
		status.Metrics.Running = status.Metrics.Running + Doingnum
		status.Metrics.Pending = status.Metrics.Pending + Waitnum
		if Doingnum+Waitnum > 0 {
			status.IsOngoing = true
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
					if r := recover(); r != nil {
						logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
					}
					atomic.StoreInt32(&api.abortAnyNewScansBool, 0)
					logging.GetLogger().Info().Msg("No longer aborting in-progress and new scan tasks")
				}()

				for status.IsOngoing {
					time.Sleep(5 * time.Second)
					status, err = api.harborClient.GetScanAllStatus(ctx)
					if err != nil {
						logging.GetLogger().Error().Err(err).Msg("Failed to get current status of scan all job")
						return
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

// @Summary Get scan one status.
// @Description Get scan one status.
// @Router/api/v2/containerSec/scanner/harbor/scanOneStatus [get]
func (api *api) harborScanOneStatus() http.HandlerFunc {
	type respT struct {
		EndTime    time.Time `json:"end_time"`
		ScanStatus string    `json:"scan_status"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		fullRepoName := r.URL.Query().Get("repositoryName")
		tag := r.URL.Query().Get("tag")
		digest := r.URL.Query().Get("digest")
		if digest == "" || fullRepoName == "" || tag == "" || len(fullRepoName) > 64 || len(tag) > 32 {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("digest/repoName/tag len error"),
				Suberror{"digest/repoName/tag", ""}))
			return
		}

		projectNameRepoName := strings.SplitN(fullRepoName, "/", 2)
		projectName := projectNameRepoName[0]
		repoName := projectNameRepoName[1]
		frepoName := strings.Replace(repoName, "/", "%252F", -1)
		tags := strings.SplitN(tag, ";", 2)

		endTime, status, err := api.harborClient.ScanOneStatus(ctx, projectName, frepoName, tags[0], digest)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to get current status of scan one: %w", err))
			return
		}
		virusStatus, err := dal.GetAllVirusScanOneStatus(ctx, api.scannerURL, digest)
		if err != nil {
			logging.GetLogger().Error().Msgf("GetAllVirusScanOneStatus error :%+v ", err)
		}
		if err != nil || virusStatus == "" {
			resp := respT{
				EndTime:    endTime,
				ScanStatus: strings.ToLower(status),
			}
			response.Ok(w, response.WithItem(resp))
			return
		}

		if virusStatus == model.VirusStatusDoing || virusStatus == model.VirusStatusWait {
			resp := respT{
				ScanStatus: strings.ToLower(model.JobRunning),
			}
			response.Ok(w, response.WithItem(resp))
			return
		}
		resp := respT{
			EndTime:    endTime,
			ScanStatus: strings.ToLower(status),
		}
		response.Ok(w, response.WithItem(resp))
	}
}
