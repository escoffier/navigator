package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	// TODO: Potentially move this to config file or command line param
	lastChanceTimeout = time.Minute * 10
)

func (api *api) harbor() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/metadata", api.getHarborPluginManifest())
		r.Post("/scan", api.postHarborPluginScan())
		r.Get("/scan/{scan_request_id}/report", api.getHarborPluginReport())
	}
}

func (api *api) getHarborPluginManifest() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		newCtx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		manifest := harbor.Manifest{
			Scanner: harbor.Scanner{
				Name:    "TensorSecurity scanner",
				Vendor:  "TensorSecurity",
				Version: "0.0.1",
			},
			Capabilities: []harbor.Capability{
				{
					ConsumesMIMETypes: []string{
						// Let's only support v2 for now.
						// "application/vnd.oci.image.manifest.v1+json",
						"application/vnd.docker.distribution.manifest.v2+json",
					},
					ProducesMIMETypes: []string{
						// NOTE: if we don't specify capability to return harbor report, the scanner will fail to register with Harbor
						// (but it will report it as "unreachable" error for some reason)
						"application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
						// Harbor report format is required, so we probably don't care about raw (vendor specific) format
						// "application/vnd.scanner.adapter.vuln.report.raw",
					},
				},
			},
			Properties: map[string]string{
				"harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
			},
		}

		updatedAtInt, err := api.getUpdatedAt(newCtx)
		if err == nil {
			updatedAt := time.Unix(updatedAtInt, 0).Format(time.RFC3339)
			manifest.Properties["harbor.scanner-adapter/vulnerability-database-updated-at"] = string(updatedAt)
		} else {
			logging.GetLogger().Warn().Err(err).Msg("Failed to obtain vulnerability DB update time")
		}

		response.Respond(w, http.StatusOK, "application/vnd.scanner.adapter.metadata+json; version=1.0", manifest)

		// TODO Harbor polls this endpoint very often to determine health of the scanner. Therefore
		// we should check for backend scanner health and return 500 if unhealthy
	}
}

func (api *api) postHarborPluginScan() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		if atomic.LoadInt32(&api.abortAnyNewScansBool) != 0 {
			e := harbor.NewHarborErrorAndLog(fmt.Errorf(""), "Not currently accepting any new scan tasks, aborted by an operator")
			response.Respond(w, http.StatusInternalServerError, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		var harborScanReq harbor.ScanRequest
		err := json.NewDecoder(r.Body).Decode(&harborScanReq)
		if err != nil {
			e := harbor.NewHarborErrorAndLog(err, "Failed to decode json received from harbor")
			response.Respond(w, http.StatusBadRequest, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		harborScanReqRedacted := harborScanReq
		harborScanReqRedacted.Registry.Authorization = "<redacted>"
		logging.GetLogger().Info().Str("scanrequest", fmt.Sprintf("%+v", harborScanReqRedacted)).Msg("Received scan request from Harbor")

		_, ok := api.unprocessableEntityCache.Get(harborScanReq.Artifact.Digest)
		if ok {
			e := harbor.NewHarborErrorAndLog(err, "Unprocessable entity, don't retry please")
			response.Respond(w, http.StatusUnprocessableEntity, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		harborResultsLink, err := api.harborClient.GetHarborScanResultsLink(ctx, harborScanReq.Artifact.Repository, harborScanReq.Artifact.Digest, harborScanReq.Artifact.Tag)
		if err != nil {
			e := harbor.NewHarborErrorAndLog(err, "Failed to obtain harbor results link")
			response.Respond(w, http.StatusInternalServerError, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		tensorsecScannerReqPayload := model.ScannerReq{
			URL:           harborScanReq.Registry.URL,
			Authorization: harborScanReq.Registry.Authorization,
			Repository:    harborScanReq.Artifact.Repository,
			Digest:        harborScanReq.Artifact.Digest,
			Tag:           harborScanReq.Artifact.Tag,
			ResultsURL:    harborResultsLink,
		}

		err, scanTask := api.ScannerOne(tensorsecScannerReqPayload)
		if err != nil {
			e := harbor.NewHarborErrorAndLog(err, "Failed to decode response from tensorsec scanner")
			response.Respond(w, http.StatusInternalServerError, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		harborScanResp := harbor.ScanResponse{
			ID: scanTask.ID.Hex(),
		}
		response.Respond(w, http.StatusAccepted, "application/vnd.scanner.adapter.scan.response+json; version=1.0", harborScanResp)
	}
}

func (api *api) getHarborPluginReport() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		if atomic.LoadInt32(&api.abortAnyNewScansBool) != 0 {
			e := harbor.NewHarborErrorAndLog(fmt.Errorf(""), "Scans aborted by an operator")
			response.Respond(w, http.StatusInternalServerError, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		scanRequestID := chi.URLParam(r, "scan_request_id")
		if scanRequestID == "" {
			e := harbor.NewHarborErrorAndLog(nil, "scan_request_id missing in URL")
			response.Respond(w, http.StatusNotFound, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		objectID, err := primitive.ObjectIDFromHex(scanRequestID)
		if err != nil {
			e := harbor.NewHarborErrorAndLog(err, "scan_request_id is in invalid format")
			response.Respond(w, http.StatusNotFound, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		var result model.ScanTask
		err = api.mongodb.Collection(model.ScanTasksCollection.String()).FindOne(ctx, bson.M{"_id": objectID}).Decode(&result)
		if err != nil {
			e := harbor.NewHarborErrorAndLog(err, "Couldn't find task with this identifier")
			response.Respond(w, http.StatusNotFound, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		if result.Status == model.ScanStatusSucceeded {
			api.removeFromScanResultExponentialBackoffCache(result.ID.Hex())
			harborVulnReport := harbor.RedclairReportToHarborReport(result.ScanReport.Vulns)
			response.Respond(w, http.StatusOK, "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0", harborVulnReport)
			return
		} else if result.Status == model.ScanStatusFailed {
			api.removeFromScanResultExponentialBackoffCache(result.ID.Hex())
			e := harbor.NewHarborErrorAndLog(nil, fmt.Sprintf("Scan failed in scanner: %s", result.Message))
			response.Respond(w, http.StatusInternalServerError, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		} else if time.Now().Unix()-result.StartedAt > int64(lastChanceTimeout.Seconds()) {
			// Timeout in Console layer. There is also a timeout in Scanner, but if Scanner misbehaves, we want to inform Harbor about it as well.
			// The timeout itself is quite long since its purpose is to catch orphaned jobs.
			api.removeFromScanResultExponentialBackoffCache(result.ID.Hex())
			e := harbor.NewHarborErrorAndLog(nil, "Waited for scanner for too long")
			response.Respond(w, http.StatusInternalServerError, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		} else if result.Status == model.ScanStatusInProgress {
			refreshAfterSec := api.scanResultExponentialBackoffWithJitter(objectID.Hex())

			// harbor expects 302 Found. By http spec, we must supply Location header.
			w.Header().Set("Location", r.URL.Path)
			w.Header().Set("Refresh-After", fmt.Sprint(refreshAfterSec))
			w.WriteHeader(http.StatusFound)
		}
	}
}

func (api *api) scanResultExponentialBackoffWithJitter(id string) int {
	api.scanResultLocalBackoffCacheMux.Lock()
	defer api.scanResultLocalBackoffCacheMux.Unlock()

	nextWaitTimeSec, ok := api.scanResultLocalBackoffCache[id]
	if !ok {
		nextWaitTimeSec = 1
	} else {
		nextWaitTimeSec = 2 * nextWaitTimeSec
		if nextWaitTimeSec > 20 {
			nextWaitTimeSec = 20
		}
	}

	api.scanResultLocalBackoffCache[id] = nextWaitTimeSec

	jitterSec := rand.Intn(nextWaitTimeSec) // jitter shall be smaller than base
	jitterSec = jitterSec - nextWaitTimeSec/2

	return nextWaitTimeSec + jitterSec
}

func (api *api) removeFromScanResultExponentialBackoffCache(id string) {
	delete(api.scanResultLocalBackoffCache, id) // if key doesn't exist, noop
}

func (api *api) getUpdatedAt(ctx context.Context) (int64, error) {
	lastUpdateTime := int64(0)
	lastUpdateTimeStr, err := api.redisClient.Get(ctx, "DBupdate").Result()
	if err == redis.Nil {
		return 0, errors.New("Clair DB update time hasn't been cached yet")
	} else if err != nil {
		return 0, err
	} else {
		lastUpdateTime, err = strconv.ParseInt(lastUpdateTimeStr, 10, 64)
		if err != nil {
			return 0, err
		}
	}
	return lastUpdateTime, nil
}
