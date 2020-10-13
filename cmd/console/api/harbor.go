package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (api *api) harbor() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/metadata", api.getHarborPluginManifest())
		r.Post("/scan", api.postHarborPluginScan())
		r.Get("/scan/{scan_request_id}/report", api.getHarborPluginReport())
	}
}

type harborErrorInner struct {
	Message string `json:"message"`
}

type harborError struct {
	Inner harborErrorInner `json:"error"`
}

func (api *api) getHarborPluginManifest() http.HandlerFunc {
	type Scanner struct {
		Name    string `json:"name"`
		Vendor  string `json:"vendor"`
		Version string `json:"version"`
	}
	type Capability struct {
		ConsumesMIMETypes []string `json:"consumes_mime_types"`
		ProducesMIMETypes []string `json:"produces_mime_types"`
	}
	type Manifest struct {
		Scanner      Scanner           `json:"scanner"`
		Capabilities []Capability      `json:"capabilities"`
		Properties   map[string]string `json:"properties"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		manifest := Manifest{
			Scanner: Scanner{
				Name:    "TensorSecurity scanner",
				Vendor:  "TensorSecurity",
				Version: "0.0.1",
			},
			Capabilities: []Capability{
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
				// "harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
				// "harbor.scanner-adapter/vulnerability-database-updated-at": "2019-08-13T08:16:33.345Z",
				"testproperty": "hello-world",
			},
		}
		response.Respond(w, http.StatusOK, "application/vnd.scanner.adapter.metadata+json; version=1.0", manifest)

		// TODO: should check for backend scanner health and return 500 with error schema if unhealthy
	}
}

func (api *api) postHarborPluginScan() http.HandlerFunc {

	type Registry struct {
		URL           string `json:"url"`
		Authorization string `json:"authorization"`
	}
	type Artifact struct {
		Repository string `json:"repository"`
		Digest     string `json:"digest"`
		Tag        string `json:"tag"`
		MimeType   string `json:"mime_type"`
	}
	type ScanRequest struct {
		Registry Registry `json:"registry"`
		Artifact Artifact `json:"artifact"`
	}

	type ScanResponse struct {
		ID string `json:"id"`
	}

	type TensorsecScannerReq struct {
		ImageName   string `json:"image"`
		ForceRescan bool   `json:"rescan"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		var harborScanReq ScanRequest
		err := json.NewDecoder(r.Body).Decode(&harborScanReq)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to decode json received from harbor")
			e := harborError{harborErrorInner{"Failed to decode json received from harbor"}}
			response.Respond(w, http.StatusBadRequest, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		logging.GetLogger().Info().Str("scanrequest", fmt.Sprintf("%+v", harborScanReq)).Msg("Received scan request from Harbor")

		tensorsecScannerReq := TensorsecScannerReq{
			ImageName: "nginx",
			// TODO how to set tag
			// TODO scanner needs to use auth mechanism passed from harbor
			ForceRescan: false,
		}
		tensorsecScannerReqJSON, err := json.Marshal(tensorsecScannerReq)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to marshall request to tensorsec scanner")
			e := harborError{harborErrorInner{"Failed to marshall request to tensorsec scanner"}}
			response.Respond(w, http.StatusInternalServerError, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		httpClient := http.Client{
			// TODO: needs better timeouts
			Timeout: 10 * time.Second,
		}
		tensorsecScannerResp, err := httpClient.Post(
			fmt.Sprintf("%s/api/v1/scan/one", api.scannerURL),
			"application/json",
			bytes.NewBuffer(tensorsecScannerReqJSON),
		)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to send request to tensorsec scanner")
			e := harborError{harborErrorInner{"Failed to send request to tensorsec scanner"}}
			response.Respond(w, http.StatusInternalServerError, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}
		defer tensorsecScannerResp.Body.Close()

		var tensorsecScannerRespEnvelope response.HTTPEnvelope
		err = json.NewDecoder(tensorsecScannerResp.Body).Decode(&tensorsecScannerRespEnvelope)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to decode response from tensorsec scanner")
			e := harborError{harborErrorInner{"Failed to decode response from tensorsec scanner"}}
			response.Respond(w, http.StatusBadRequest, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		logging.GetLogger().Info().Str("tensorsecscanresponse", fmt.Sprintf("%+v", tensorsecScannerRespEnvelope)).Msg("Received scan response from tensorsec scanner")

		var scanTask model.ScanTask
		json.Unmarshal(tensorsecScannerRespEnvelope.Data.Item, &scanTask)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to unmarshall scanTask in response from tensorsec scanner")
			e := harborError{harborErrorInner{"Failed to unmarshall scanTask in response from tensorsec scanner"}}
			response.Respond(w, http.StatusBadRequest, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		harborScanResp := ScanResponse{
			ID: scanTask.ID.Hex(),
		}
		response.Respond(w, http.StatusAccepted, "application/vnd.scanner.adapter.scan.response+json; version=1.0", harborScanResp)
	}
}

func (api *api) getHarborPluginReport() http.HandlerFunc {

	type EmptyResponse struct {
		// TODO we should have a nicer way of doing this
	}

	type VendorSpecificScanReport struct {
		report model.ScanReport
	}
	type HarborSpecificScanReport struct {
		// TODO transform data for harbor
	}

	return func(w http.ResponseWriter, r *http.Request) {
		scanRequestID := chi.URLParam(r, "scan_request_id")
		if scanRequestID == "" {
			logging.GetLogger().Error().Msg("scan_request_id missing in URL")
			e := harborError{harborErrorInner{"scan_request_id missing in URL"}}
			response.Respond(w, http.StatusNotFound, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		objectID, err := primitive.ObjectIDFromHex(scanRequestID)
		if err != nil {
			logging.GetLogger().Error().Msg("scan_request_id is in invalid format")
			e := harborError{harborErrorInner{"scan_request_id is in invalid format"}}
			response.Respond(w, http.StatusNotFound, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		mongoCtx, mongoCtxCancel := api.getTimeoutCtx()
		defer mongoCtxCancel()

		// from mongo
		var result model.ScanTask
		err = api.mongodb.Collection(model.ScanTasksCollection).FindOne(mongoCtx, bson.M{"_id": objectID}).Decode(&result)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Coudln't find task with this identifier")
			e := harborError{harborErrorInner{"Coudln't find task with this identifier"}}
			response.Respond(w, http.StatusNotFound, "application/vnd.scanner.adapter.error+json; version=1.0", e)
			return
		}

		// TODO: checking if scan report is ready like this seems bad. Better have a status field.
		if len(result.ScanReport.Files) > 0 {
			vendorScanReport := VendorSpecificScanReport{
				report: result.ScanReport,
			}
			response.Respond(w, http.StatusOK, "application/vnd.scanner.adapter.vuln.report.raw; version=1.0", vendorScanReport)
		} else {
			// TODO add some timeout where we just return 500, because maybe there's an error in tensorsec scanner.
			// TODO also, if there is an error in scanner, it should set status in mongo to failed with error message or something, so we don't wait...

			// Tell harbor to retry after 10 seconds
			w.Header().Set("Refresh-After", "10")
			// harbor expects 302 Found. By http spec, we must supply Location header.
			w.Header().Set("Location", r.URL.Path)
			w.WriteHeader(http.StatusFound)
		}
	}
}
