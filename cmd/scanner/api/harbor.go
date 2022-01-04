package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type harborApi struct {
	Srv         component.HarborSvc
	redisClient *redis.Client
}

func (harborApi *harborApi) getHarborPluginManifest(ctx *gin.Context) {
	newCtx, cancel := context.WithTimeout(ctx, time.Second*10)
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

	updatedAtInt, err := harborApi.getUpdatedAt(newCtx)
	if err == nil {
		updatedAt := time.Unix(updatedAtInt, 0).Format(time.RFC3339)
		manifest.Properties["harbor.scanner-adapter/vulnerability-database-updated-at"] = string(updatedAt)
	} else {
		logging.GetLogger().Warn().Err(err).Msg("Failed to obtain vulnerability DB update time")
	}

	response.Respond(ctx.Writer, http.StatusOK, "application/vnd.scanner.adapter.metadata+json; version=1.0", manifest)

	// TODO Harbor polls this endpoint very often to determine health of the scanner. Therefore
	// we should check for backend scanner health and return 500 if unhealthy
}

func (harborApi *harborApi) postHarborPluginScan(ctx *gin.Context) {
	//newctx, cancel := context.WithTimeout(ctx, time.Second*10)
	//defer cancel()

	/*if atomic.LoadInt32(&api.abortAnyNewScansBool) != 0 {
		e := harbor.NewHarborErrorAndLog(fmt.Errorf(""), "Not currently accepting any new scan tasks, aborted by an operator")
		response.Respond(ctx.Writer, http.StatusInternalServerError, "application/vnd.scanner.adapter.error+json; version=1.0", e)
		return
	}*/

	var harborScanReq harbor.ScanRequest
	err := ctx.BindJSON(&harborScanReq)
	//err := json.NewDecoder(r.Body).Decode(&harborScanReq)
	if err != nil {
		e := harbor.NewHarborErrorAndLog(err, "Failed to decode json received from harbor")
		response.Respond(ctx.Writer, http.StatusBadRequest, "application/vnd.scanner.adapter.error+json; version=1.0", e)
		return
	}

	harborScanReqRedacted := harborScanReq
	harborScanReqRedacted.Registry.Authorization = "<redacted>"

	/*_, ok := api.unprocessableEntityCache.Get(harborScanReq.Artifact.Digest)
	if ok {
		e := harbor.NewHarborErrorAndLog(err, "Unprocessable entity, don't retry please")
		response.Respond(w, http.StatusUnprocessableEntity, "application/vnd.scanner.adapter.error+json; version=1.0", e)
		return
	}*/

	/*harborResultsLink, err := api.harborClient.GetHarborScanResultsLink(newctx, harborScanReq.Artifact.Repository, harborScanReq.Artifact.Digest, harborScanReq.Artifact.Tag)
	if err != nil {
		e := harbor.NewHarborErrorAndLog(err, "Failed to obtain harbor results link")
		response.Respond(ctx.Writer, http.StatusInternalServerError, "application/vnd.scanner.adapter.error+json; version=1.0", e)
		return
	}*/
	tensorsecScannerReqPayload := model.ScannerReq{
		URL:           harborScanReq.Registry.URL,
		Authorization: harborScanReq.Registry.Authorization,
		Repository:    harborScanReq.Artifact.Repository,
		Digest:        harborScanReq.Artifact.Digest,
		Tag:           harborScanReq.Artifact.Tag,
		//ResultsURL:    harborResultsLink,
	}
	logging.GetLogger().Info().Str("scanrequest", fmt.Sprintf("%+v", tensorsecScannerReqPayload)).Msg("Received scan request from Harbor")
	//	tags, err := harborApi.Srv.GetTags(ctx, tensorsecScannerReqPayload.URL, tensorsecScannerReqPayload.Authorization,
	//		tensorsecScannerReqPayload.Repository, tensorsecScannerReqPayload.Digest)
	ids := harborApi.Srv.AddHarborScanTask(ctx, tensorsecScannerReqPayload, []registry.Tag{})
	if len(ids) == 0 {
		e := harbor.NewHarborErrorAndLog(err, "Failed to decode response from scanner")
		response.Respond(ctx.Writer, http.StatusInternalServerError, "application/vnd.scanner.adapter.error+json; version=1.0", e)
		return
	}

	harborScanResp := harbor.ScanResponse{
		ID: fmt.Sprint(ids[0]),
	}
	response.Respond(ctx.Writer, http.StatusAccepted, "application/vnd.scanner.adapter.scan.response+json; version=1.0", harborScanResp)
}

func (harborApi *harborApi) getHarborPluginReport(ctx *gin.Context) {

	scanRequestID := ctx.Param("id")
	if scanRequestID == "" {
		e := harbor.NewHarborErrorAndLog(nil, "scan_request_id missing in URL")
		response.Respond(ctx.Writer, http.StatusNotFound, "application/vnd.scanner.adapter.error+json; version=1.0", e)
		return
	}
	imgId, _ := strconv.ParseInt(scanRequestID, 10, 64)
	result, image := harborApi.Srv.GetScanResult(ctx, imgId)
	fmt.Println("结果为：", result)
	if result.Status == model.ScanStatusSucceeded {
		//api.removeFromScanResultExponentialBackoffCache(result.ID.Hex())
		//var vulns []model.VulnerabilityInfo

		tmpReport := model.VulnerabilityReport{}
		_ = json.Unmarshal(result.VulnInfoJSON, &tmpReport.Vulnerabilities)
		_ = json.Unmarshal(result.SensitiveFileJSON, &tmpReport.Sensitives)
		tmpReport.Digest = image.Digest
		//tmpReport.Tag = image.Tags
		tmpReport.Repository = image.FullRepoName
		fmt.Println("报告为：", tmpReport)
		harborVulnReport := harbor.RedclairReportToHarborReport(tmpReport)
		response.Respond(ctx.Writer, http.StatusOK, "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0", harborVulnReport)
		return
	} else if result.Status == model.ScanStatusFailed {
		//api.removeFromScanResultExponentialBackoffCache(result.ID.Hex())
		e := harbor.NewHarborErrorAndLog(nil, fmt.Sprintf("Scan failed in scanner: %s", result.Message))
		response.Respond(ctx.Writer, http.StatusInternalServerError, "application/vnd.scanner.adapter.error+json; version=1.0", e)
		return
	} else if time.Now().Unix()-result.StartedAt > int64((time.Minute * 10).Seconds()) {
		// Timeout in Console layer. There is also a timeout in Scanner, but if Scanner misbehaves, we want to inform Harbor about it as well.
		// The timeout itself is quite long since its purpose is to catch orphaned jobs.
		//api.removeFromScanResultExponentialBackoffCache(result.ID.Hex())
		e := harbor.NewHarborErrorAndLog(nil, "Waited for scanner for too long")
		response.Respond(ctx.Writer, http.StatusInternalServerError, "application/vnd.scanner.adapter.error+json; version=1.0", e)
		return
	} else if result.Status == model.ScanStatusInProgress {
		//refreshAfterSec := api.scanResultExponentialBackoffWithJitter(objectID.Hex())

		// harbor expects 302 Found. By http spec, we must supply Location header.
		ctx.Writer.Header().Set("Location", ctx.Request.URL.Path)
		ctx.Writer.Header().Set("Refresh-After", fmt.Sprint(5))
		ctx.Writer.WriteHeader(http.StatusFound)
	}
}

func (harborApi *harborApi) getUpdatedAt(ctx context.Context) (int64, error) {
	lastUpdateTime := int64(0)
	lastUpdateTimeStr, err := harborApi.redisClient.Get(ctx, "DBupdate").Result()
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

func NewHaborApiSrv(srv component.HarborSvc, redisClient *redis.Client) *harborApi {
	return &harborApi{
		Srv:         srv,
		redisClient: redisClient,
	}
}
