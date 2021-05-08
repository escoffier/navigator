package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"time"

	"github.com/go-chi/chi"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (api *api) scanner() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/task/{taskID}", api.getScannerTask())
		r.Get("/reportsBySeverity", api.listScanReportsBySeverity())
		r.Get("/reportsByImage", api.listScannedImages())
		r.Get("/reportsByImageList", api.listScannedByImageList())
		r.Get("/reportsByImageOverview", api.listScannedByImageOverview())
		r.Get("/reportsByImageDetails", api.ScannedByImageDetails())
		r.Get("/report/{taskID}", api.getScannerImageVulnerabilities())
		r.Post("/scan", api.scan())
		r.Post("/scanone", api.scanOne())

		r.Post("/harbor/scanAllNow", api.harborScanAllNow())
		r.Post("/harbor/scanOnline", api.harborScanOnline())
		r.Get("/harbor/scanConfig", api.harborScanConfig())
		r.Get("/harbor/scanStatus", api.harborScanStatus())
		r.Get("/harbor/scanOneStatus", api.harborScanOneStatus())
		r.Post("/harbor/abortScanAll", api.harborAbortScanAll())
	}
}

func getTaskObjectIDFromURL(r *http.Request) (primitive.ObjectID, error) {
	taskID := chi.URLParam(r, "taskID")
	if taskID == "" {
		return primitive.NilObjectID, errors.New("taskID is not provided")
	}
	return primitive.ObjectIDFromHex(taskID)
}

// @Summary Get image and its vulnerabilities
// @Description Get image and its vulnerabilities
// @Produce json
// @Param taskID path string true "scan task ID"
// @Router /api/v1/scanner/report/{taskID} [get]
func (api *api) getScannerImageVulnerabilities() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get ObjectID
		taskObjectID, err := getTaskObjectIDFromURL(r)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read taskID: %w", err),
					Suberror{"taskID", ""}))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		findOneOptions := options.FindOne().SetMaxTime(time.Second * 10)

		// from mongo
		var scanTask model.ScanTask
		err = api.mongodb.Get().Collection(model.ScanTasksCollection.String()).FindOne(
			ctx, bson.M{"_id": taskObjectID}, findOneOptions).Decode(&scanTask)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))
			return
		}

		result := &model.ImageScanDetailedResult{}
		report := scanTask.ScanReport.Vulns
		result.HarborURL = scanTask.HarborURL

		topVulnsNum := len(report.Vulnerabilities)
		if len(report.Vulnerabilities) >= 5 {
			topVulnsNum = 5
		}
		result.TopVulns = report.Vulnerabilities[:topVulnsNum]

		if len(result.TopVulns) >= 1 {
			result.OverallSeverity = report.Vulnerabilities[0].Severity
		} else {
			result.OverallSeverity = redclair.SeverityUnknown
		}

		result.Repository = report.Repository
		result.Tag = report.Tag
		result.Digest = report.Digest
		for i := range report.PerLayerReport {
			for j := range report.PerLayerReport[i].Sensitives {
				if lang.Language(ctx) == lang.LanguageZH {
					description := report.PerLayerReport[i].Sensitives[j].DescriptionZh
					report.PerLayerReport[i].Sensitives[j].Description = description
				} else {
					description := report.PerLayerReport[i].Sensitives[j].DescriptionEn
					report.PerLayerReport[i].Sensitives[j].Description = description
				}
			}
		}
		result.PerLayerReport = report.PerLayerReport
		result.TaskID = scanTask.ID
		result.SeverityHistogram = scanTask.ScanReport.Vulns.SeverityHistogram

		response.Ok(w, response.WithItem(*result))
	}
}

// @Summary List images and their vulnerabilities
// @Description List images and their vulnerabilities
// @Produce json
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param sortOrder query string false "asc/desc"
// @Param maxImageAgeInHours query int false "return only images that have only scans younger than this number; 0 or empty disables"
// @Param sortBy query string false "finishedAt/overallSeverity/repository/tag/imageDigest"
// @Router /api/v1/scanner/reportsByImage [get]
func (api *api) listScannedImages() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		var maxImageAgeInHours int
		maxImageAgeInHoursRaw := r.URL.Query().Get("maxImageAgeInHours")
		if maxImageAgeInHoursRaw != "" {
			m, err := strconv.Atoi(maxImageAgeInHoursRaw)
			if err != nil {
				RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
					fmt.Errorf("failed to convert to int: %w", err),
					Suberror{"maxImageAgeInHours", "uint"}))
				return
			}
			if maxImageAgeInHours < 0 {
				RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
					fmt.Errorf("must be positive"),
					Suberror{"maxImageAgeInHours", "uint"}))
				return
			}
			if maxImageAgeInHours != 1 && maxImageAgeInHours != 24 && maxImageAgeInHours != 0 {
				RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
					fmt.Errorf("must be equal to 0, 1 or 24"),
					Suberror{"maxImageAgeInHours", "uint"}))
				return
			}
			maxImageAgeInHours = m
		} else {
			maxImageAgeInHours = 0
		}

		sortBy, err := api.sortByFromQuery(r, model.GetDefaultScannedImagesSortableName(), model.GetScannedImagesSortableNames()...)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		sortOrder, err := api.sortOrderFromQuery(r, "desc")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		offset, limit := api.getOffsetAndLimit(r)

		items, docNum, err := api.scannerService.GetScannedImages(ctx, maxImageAgeInHours, offset, limit, model.ScannedImagesSortableFields[sortBy], sortOrder)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		response.Ok(w,
			response.WithItems(items),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

//
// @Router  /api/v2/containerSec/scanner/reportsByRepo [get]
func (api *api) listScannedByImageList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		search := r.URL.Query().Get("search")
		if len(search) > 64 {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("the maximum value is exceeded"),
				Suberror{"search", ""}))
			return
		}
		offset, limit := api.getOffsetAndLimit(r)

		online := r.URL.Query().Get("online")
		if online == "" {
			online = "false"
		}
		if online != "false" && online != "true" {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("online error"),
				Suberror{"online", "true/false"}))
			return
		}

		kind := r.URL.Query().Get("kind")

		items, docNum, err := api.scannerService.GetImageList(ctx, offset, limit, search, online, kind)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		response.Ok(w,
			response.WithItems(items),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

// @Router  /api/v2/containerSec/scanner/reportsByRepo [get]
func (api *api) listScannedByImageOverview() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		item, err := api.scannerService.GetImageOverView(ctx)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}
		response.Ok(w, response.WithItem(item))

	}
}

//@Summary Get a scan task by scantask on image
// @Description Get a scan task by scantask on image
// @Router /api/v2/containerSec/scanner/reportsByImageDetails [get]
func (api *api) ScannedByImageDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		digest := r.URL.Query().Get("digest")
		fullRepoName := r.URL.Query().Get("repositoryName")
		if len(digest) != 71 || len(fullRepoName) > 64 {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("digest or repo name len error"),
				Suberror{"digest/repo", ""}))
			return
		}

		items, err := api.scannerService.GetImageDetail(ctx, digest, fullRepoName)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		response.Ok(w, response.WithItem(items))
	}
}

// @Summary Get a scan task by scantask ID
// @Description Get a scan task
// @ID v1-scanner-task-get
// @Produce json
// @Param taskID path string true "scan task ID"
// @Router /api/v1/scanner/task/{taskID} [get]
func (api *api) getScannerTask() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get ObjectID
		taskObjectID, err := getTaskObjectIDFromURL(r)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read taskID: %w", err),
					Suberror{"taskID", ""}))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		oneOptions := options.FindOne().SetMaxTime(time.Second * 10)
		// from mongo
		var result model.ScanTask
		err = api.mongodb.Get().Collection(model.ScanTasksCollection.String()).FindOne(
			ctx, bson.M{"_id": taskObjectID}, oneOptions).Decode(&result)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))
			return
		}
		response.Ok(w, response.WithItem(result))
	}
}

// @Summary List reports by severity
// @Description List reports by severity
// @Produce json
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param riskFilter query string false "risk explorarion filter (none(default)/medToCrit/networkBased)"
// @Param sortOrder query string false "asc/desc"
// @Router /api/v1/scanner/reportsBySeverity [get]
func (api *api) listScanReportsBySeverity() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*30)
		defer cancel()

		riskFilter := r.URL.Query().Get("riskFilter")
		if riskFilter == "" {
			riskFilter = model.GetDefaultVulnerabilityInImagesRiskFilterName()
		}

		if _, ok := model.VulnerabilityInImagesRiskFilters[riskFilter]; !ok {
			RespAndLog(w, r.Context(),
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid riskFilter param value (allowed: default/medToCrit/networkBased)"),
					Suberror{"riskFilter", "allowed: default/medToCrit/networkBased"}))
			return
		}
		sortOrder := r.URL.Query().Get("sortOrder")
		if sortOrder == "" {
			sortOrder = "desc"
		}
		if sortOrder != "asc" && sortOrder != "desc" {
			RespAndLog(w, r.Context(),
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid sortOrder param value (allowed: asc/desc)"),
					Suberror{"sortOrder", "allowed: asc/desc"}))
			return
		}
		offset, limit := api.getOffsetAndLimit(r)
		resultItems, size, err := api.scannerService.GetImageVulnerabilities(
			ctx, riskFilter, offset, limit, sortOrder)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w,
			response.WithItems(resultItems),
			response.WithTotalItems(size),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

// @Summary Tell scanner to scan an image
// @Description Tell scanner to scan an image
// @ID v1-scanner-scan
// @Produce json
// @Param image body string true "image name"
// @Param rescan body bool true "force rescan the image"
// @Router /api/v1/scanner/scan [post]
func (api *api) scan() http.HandlerFunc {
	type param struct {
		ImageName   string `json:"image"`
		ForceRescan bool   `json:"rescan"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var param param
		err := util.DecodeJSONBody(w, r, &param)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		jsonValue, err := json.Marshal(param)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to marshall json: %w", err)))
			return
		}

		client := http.Client{
			Timeout: 10 * time.Second,
		}
		resp, err := client.Post(
			fmt.Sprintf("%s/api/v1/scan/one", api.scannerURL),
			"application/json",
			bytes.NewBuffer(jsonValue),
		)
		if resp != nil {
			defer util.CloseBodyWithLog(resp.Body)
		}
		if err != nil {
			RespAndLog(w, r.Context(),
				NewConnectionError(http.StatusInternalServerError,
					fmt.Errorf("POSt to Scanner failed: %w", err)))
			return
		}

		_, err = io.Copy(w, resp.Body)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewHTTPResponseError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't respond with response from Scanner: %w", err)))
			return
		}
	}
}

func (api *api) quickReqToScanner(ctx context.Context, method, url string, outData interface{}) error {
	tensorsecScannerReq, err := http.NewRequest(method, url, nil)
	if err != nil {
		return NewAnError(http.StatusInternalServerError,
			fmt.Errorf("Failed to prepare request to tensorsec scanner: %w", err))
	}

	httpClient := http.Client{}
	resp, err := httpClient.Do(tensorsecScannerReq.WithContext(ctx))
	if err != nil {
		return NewAnError(http.StatusInternalServerError,
			fmt.Errorf("Failed to send request to tensorsec scanner: %w", err))
	}
	defer util.CloseBodyWithLog(resp.Body)

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return NewHarborUnauthorizedError(resp.StatusCode, fmt.Errorf("Harbor API returned status Unauthorized"))
		} else if resp.StatusCode == http.StatusForbidden {
			return NewHarborForbiddenError(resp.StatusCode, fmt.Errorf("Harbor API returned status Forbidden"))
		} else if resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusPreconditionFailed {
			// 409 is documented as "harbor scan already in progress", 412 is undocumented
			return NewHarborScanAllInProgressError(resp.StatusCode, fmt.Errorf("Harbor scan already in progress"))
		} else if resp.StatusCode == http.StatusServiceUnavailable {
			return NewHarborError(resp.StatusCode, fmt.Errorf("Harbor API returned error, potentially no scanners detected"))
		} else {
			return NewHarborError(resp.StatusCode, fmt.Errorf("Harbor API returned error"))
		}
	}

	var envelope response.HTTPEnvelope
	err = json.NewDecoder(resp.Body).Decode(&envelope)
	if err != nil {
		return NewAnError(http.StatusInternalServerError,
			fmt.Errorf("Failed to decode response from tensorsec scanner: %w", err))
	}

	logging.GetLogger().Info().Str("envelope", fmt.Sprintf("%+v", envelope)).Msg("Received response from tensorsec scanner")

	json.Unmarshal(envelope.Data.Item, outData)
	if err != nil {
		return NewAnError(http.StatusInternalServerError,
			fmt.Errorf("Failed to unmarshal from tensorsec scanner: %w", err))
	}

	return nil
}

// @Summary Tell scanner to scan an image
// @Description Tell scanner to scan an image
// @Router /api/v2/containerSec/scanner/scanOne [post]
func (api *api) scanOne() http.HandlerFunc {
	type param struct {
		FullRepoName string `json:"full_repo_name"`
		Tag          string `json:"tag"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()
		var p param
		err := util.DecodeJSONBody(w, r, &p)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		if len(p.FullRepoName) > 64 || len(p.Tag) > 32 {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("FullRepoName or  tag len error"),
				Suberror{"RepoName/tag", ""}))
			return
		}

		projectNameRepoName := strings.SplitN(p.FullRepoName, "/", 2)
		projectName := projectNameRepoName[0]
		repoName := projectNameRepoName[1]
		frepoName := strings.Replace(repoName, "/", "%252F", -1)

		tag := strings.SplitN(p.Tag, ";", 2)

		err = api.harborClient.ScanOne(ctx, projectName, frepoName, tag[0])
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to trigger  scan one in Harbor: %w", err))
			return
		}

		response.Ok(w, response.WithItem(resp{Status: "OK"}))

	}
}
