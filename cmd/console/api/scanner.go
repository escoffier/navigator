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

	"time"

	"github.com/go-chi/chi"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

	s "gitlab.com/piccolo_su/vegeta/cmd/console/model/scanner"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) scanner() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/task/{taskID}", api.getScannerTask())
		r.Get("/reportsBySeverity", api.listScanReportsBySeverity())
		r.Get("/reportsByImage", api.listScannerImageVulnerabilities())
		r.Get("/report/{taskID}", api.getScannerImageVulnerabilities())
		r.Post("/scan", api.scan())

		r.Post("/harbor/scanAllNow", api.harborScanAllNow())
		r.Get("/harbor/scanConfig", api.harborScanConfig())
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
		err = api.mongodb.Collection(model.ScanTasksCollection).FindOne(
			ctx, bson.M{"_id": taskObjectID}, findOneOptions).Decode(&scanTask)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))
			return
		}

		result := &s.ImageScanDetailedResult{}
		report := scanTask.ScanReport.Vulns

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
func (api *api) listScannerImageVulnerabilities() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		maxImageAgeInHoursRaw := r.URL.Query().Get("maxImageAgeInHours")
		var imageTimeFilter time.Time
		if maxImageAgeInHoursRaw != "" && maxImageAgeInHoursRaw != "0" {
			maxImageAgeInHours, err := strconv.Atoi(maxImageAgeInHoursRaw)
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
			imageTimeFilter = time.Now().Add(time.Duration(-1*maxImageAgeInHours) * time.Hour)
		}

		sortBy := r.URL.Query().Get("sortBy")
		if sortBy == "" {
			sortBy = "finishedAt"
		}
		if sortBy != "finishedAt" && sortBy != "overallSeverity" && sortBy != "repository" && sortBy != "tag" && sortBy != "imageDigest" {
			RespAndLog(w, r.Context(),
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid sortBy param value (allowed: finishedAt/overallSeverity/repository/tag/imageDigest)"),
					Suberror{"sortBy", "allowed: finishedAt/overallSeverity/repository/tag/imageDigest"}))
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
		sortOrderInt := 1
		if sortOrder == "desc" {
			sortOrderInt = -1
		}

		offset, limit := api.getOffsetAndLimit(r)

		filter := bson.M{
			"$and": []bson.M{
				{"stale": false},
				{"status": model.ScanStatusSucceeded},
			},
		}
		if !imageTimeFilter.IsZero() {
			filter = bson.M{
				"$and": []bson.M{
					{"stale": false},
					{"status": model.ScanStatusSucceeded},
					{"firstScanAt": bson.M{"$gt": imageTimeFilter.Unix()}},
				},
			}
		}

		mt := time.Second * 10
		findOptions := options.FindOptions{
			Skip:    &offset,
			Limit:   &limit,
			MaxTime: &mt,
		}

		switch sortBy {
		case "finishedAt":
			findOptions.SetSort(bson.D{{"finishedAt", sortOrderInt}})
		case "overallSeverity":
			findOptions.SetSort(bson.D{{"scan_report.overallSeverityInt", sortOrderInt}})
		case "repository":
			findOptions.SetSort(bson.D{{"repository", sortOrderInt}})
		case "tag":
			findOptions.SetSort(bson.D{{"tag", sortOrderInt}})
		case "imageDigest":
			findOptions.SetSort(bson.D{{"digest", sortOrderInt}})
		}

		docNum, err := api.mongodb.Collection(model.ScanTasksCollection).CountDocuments(ctx, filter)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Failed to count documents: %w", err)))
			return
		}

		cursor, err := api.mongodb.Collection(model.ScanTasksCollection).Find(ctx, filter, &findOptions)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))
			return
		}
		defer cursor.Close(ctx)

		scanTasks := []model.ScanTask{}
		for cursor.Next(ctx) {
			var task model.ScanTask
			err := cursor.Decode(&task)
			if err != nil {
				RespAndLog(w, r.Context(),
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't decode document: %w", err)))
				return
			}

			scanTasks = append(scanTasks, task)
		}

		items := make([]s.ImageScanSummaryResult, len(scanTasks))
		for scanTaskNo, scanTask := range scanTasks {

			report := scanTask.ScanReport.Vulns

			topVulnsNum := len(report.Vulnerabilities)
			if len(report.Vulnerabilities) >= 5 {
				topVulnsNum = 5
			}

			for j := range report.Sensitives {
				if lang.Language(ctx) == lang.LanguageZH {
					description := report.Sensitives[j].DescriptionZh
					report.Sensitives[j].Description = description
				} else {
					description := report.Sensitives[j].DescriptionEn
					report.Sensitives[j].Description = description
				}
			}

			imageScanResult := s.ImageScanSummaryResult{
				TopVulns:        report.Vulnerabilities[:topVulnsNum],
				SensitiveFiles:  report.Sensitives,
				Repository:      report.Repository,
				Tag:             report.Tag,
				Digest:          report.Digest,
				TaskID:          scanTask.ID,
				StartedAt:       scanTask.StartedAt,
				FinishedAt:      scanTask.FinishedAt,
				OverallSeverity: scanTask.ScanReport.OverallSeverity,
			}

			items[scanTaskNo] = imageScanResult
		}

		response.Ok(w,
			response.WithItems(items),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
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
		err = api.mongodb.Collection(model.ScanTasksCollection).FindOne(
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

type scanReportAffectedImage struct {
	Repository string             `json:"repository"`
	Tag        string             `json:"tag"`
	Digest     string             `json:"digest"`
	HarborURL  string             `json:"harborURL"`
	FinishedAt int64              `json:"finishedAt"`
	TaskID     primitive.ObjectID `json:"taskID"`
}

type scanReportListItem struct {
	VulnInfo       redclair.VulnerabilityInfo `json:"vulnInfo"`
	AffectedImages *[]scanReportAffectedImage `json:"affectedImages"`
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
			riskFilter = "none"
		}
		if riskFilter != "none" && riskFilter != "medToCrit" && riskFilter != "networkBased" {
			RespAndLog(w, r.Context(),
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid riskFilter param value (allowed: none(default)/medToCrit/networkBased)"),
					Suberror{"riskFilter", "allowed: none(default)/medToCrit/networkBased"}))
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
		resultItems, size, err := api.syncData.GetResultItem(ctx, riskFilter, offset, limit, sortOrder)
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
			defer resp.Body.Close()
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

// @Summary Trigger scan of all images in Harbor.
// @Description Trigger scan of all images in Harbor.
// @Router /api/v1/scanner/harbor/scanAllNow [post]
func (api *api) harborScanAllNow() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		type respT struct{}
		var resp respT
		err := api.quickReqToScanner(ctx, "POST", fmt.Sprintf("%s/api/v1/scan/harbor/scanAll", api.scannerURL), &resp)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		response.Ok(w)
	}
}

// @Summary Redirect to scan config screen in Harbor.
// @Description Redirect to scan config screen in Harbor.
// @Router /api/v1/scanner/harbor/scanConfig [get]
func (api *api) harborScanConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		type respT struct {
			Href string `json:"href"`
		}
		var resp respT
		err := api.quickReqToScanner(ctx, "GET", fmt.Sprintf("%s/api/v1/scan/harbor/scanConfigURL", api.scannerURL), &resp)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		response.Ok(w, response.WithItem(resp))
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
	defer resp.Body.Close()

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
