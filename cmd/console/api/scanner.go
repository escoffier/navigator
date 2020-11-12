package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"

	"time"

	"github.com/go-chi/chi"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

	s "gitlab.com/piccolo_su/vegeta/cmd/console/model/scanner"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
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

		// from mongo
		var scanTask model.ScanTask
		err = api.mongodb.Collection(model.ScanTasksCollection).FindOne(
			ctx, bson.M{"_id": taskObjectID}).Decode(&scanTask)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))
			return
		}

		result := &s.ImageScanDetailedResult{}
		report := scanTask.ScanReport.Vulns
		util.SortVulnsBySeverityAndStuff(report.Vulnerabilities, false)

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
// @Router /api/v1/scanner/reportsByImage [get]
func (api *api) listScannerImageVulnerabilities() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		offset, limit := api.getOffsetAndLimit(r)

		filter := bson.M{}
		findOptions := options.Find()
		findOptions.SetSort(bson.D{{"finishedAt", 1}})

		cursor, err := api.mongodb.Collection(model.ScanTasksCollection).Find(ctx, filter, findOptions)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))
			return
		}
		defer cursor.Close(ctx)

		scanTasksMap := make(map[string]model.ScanTask)
		for cursor.Next(ctx) {
			var task model.ScanTask
			err := cursor.Decode(&task)
			if err != nil {
				RespAndLog(w, r.Context(),
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't decode document: %w", err)))
				return
			}

			if task.Status != model.ScanStatusSucceeded {
				continue
			}

			scanTasksMap[task.ImageDigest] = task
		}
		scanTasks := make([]model.ScanTask, 0, len(scanTasksMap))

		for _, scanTask := range scanTasksMap {
			scanTasks = append(scanTasks, scanTask)
		}

		actualOffset := int(math.Min(float64(offset), float64(len(scanTasks))))
		actualLimit := int(math.Min(float64(offset+limit), float64(len(scanTasks))))

		scanTasks = scanTasks[actualOffset:actualLimit]
		items := make([]s.ImageScanSummaryResult, len(scanTasks))
		for scanTaskNo, scanTask := range scanTasks {
			imageScanResult := &s.ImageScanSummaryResult{}
			report := scanTask.ScanReport.Vulns
			util.SortVulnsBySeverityAndStuff(report.Vulnerabilities, false)

			topVulnsNum := len(report.Vulnerabilities)
			if len(report.Vulnerabilities) >= 5 {
				topVulnsNum = 5
			}
			imageScanResult.TopVulns = report.Vulnerabilities[:topVulnsNum]

			if len(imageScanResult.TopVulns) >= 1 {
				imageScanResult.OverallSeverity = report.Vulnerabilities[0].Severity
			} else {
				imageScanResult.OverallSeverity = redclair.SeverityUnknown
			}
			imageScanResult.SensitiveFiles = report.Sensitives
			imageScanResult.Repository = report.Repository
			imageScanResult.Tag = report.Tag
			imageScanResult.Digest = report.Digest
			imageScanResult.TaskID = scanTask.ID
			items[scanTaskNo] = *imageScanResult
		}
		docNum := int64(len(items))
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

		// from mongo
		var result model.ScanTask
		err = api.mongodb.Collection(model.ScanTasksCollection).FindOne(
			ctx, bson.M{"_id": taskObjectID}).Decode(&result)
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
// @Param from query int64 false "absolute time (in unix epoch seconds) from which to return results (default is 1 week ago)"
// @Router /api/v1/scanner/reportsBySeverity [get]
func (api *api) listScanReportsBySeverity() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*20)
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

		fromDateUnix := time.Now().Add(-1 * time.Hour * 24 * 7).Unix()
		toDateUnix := time.Now().Unix()

		filterFrom := r.URL.Query().Get("from")
		filterTo := r.URL.Query().Get("to")
		if filterFrom != "" {
			fromTimestamp, err := time.Parse(time.RFC3339, filterFrom)
			if err != nil {
				RespAndLog(w, r.Context(),
					NewFieldError(http.StatusBadRequest,
						fmt.Errorf("failed to parse time (allowed: RFC3339 timestamp format): %w", err),
						Suberror{"from", "allowed: RFC3339 timestamp format"}))
				return
			}
			fromDateUnix = fromTimestamp.Unix()
		}
		if filterTo != "" {
			toTimestamp, err := time.Parse(time.RFC3339, filterTo)
			if err != nil {
				RespAndLog(w, r.Context(),
					NewFieldError(http.StatusBadRequest,
						fmt.Errorf("failed to parse time (allowed: RFC3339 timestamp format): %w", err),
						Suberror{"to", "allowed: RFC3339 timestamp format"}))
				return
			}
			toDateUnix = toTimestamp.Unix()
		}

		filter := bson.M{
			"finishedAt": bson.M{"$gt": fromDateUnix, "$lt": toDateUnix},
		}
		if filterTo == "" {
			filter = bson.M{
				"finishedAt": bson.M{"$gt": fromDateUnix},
			}
		}

		findOptions := options.Find()
		// sorted by date ascending, so that newer scans of the same digest are on top ("last scan wins")
		// NOTE: need index on finishedAt ascending on this collection for this to work, otherwise
		// may get errors like:
		//  (OperationFailed) Executor error during find command :: caused by ::
		//  Sort operation used more than the maximum 33554432 bytes of RAM. Add an index, or specify a smaller limit."
		findOptions.SetSort(bson.D{{"finishedAt", 1}})

		cursor, err := api.mongodb.Collection(model.ScanTasksCollection).Find(ctx, filter, findOptions)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))
			return
		}
		defer cursor.Close(ctx)

		type vulnInfoEx struct {
			// Helper struct that creates one to one mapping between vulnerability and affected image.
			redclair.VulnerabilityInfo
			AffectedRepository string
			AffectedTag        string
			AffectedDigest     string
			AffectedHarborURL  string
			FinishedAt         int64
			TaskID             primitive.ObjectID
		}

		digestToVulns := make(map[string][]vulnInfoEx)
		for cursor.Next(ctx) {
			var task model.ScanTask
			err := cursor.Decode(&task)
			if err != nil {
				RespAndLog(w, r.Context(),
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't decode document: %w", err)))
				return
			}

			if task.Status != model.ScanStatusSucceeded {
				continue
			}

			// if the same ImageDigest was encountered before, its list of vulns will be overwritten.
			// This way, we only keep info from the newest scan of an image.
			// This assumes cursor returns entries sorted from old to new.
			digestToVulns[task.ImageDigest] = []vulnInfoEx{}

			for _, vuln := range task.ScanReport.Vulns.Vulnerabilities {

				if riskFilter == "medToCrit" || riskFilter == "networkBased" {
					if !redclair.SeverityGreaterThan(vuln.Severity, redclair.SeverityLow) {
						continue
					}
				}
				if riskFilter == "networkBased" {
					if strings.Contains(vuln.CVSSv2Vector, "AV:L") {
						continue
					}
				}

				vex := vulnInfoEx{
					VulnerabilityInfo:  vuln,
					AffectedRepository: task.Repository,
					AffectedTag:        task.Tag,
					AffectedDigest:     task.ImageDigest,
					AffectedHarborURL:  task.HarborURL,
					FinishedAt:         task.FinishedAt,
					TaskID:             task.ID,
				}
				digestToVulns[task.ImageDigest] = append(digestToVulns[task.ImageDigest], vex)
			}
			for _, sens := range task.ScanReport.Vulns.Sensitives {

				if riskFilter == "medToCrit" || riskFilter == "networkBased" {
					continue
				}

				// "dumb" convert of sensitive file info to vulnerability info.
				// Consider a different way to return this maybe?
				vi := redclair.VulnerabilityInfo{
					Description:    fmt.Sprintf("Potential file leak: %s", sens.Description),
					FeatureName:    sens.Name,
					Severity:       redclair.SeverityMedium,
					CVE:            "-",
					CNNVD:          "-",
					Namespace:      "-",
					Links:          []string{},
					FeatureVersion: "-",
					FixedBy:        "-",
				}
				vex := vulnInfoEx{
					VulnerabilityInfo:  vi,
					AffectedRepository: task.Repository,
					AffectedTag:        task.Tag,
					AffectedDigest:     task.ImageDigest,
					AffectedHarborURL:  task.HarborURL,
					FinishedAt:         task.FinishedAt,
					TaskID:             task.ID,
				}
				digestToVulns[task.ImageDigest] = append(digestToVulns[task.ImageDigest], vex)
			}
		}

		err = cursor.Err()
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Cursor error: %w", err)))
			return
		}

		listItemsSet := make(map[string]scanReportListItem)
		for _, vulns := range digestToVulns {

			for _, vuln := range vulns {
				key := vuln.CVE
				if key == "-" {
					// handle sensitive filename
					key = vuln.FeatureName
				}

				if _, ok := listItemsSet[key]; !ok {
					listItemsSet[key] = scanReportListItem{
						VulnInfo:       vuln.VulnerabilityInfo,
						AffectedImages: &[]scanReportAffectedImage{},
					}
				}

				af := scanReportAffectedImage{
					Repository: vuln.AffectedRepository,
					Tag:        vuln.AffectedTag,
					Digest:     vuln.AffectedDigest,
					HarborURL:  vuln.AffectedHarborURL,
					FinishedAt: vuln.FinishedAt,
					TaskID:     vuln.TaskID,
				}

				*listItemsSet[key].AffectedImages = append(*listItemsSet[key].AffectedImages, af)
			}
		}

		// convert to list in order to sort easier
		listItems := make([]scanReportListItem, len(listItemsSet))
		i := 0
		for _, item := range listItemsSet {
			listItems[i] = item
			i++
		}

		sortListItemsBySeverityAndStuff(listItems, sortOrder == "asc")

		// TODO: if many images are vulnerable to the same CVE, this CVE will appear multiple times in output
		// (albeit with different `affectedImage`).
		// Why not merge them somehow?
		// The logic to merge multiple CVEs into one CVE isn't obvious. E.g. what if desription changed?
		// How to merge fixVersion?, etc...
		// Potentially something to consider the future.

		docNum := int64(len(listItems))
		actualOffset := int(math.Min(float64(offset), float64(len(listItems))))
		actualLimit := int(math.Min(float64(offset+limit), float64(len(listItems))))
		response.Ok(w,
			response.WithItems(listItems[actualOffset:actualLimit]),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

func sortListItemsBySeverityAndStuff(vulnerabilities []scanReportListItem, asc bool) {
	sort.Slice(vulnerabilities, func(i, j int) bool {
		if !asc {
			i, j = j, i
		}

		return redclair.CompareVulnerabilities(vulnerabilities[i].VulnInfo, vulnerabilities[j].VulnInfo)
	})
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
