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
	"time"

	"github.com/go-chi/chi"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) scanner() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/task/{taskID}", api.getScannerTask())
		r.Get("/reportsBySeverity", api.listScanReportsBySeverity())
		r.Post("/scan", api.scan())
	}
}

func getTaskObjectIDFromURL(r *http.Request) (primitive.ObjectID, error) {
	taskID := chi.URLParam(r, "taskID")
	if taskID == "" {
		return primitive.NilObjectID, errors.New("taskID is not provided")
	}
	return primitive.ObjectIDFromHex(taskID)
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
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read taskID: %w", err),
					Suberror{"taskID", ""}))
			return
		}

		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		// from mongo
		var result model.ScanTask
		err = api.mongodb.Collection(model.ScanTasksCollection).FindOne(
			ctx, bson.M{"_id": taskObjectID}).Decode(&result)
		if err != nil {
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))
			return
		}

		response.Ok(w, response.WithItem(result))
	}
}

type vulnInfoEx struct {
	// Helper struct that creates one to one mapping between vulnerability and affected image.
	redclair.VulnerabilityInfo `json:"vulnInfo"`
	AffectedRepository         string `json:"affectedRepository"`
	AffectedTag                string `json:"affectedTag"`
	AffectedDigest             string `json:"affectedDigest"`
	FinishedAt                 int64  `json:"finishedAt"`
}

func sortBySeverity(vulnerabilities []vulnInfoEx, asc bool) {
	sort.Slice(vulnerabilities, func(i, j int) bool {
		if asc {
			return redclair.SeverityMap[vulnerabilities[i].Severity] < redclair.SeverityMap[vulnerabilities[j].Severity]
		} else {
			return redclair.SeverityMap[vulnerabilities[i].Severity] > redclair.SeverityMap[vulnerabilities[j].Severity]
		}
	})
}

func stableSortByCVE(vulnerabilities []vulnInfoEx, asc bool) {
	// Intended to be used after SortBySeverity
	sort.SliceStable(vulnerabilities, func(i, j int) bool {
		if asc {
			return redclair.SeverityMap[vulnerabilities[i].CVE] < redclair.SeverityMap[vulnerabilities[j].CVE]
		} else {
			return redclair.SeverityMap[vulnerabilities[i].CVE] > redclair.SeverityMap[vulnerabilities[j].CVE]
		}
	})
}

// @Summary List reports by severity
// @Description List reports by severity
// @Produce json
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param sortOrder query string false "asc/desc"
// @Param from query int64 false "absolute time (in unix epoch seconds) from which to return results (default is 1 week ago)"
// @Router /api/v1/scanner/reportsBySeverity [get]
func (api *api) listScanReportsBySeverity() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*20)
		defer cancel()

		sortOrder := r.URL.Query().Get("sortOrder")
		if sortOrder == "" {
			sortOrder = "asc"
		}
		if sortOrder != "asc" && sortOrder != "desc" {
			RespAndLog(w, r,
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
				RespAndLog(w, r,
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
				RespAndLog(w, r,
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
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))
			return
		}
		defer cursor.Close(ctx)

		digestToVulns := make(map[string][]vulnInfoEx)
		for cursor.Next(ctx) {
			var task model.ScanTask
			err := cursor.Decode(&task)
			if err != nil {
				RespAndLog(w, r,
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
				vex := vulnInfoEx{
					VulnerabilityInfo:  vuln,
					AffectedRepository: task.Repository,
					AffectedTag:        task.Tag,
					AffectedDigest:     task.ImageDigest,
					FinishedAt:         task.FinishedAt,
				}
				digestToVulns[task.ImageDigest] = append(digestToVulns[task.ImageDigest], vex)
			}
		}

		err = cursor.Err()
		if err != nil {
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Cursor error: %w", err)))
			return
		}

		// convert to list in order to sort easier
		vulns := []vulnInfoEx{}
		for _, vulnsOfDigest := range digestToVulns {
			vulns = append(vulns, vulnsOfDigest...)
		}
		sortBySeverity(vulns, sortOrder == "asc")
		stableSortByCVE(vulns, sortOrder == "asc")

		// TODO: if many images are vulnerable to the same CVE, this CVE will appear multiple times in output
		// (albeit with different `affectedImage`).
		// Why not merge them somehow?
		// The logic to merge multiple CVEs into one CVE isn't obvious. E.g. what if desription changed?
		// How to merge fixVersion?, etc...
		// Potentially something to consider the future.

		docNum := int64(len(vulns))
		actualOffset := int(math.Min(float64(offset), float64(len(vulns))))
		actualLimit := int(math.Min(float64(offset+limit), float64(len(vulns))))
		response.Ok(w,
			response.WithItems(vulns[actualOffset:actualLimit]),
			response.WithTotalItems(docNum),
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
			RespAndLog(w, r,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		jsonValue, err := json.Marshal(param)
		if err != nil {
			RespAndLog(w, r,
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
			RespAndLog(w, r,
				NewConnectionError(http.StatusInternalServerError,
					fmt.Errorf("POSt to Scanner failed: %w", err)))
			return
		}

		_, err = io.Copy(w, resp.Body)
		if err != nil {
			RespAndLog(w, r,
				NewHTTPResponseError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't respond with response from Scanner: %w", err)))
			return
		}
	}
}
