package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
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

// 转发scanner中 /api/v1/scan 开头的接口
func (api *api) scanner() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/task/{taskID}", api.getScannerTask())
		r.Get("/reportsByImageList", api.RedirectToScanner(true))     // don
		r.Get("/reportsByImageOverview", api.RedirectToScanner(true)) // don
		r.Get("/reportsByImageDetails", api.RedirectToScanner(true))  // don
		r.Get("/report/{taskID}", api.getScannerImageVulnerabilities())
		r.Post("/scan", api.scan())
		r.Post("/scanone", api.RedirectToScanner(true))

		r.Post("/harbor/scanAllNow", api.RedirectToScanner(true))
		r.Get("/harbor/scanConfig", api.harborScanConfig())
		r.Get("/harbor/scanStatus", api.RedirectToScanner(true))
		r.Get("/harbor/scanOneStatus", api.RedirectToScanner(true))
		r.Post("/harbor/abortScanAll", api.harborAbortScanAll())

		r.Get("/images/{imgDigest}/layers", api.RedirectToScanner())
		r.Get("/layers/{layerDigest}/info", api.RedirectToScanner())

		r.Get("/vulns/detail/{name}", api.RedirectToScanner())
		r.Get("/vulns/statistic", api.RedirectToScanner())
		r.Get("/vulns/all", api.RedirectToScanner())
		r.Get("/vulns/relation", api.RedirectToScanner())

		r.Get("/register/projects/{projectName}", api.RedirectToScanner())
		r.Get("/register/registries", api.RedirectToScanner())

		r.Get("/imagereject/overview", api.RedirectToScanner())
		r.Get("/imagereject/images", api.RedirectToScanner())
		r.Get("/imagereject/whitelist", api.RedirectToScanner())
		r.Post("/imagereject/whitelist", api.RedirectToScanner())
		r.Delete("/imagereject/whitelist/{id}", api.RedirectToScanner())
		r.Get("/imagereject/policy", api.RedirectToScanner())
		r.Post("/imagereject/policy", api.RedirectToScanner())
		r.Put("/imagereject/policy", api.RedirectToScanner())
		r.Delete("/imagereject/policy/{id}", api.RedirectToScanner())
		r.Post("/imagereject/scanone/cicd", api.RedirectToScanner())
		r.Post("/imagereject/online_moniter", api.RedirectToScanner())
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

// RedirectToScanner 转发scanner的请示
// 参数的意思是是否替换uri中的scanner字段，主要是为了兼容重构前的uri,之后的调用默认不传参数
func (api *api) RedirectToScanner(repaleceScannner ...bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// /api/v2/containerSec/scanner/reportsByImageOverview
		// /api/v1/scan/reportsByImageOverview?offset=1
		start := time.Now()
		pre := r.URL.String()
		log.WithContext(api.ctx).Infof("preUrl", pre)
		var newUrl string

		if len(repaleceScannner) > 0 && repaleceScannner[0] {
			newUrl = fmt.Sprintf("%s%s", api.scannerURL,
				strings.Replace(pre, "/api/v2/containerSec/scanner", "/api/v1/scan", 1))
		} else {
			newUrl = fmt.Sprintf("%s%s", api.scannerURL,
				strings.Replace(pre, "/api/v2/containerSec/scanner", "/api/v1", 1))
		}

		log.WithContext(api.ctx).Infof("newUrl", newUrl)
		log.WithContext(api.ctx).Infof("scannerURL", api.scannerURL)

		u, err := url.Parse(newUrl)
		if nil != err {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest, fmt.Errorf("count not parse the url:%s,error  %w", pre, err)))
			return
		}
		proxy := httputil.ReverseProxy{
			Director: func(request *http.Request) {
				request.URL = u
			},
		}
		log.WithContext(api.ctx).Infof(fmt.Sprintf("生成URL时间:%f秒\n", time.Since(start).Seconds()))
		proxy.ServeHTTP(w, r)
		log.WithContext(api.ctx).Infof(fmt.Sprintf("请求完成总共所用时间:%f秒\n", time.Since(start).Seconds()))
	}
}
