package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"go.mongodb.org/mongo-driver/bson/primitive"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// ScanResultResponse is the response for scan result
type ScanResultResponse struct {
	ImageName string `json:"imageName"`
	DBId      string `json:"dbId"`
}

func (api *api) scan() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/one", api.scanOne())
		r.Post("/dev/forceInvalidateCache", api.forceInvalidateCache())
		r.Get("/get/allscanStatus", api.getAllScanStatus())
		r.Get("/get/sha256scanstatus", api.getSha256ScanStatus())
		r.Post("/NewScanone", api.NewscanOne())
		r.Get("/gin/609e239b23becac252dc4e1f", api.redirect())

	}
}

// @Summary Get all virusScan Status
// @Description Get all virusScan Status form virusScan sync.Map
// @Produce json
// @Router /api/v1/scan/get/allscanStatus [get]
func (api *api) getAllScanStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		waitNum, doingNum := api.virusScan.GetAllScanStatus()
		data := struct {
			WaitNum  int `json:"waitnum"`
			DoingNum int `json:"doingnum"`
		}{WaitNum: waitNum, DoingNum: doingNum}
		response.Ok(w, response.WithItem(data))
	}
}

// @Summary Get ScanStatus from give sha256
// @Description Get ScanStatus form give sha256
// @Produce json
// @Router /api/v1/scan/get/sha256scanstatus [get]
func (api *api) getSha256ScanStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		search := r.URL.Query().Get("digest")
		res := api.virusScan.GetSha256ScanStatus(search)
		data := struct {
			Status string `json:"status,omitempty"`
		}{Status: res}
		response.Ok(w, response.WithItem(data))
	}
}

// @Summary Force layer cache invalidation.
// @Description Force layer cache invalidation. Then reinitialize it.
// @Produce json
// @Router /api/v1/scan/dev/forceInvalidateCache [post]
func (api *api) forceInvalidateCache() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		log.Warn().Msg("/api/v1/scan/forceInvalidateCache is exposed for development purpose.")

		err := api.redclair.ForceInvalidateCache(ctx)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to force cache invalidation: %w", err))
			return
		}

		log.Info().Msg("Successfully invalidated cache")
		response.Ok(w)
	}
}

// @Summary Scan one image
// @Description Scan one image
// @ID v1-scan-one-post
// @Produce json
// @Router /api/v1/scan/one [post]
func (api *api) scanOne() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		var scanReq model.ScannerReq
		err := util.DecodeJSONBody(w, r, &scanReq)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		scanReqRedacted := scanReq
		scanReqRedacted.Authorization = "<redacted>"
		log.Info().Str("request", fmt.Sprintf("%+v", scanReqRedacted)).Msgf("Received scan request")

		task := model.ScanTask{
			Status:        model.ScanStatusInProgress,
			StartedAt:     time.Now().Unix(),
			Repository:    scanReq.Repository,
			Tag:           scanReq.Tag,
			URL:           scanReq.URL,
			HarborURL:     scanReq.ResultsURL,
			Authorization: scanReq.Authorization,
			ImageDigest:   scanReq.Digest,
		}

		// 插入待扫描的任务进postgres
		imageID, err := api.scannerDB.GetImageID(ctx, scanReq.Digest, scanReq.Repository)
		tmp := &model.ScanImage{}
		if imageID != -1 {
			tmp.StartedAt = time.Now().Unix()
			tmp.ImageId = imageID
			tmp.Status = model.ScanStatusInProgress
			api.scannerDB.InsertToScanImage(ctx, tmp)
		}
		task.TableID = tmp.ID
		// persist the task to Mongo
		mongoCtx, mongoCancel := context.WithTimeout(ctx, 10*time.Second)
		defer mongoCancel()

		task.ID = primitive.NewObjectIDFromTimestamp(time.Now())
		task.HistoricisedTimestamp = time.Now()
		_, err = api.mongodb.Collection(model.ScanTasksCollection.String()).InsertOne(mongoCtx, task)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't insert document")
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't update cluster: %w", err)))
			return
		}

		viursTask := model.VirusScanTask{
			Status:        model.VirusScanDoing,
			StartedAt:     time.Now().Unix(),
			Repository:    scanReq.Repository,
			Tag:           scanReq.Tag,
			URL:           scanReq.URL,
			HarborURL:     scanReq.ResultsURL,
			Authorization: scanReq.Authorization,
			ImageDigest:   scanReq.Digest,
			ID:            primitive.NewObjectIDFromTimestamp(time.Now()),
		}
		_, err = api.mongodb.Collection(model.VirusScanTaskCollection.String()).InsertOne(mongoCtx, viursTask)

		// add the task to redclair
		api.redclair.AddScanTask(task)

		// add the task to virusScan
		api.virusScan.AddScanTask(viursTask)

		response.Ok(w, response.WithItem(task))
	}
}

func (api *api) ScannerOne(scanReq model.ScannerReq) (error, model.ScanTask) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	scanReqRedacted := scanReq
	scanReqRedacted.Authorization = "<redacted>"
	log.Info().Str("request", fmt.Sprintf("%+v", scanReqRedacted)).Msgf("Received scan request")

	task := model.ScanTask{
		Status:        model.ScanStatusInProgress,
		StartedAt:     time.Now().Unix(),
		Repository:    scanReq.Repository,
		Tag:           scanReq.Tag,
		URL:           scanReq.URL,
		HarborURL:     scanReq.ResultsURL,
		Authorization: scanReq.Authorization,
		ImageDigest:   scanReq.Digest,
	}

	// 插入待扫描的任务进postgres
	imageID, err := api.scannerDB.GetImageID(ctx, scanReq.Digest, scanReq.Repository)
	tmp := &model.ScanImage{}
	if imageID != -1 {
		tmp.StartedAt = time.Now().Unix()
		tmp.ImageId = imageID
		tmp.Status = model.ScanStatusInProgress
		api.scannerDB.InsertToScanImage(ctx, tmp)
		task.ImageID = imageID
	}
	task.TableID = tmp.ID
	// persist the task to Mongo
	mongoCtx, mongoCancel := context.WithTimeout(ctx, 10*time.Second)
	defer mongoCancel()

	task.ID = primitive.NewObjectIDFromTimestamp(time.Now())
	task.HistoricisedTimestamp = time.Now()
	_, err = api.mongodb.Collection(model.ScanTasksCollection.String()).InsertOne(mongoCtx, task)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Couldn't insert document")

		return err, task
	}

	viursTask := model.VirusScanTask{
		Status:        model.VirusScanDoing,
		StartedAt:     time.Now().Unix(),
		Repository:    scanReq.Repository,
		Tag:           scanReq.Tag,
		URL:           scanReq.URL,
		HarborURL:     scanReq.ResultsURL,
		Authorization: scanReq.Authorization,
		ImageDigest:   scanReq.Digest,
		ID:            primitive.NewObjectIDFromTimestamp(time.Now()),
	}
	_, err = api.mongodb.Collection(model.VirusScanTaskCollection.String()).InsertOne(mongoCtx, viursTask)

	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Couldn't insert document")
		return err, task
	}

	// add the task to redclair
	api.redclair.AddScanTask(task)

	api.virusScan.AddScanTask(viursTask)
	return nil, task

}

// @Router /api/v1/newscan/one [post]
func (api *api) NewscanOne() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		var scanReq model.ScannerReq
		err := util.DecodeJSONBody(w, r, &scanReq)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		scanReqRedacted := scanReq
		scanReqRedacted.Authorization = "<redacted>"
		log.Info().Str("request", fmt.Sprintf("%+v", scanReqRedacted)).Msgf("Received scan request")
		authStr := api.scannerDB.GetAuthFromRegistry(ctx, scanReq.URL)

		// scanReq.ResultsURL=url+"/harbor/projects/2/repositories/"+""
		task := model.ScanTask{
			Status:        model.ScanStatusInProgress,
			StartedAt:     time.Now().Unix(),
			Repository:    scanReq.Repository,
			Tag:           scanReq.Tag,
			URL:           scanReq.URL,
			HarborURL:     scanReq.ResultsURL,
			Authorization: authStr,
			ImageDigest:   scanReq.Digest,
		}
		// 插入待扫描的任务进postgres
		imageID, err := api.scannerDB.GetImageID(ctx, scanReq.Digest, scanReq.Repository)
		tmp := &model.ScanImage{}
		if imageID != -1 {
			tmp.StartedAt = time.Now().Unix()
			tmp.ImageId = imageID
			tmp.Status = model.ScanStatusInProgress
			api.scannerDB.InsertToScanImage(ctx, tmp)
		}
		task.TableID = tmp.ID
		// persist the task to Mongo
		mongoCtx, mongoCancel := context.WithTimeout(ctx, 10*time.Second)
		defer mongoCancel()

		task.ID = primitive.NewObjectIDFromTimestamp(time.Now())
		task.HistoricisedTimestamp = time.Now()
		_, err = api.mongodb.Collection(model.ScanTasksCollection.String()).InsertOne(mongoCtx, task)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't insert document")
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't update cluster: %w", err)))
			return
		}
		api.redclair.AddScanTask(task)
		response.Ok(w, response.WithItem(task))
	}
}

func (api *api) redirect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// /api/v2/containerSec/scanner/reportsByImageOverview
		// /api/v1/scan/reportsByImageOverview?offset=1
		pre := r.URL.String()
		log.WithContext(api.ctx).Infof("pre", pre)

		newUrl := fmt.Sprintf("%s/%s", "http://127.0.0.1:8081",
			strings.Replace(pre, "/api/v2/containerSec/scanner", "/api/v1/scan", 1))
		log.WithContext(api.ctx).Infof("newUrl", newUrl)

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
		proxy.ServeHTTP(w, r)
	}
}
