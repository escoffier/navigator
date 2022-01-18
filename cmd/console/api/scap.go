package api

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/pkg/errors"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) scap() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/{checkType}/{clusterKey}", api.scapCheck())
		r.Get("/{checkType}/{nodeName}/{checkID}/details", api.getNodeCheckDetails())
		r.Get("/{checkType}/breakdown/{checkID}/{policyNumber}/details", api.getPolicyDetails())
		r.Get("/{checkType}/breakdown/{checkID}", api.getCheckBreakdown())
		r.Get("/{checkType}/{clusterKey}/breakdown", api.getLatestScanRecord())
		r.Get("/{checkType}/{clusterKey}/history", api.getCheckHistory())
		r.Post("/harborScan", api.harborScan())
		r.Get("/harborScanList", api.harborScanList())
		r.Get("/{checkType}/{clusterKey}/cron", api.getCron())
		r.Put("/{checkType}/{clusterKey}/cron", api.putCron())
		r.Get("/{checkType}/{checkID}/exportfile", api.exportFile())
		r.Get("/{checkID}/getfile", api.getFile())
	}
}

func (api *api) scapInternal() func(chi.Router) {
	return func(r chi.Router) {
		r.Put("/scanResults", api.addScanResults())
		r.Post("/nodeRecordVariate", api.updateRecordVariate())
	}
}

// @Summary Get node check details
// @Description Get node check details
// @ID v1-node-check-details-get
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param nodeName path string true "nodeName"
// @Param checkID path string true "checkID"
// @Router /api/v1/scap/{checkType}/{nodeName}/{checkID}/details [get]
func (api *api) getNodeCheckDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkID param missing"), Suberror{"checkID", ""}))
			return
		}

		nodeName := chi.URLParam(r, "nodeName")
		if nodeName == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("nodeName param missing"), Suberror{"nodeName", ""}))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest,
				fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
				Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		scapService, _ := scapper.GetService(ctx)
		nodeCheckDetails := &model.NodeCheckDetails{}

		switch checkType {
		case model.ComplianceCheckTargetTypeKube:
			err := scapService.GetNodeChecKubeDetails(ctx, nodeName, checkID, string(checkType), nodeCheckDetails)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get kube history entries: %w", err)))
				return
			}

		case model.ComplianceCheckTargetTypeDocker:
			err := scapService.GetNodeCheckDockerDetails(ctx, nodeName, checkID, string(checkType), nodeCheckDetails)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get docker history entries: %w", err)))
				return
			}

		case model.ComplianceCheckTargetTypeHost:
			err := scapService.GetNodeCheckHostDetails(ctx, nodeName, checkID, string(checkType), nodeCheckDetails)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get host history entries: %w", err)))
				return
			}
		}

		response.Ok(w, response.WithItem(*nodeCheckDetails))
	}
}

// @Summary Get scap history
// @Description Get scap history
// @ID v1-scap-history
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param checkID query string false "checkID"
// @Param clusterKey query string false "clusterKey"
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param sortOrder query string false "asc/desc"
// @Param sortBy query string false "createdAt/finishedAt/checkID/clusterKey/numSuccessful/numFailed/numError/numWaiting/numInconclusive"
// @Router /api/v1/scap/{checkType}/history [get]
func (api *api) getCheckHistory() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		clusterKey := chi.URLParam(r, "clusterKey")
		if clusterKey == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("Couldn't read ClusterID")))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)")))
			return
		}

		sortBy := "created_at"
		sortOrder, err := api.sortOrderFromQuery(r, "desc")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		offset, limit := api.getOffsetAndLimit(r)
		scapService, _ := scapper.GetService(ctx)

		items, docNum, err := scapService.GetCheckHistory(ctx, offset, limit, clusterKey, string(checkType), sortBy, sortOrder)
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get host history entries: %w", err)))
			return
		}

		response.Ok(w,
			response.WithItems(items),
			response.WithTotalItems(int64(docNum)),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

// @Summary Get scap job breakdown
// @Description Get scap job breakdown
// @ID v1-scap-job-breakdown
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param checkID path string true "check ID"
// @Param policyNumber query string false "policy number"
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param sortOrder query string false "asc/desc"
// @Param sortBy query string false "policyNumber/name/numFailed/numSuccessful/numInfo/numWarn"
// @Router /api/v1/scap/{checkType}/breakdown/{checkID} [get]
func (api *api) getCheckBreakdown() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkID param missing"), Suberror{"checkID", ""}))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest,
				fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
				Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		offset, limit := api.getOffsetAndLimit(r)

		waitingOn := []string{}
		errorOn := []string{}
		successOn := []string{}
		checkMap := make(map[string]*model.CheckBreakdown)

		scapService, _ := scapper.GetService(ctx)
		err := scapService.GetNodeState(ctx, &waitingOn, &errorOn, &successOn, checkID)
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get scan node state failed, %w", err)))
			return
		}

		switch checkType {
		case model.ComplianceCheckTargetTypeKube:
			err := scapService.GetKubeBreakdownEntries(ctx, checkMap, checkID, string(checkType))
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get kube breakdown entries: %w", err)))
				return
			}
		case model.ComplianceCheckTargetTypeDocker:
			err := scapService.GetDockerBreakdownEntries(ctx, checkMap, checkID, string(checkType))
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get docker breakdown entries: %w", err)))
				return
			}
		case model.ComplianceCheckTargetTypeHost:
			err := scapService.GetHostBreakdownEntries(ctx, checkMap, checkID, string(checkType))
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get host breakdown entries: %w", err)))
				return
			}
		}

		var results []*model.CheckBreakdown
		for _, v := range checkMap {
			results = append(results, v)
		}

		docNum := int64(len(checkMap))

		resultsOffset := int(math.Min(float64(offset), float64(len(results))))
		resultsLimit := int(math.Min(float64(offset+limit), float64(len(results))))
		response.Ok(w,
			response.WithCustomField("waitingOn", waitingOn),
			response.WithCustomField("errorOn", errorOn),
			response.WithCustomField("successOn", successOn),
			response.WithItems(results[resultsOffset:resultsLimit]),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

// @Summary Get scap job breakdown
// @Description Get scap job breakdown
// @ID v1-scap-job-breakdown
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param policyNumber query string false "policy number"
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param sortOrder query string false "asc/desc"
// @Router /api/v1/scap/{checkType}/breakdown [get]
func (api *api) getLatestScanRecord() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		clusterKey := chi.URLParam(r, "clusterKey")
		if clusterKey == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("Couldn't read ClusterID")))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest,
				fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
				Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		offset, limit := api.getOffsetAndLimit(r)
		sortOrder, err := api.sortOrderFromQuery(r, "desc")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		// 抽离逻辑
		checkId, waitingOn, errorOn, successOn, checkMap, ok := api.getLatestScanRecordHandler(ctx, w, clusterKey, "", checkType, sortOrder)
		if !ok {
			return
		}

		// 这里的分页逻辑不太懂，返回的是一个map，map无序的，插入到切片中能保证顺序吗？
		var results []*model.CheckBreakdown
		for _, v := range checkMap {
			results = append(results, v)
		}

		docNum := int64(len(checkMap))

		resultsOffset := int(math.Min(float64(offset), float64(len(results))))
		resultsLimit := int(math.Min(float64(offset+limit), float64(len(results))))

		response.Ok(w,
			response.WithCustomField("waitingOn", waitingOn),
			response.WithCustomField("errorOn", errorOn),
			response.WithCustomField("successOn", successOn),
			response.WithItems(results[resultsOffset:resultsLimit]),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithCheckId(checkId),
			response.WithStartIndex(offset))
	}
}

// @Summary Get scap job policy
// @Description Get scap job policy
// @ID v1-scap-job-policy
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param checkID path string true "check ID"
// @Param policyNumber path string true "policy number"
// @Router /api/v1/scap/{checkType}/breakdown/{checkID}/{policyNumber}/details [get]
func (api *api) getPolicyDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkID param missing"), Suberror{"checkID", ""}))
			return
		}

		policyId := chi.URLParam(r, "policyNumber")
		if policyId == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("policyNumber param missing"), Suberror{"policyNumber", ""}))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return

		}
		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
				Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		policyDetails, ok := api.getPolicyDetailsHandler(ctx, w, checkType, policyId, checkID)
		if !ok {
			return
		}

		response.Ok(w, response.WithItem(*policyDetails))
	}
}

// @Summary Run compliance check on specified cluster
// @Description Run compliance check on specified cluster
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterKey path string true "cluster ID"
// @Router /api/v1/scap/{checkType}/{clusterKey} [post]
func (api *api) scapCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		clusterKey := chi.URLParam(r, "clusterKey")
		if clusterKey == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("Couldn't read ClusterID")))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)")))
			return
		}

		// username
		username := "unknown"
		// get token
		_, claims, err := jwtauth.FromContext(r.Context())
		if err == nil && claims != nil {
			// get username from token
			username = claims[JWTKeyUsername].(string)
		}

		api.scapCheckHandler(ctx, w, checkType, clusterKey, username)
	}
}

// @Router /api/v1/scap/harborScan [post]
func (api *api) harborScan() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*30)
		defer cancel()

		scapper, _ := scapper.GetScapper(ctx)
		checkUUID, err := scapper.RunHarborCheck(ctx, api.harborClient)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to run compliance check: %w", err))
			return
		}

		type resp struct {
			CheckUUID string `json:"checkUUID"`
		}

		response.Ok(w, response.WithItem(resp{
			CheckUUID: checkUUID.String(),
		}))

	}

}

// @Router /api/v1/scap/harborScanList  {get}
func (api *api) harborScanList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*5)
		defer cancel()

		projectName := r.URL.Query().Get("projectname")
		checkID := r.URL.Query().Get("checkid")
		offset, limit := api.getOffsetAndLimit(r)
		scapper, _ := scapper.GetScapper(ctx)
		items, docNum, err := scapper.HarborConfigList(ctx, offset, limit, projectName, checkID)
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

// @Router /{checkType}/exportfile  {get}
func (api *api) exportFile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		// username
		username := "unknown"
		// get token
		_, claims, err := jwtauth.FromContext(ctx)
		if err == nil && claims != nil {
			// get username from token
			username = claims[JWTKeyUsername].(string)
		}

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkID param missing")))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing")))
			return
		}

		var task model.ExportTask
		tbname := task.TableName()
		query := "task_id = ? and username = ?"
		err = api.postgresDB.Get().WithContext(ctx).Table(tbname).Take(&task, query, checkID, username).Error
		if err == nil {
			if task.Status == 1 && (time.Now().Unix()-task.CreatedAt > 300) {
				task.Status = 2
			}

			if task.Status == 2 {
				delErr := api.postgresDB.Get().WithContext(ctx).Table(tbname).Where(query, checkID, username).Delete(&task).Error
				if delErr != nil {
					logging.GetLogger().WithContext(ctx).Errorf(delErr, "delete export tasks error")
				}
			}

			response.Ok(w, response.WithExportFileStatus(task.Status))
			return
		}
		language := lang.Language(ctx)
		task.Status = 1
		task.UserName = username
		task.CheckType = string(checkType)
		task.CheckId = checkID
		task.CreatedAt = time.Now().Unix()
		task.FileName = fmt.Sprintf("/var/www/%s-%s-%v.xlsx", string(checkType), string(language), task.CreatedAt)
		// insert task data to mongo
		err = api.postgresDB.Get().WithContext(ctx).Create(&task).Error
		if err != nil {
			task.Status = 2
		} else {
			// run export file task
			scapper, _ := scapper.GetScapper(ctx)
			go scapper.RunExportFileTask(&task, language)
		}

		response.Ok(w, response.WithExportFileStatus(task.Status))
	}
}

// @Router /{checkType}/getfile  {get}
func (api *api) getFile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		// username
		username := "unknown"
		// get token
		_, claims, err := jwtauth.FromContext(r.Context())
		if err == nil && claims != nil {
			// get username from token
			username = claims[JWTKeyUsername].(string)
		}

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, errors.Errorf("checkID param missing")))
			return
		}
		var task model.ExportTask
		tbname := task.TableName()
		query := "task_id = ? and username = ?"
		err = api.postgresDB.Get().WithContext(ctx).Table(tbname).Take(&task, query, checkID, username).Error
		if err != nil {
			logging.GetLogger().Error().Msgf("get export task failed, taskId : %v, username : %v, %v", checkID, username, err)
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, errors.Errorf("get export task failed, %v", err)))
			return
		}
		// task status
		if task.Status == 1 {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, errors.Errorf("Please wait while the file is being exported.")))
			return
		}
		// delete record
		err = api.postgresDB.Get().WithContext(ctx).Table(tbname).Where(query, checkID, username).Delete(&task).Error
		if err != nil {
			logging.GetLogger().WithContext(ctx).Errorf(err, "delete export tasks error")
		}

		if task.Status == 2 {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, errors.Errorf("export file failed.")))
			return
		}

		dataLen := len(task.Content)
		data := strings.Split(task.FileName, "/")
		filename := data[len(data)-1]
		// set header
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(dataLen))
		dataLen, err = w.Write(task.Content[:dataLen])
		if err != nil {
			logging.GetLogger().Error().Msgf("download file failed, %v", err)
		}
		logging.GetLogger().Info().Msgf("file bytes : %v.", dataLen)
	}
}

func (api *api) addScanResults() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		var scanResults []*model.ScanResult

		err := util.DecodeJSONBody(w, r, &scanResults)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		svc, ok := scapper.GetService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		err = svc.AddScapScanResults(ctx, scanResults)
		if err != nil {
			logging.GetLogger().Err(err).Msg("add scanning result error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("add scanning results error")))
			return
		}
		response.Ok(w)
	}
}

func (api *api) updateRecordVariate() http.HandlerFunc {
	type scanNodeRecord struct {
		TaskID      string `json:"task_id"`
		NodeName    string `json:"node_name"`
		CheckType   string `json:"check_type"`
		AutoVariate string `json:"auto_variate"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		record := &scanNodeRecord{}

		err := util.DecodeJSONBody(w, r, record)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		svc, ok := scapper.GetService(ctx)
		if !ok {
			logging.GetLogger().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		err = svc.UpdateSnrVariate(ctx, record.TaskID, record.NodeName, record.CheckType, record.AutoVariate)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("update ScanNodeRecord err")))
			return
		}
	}
}

/* 下面是抽离出一些函数逻辑，用于和openapi共用*/

func (api *api) scapCheckHandler(ctx context.Context, w http.ResponseWriter, checkType model.ComplianceCheckType, clusterKey, username string) {
	// check scanning task
	scapService, _ := scapper.GetService(ctx)
	err := scapService.CheckScanningTask(ctx, string(checkType), clusterKey, 3600)
	if err != nil {
		RespAndLog(w, ctx, fmt.Errorf("check scann task failed, %w", err))
		return
	}

	scapper, _ := scapper.GetScapper(ctx)
	checkUUID, err := scapper.RunComplianceCheck(ctx, clusterKey, checkType, username)
	if err != nil {
		RespAndLog(w, ctx, fmt.Errorf("Failed to run compliance check: %w", err))
		return
	}

	type resp struct {
		CheckId string `json:"checkId"`
	}

	response.Ok(w, response.WithItem(resp{
		CheckId: checkUUID.String(),
	}))
}

func (api *api) getLatestScanRecordHandler(
	ctx context.Context,
	w http.ResponseWriter,
	clusterKey string,
	checkId string,
	checkType model.ComplianceCheckType,
	sortOrder string,
) (
	string,
	[]string,
	[]string,
	[]string,
	map[string]*model.CheckBreakdown,
	bool,
) {
	scapService, _ := scapper.GetService(ctx)
	if checkId == "" {
		chId, err := scapService.GetLatestHistory(ctx, clusterKey, string(checkType), "created_at", sortOrder)
		if err != nil {
			response.Ok(w, response.WithTotalItems(0))
			return "", nil, nil, nil, nil, false
		}
		checkId = chId
	}

	waitingOn := []string{}
	errorOn := []string{}
	successOn := []string{}
	checkMap := make(map[string]*model.CheckBreakdown)

	err := scapService.GetNodeState(ctx, &waitingOn, &errorOn, &successOn, checkId)
	if err != nil {
		RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get scan node state failed, %w", err)))
		return "", nil, nil, nil, nil, false
	}

	switch checkType {
	case model.ComplianceCheckTargetTypeKube:
		err := scapService.GetKubeBreakdownEntries(ctx, checkMap, checkId, string(checkType))
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get kube breakdown entries: %w", err)))
			return "", nil, nil, nil, nil, false
		}
	case model.ComplianceCheckTargetTypeDocker:
		err := scapService.GetDockerBreakdownEntries(ctx, checkMap, checkId, string(checkType))
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get docker breakdown entries: %w", err)))
			return "", nil, nil, nil, nil, false
		}
	case model.ComplianceCheckTargetTypeHost:
		err := scapService.GetHostBreakdownEntries(ctx, checkMap, checkId, string(checkType))
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get host breakdown entries: %w", err)))
			return "", nil, nil, nil, nil, false
		}
	default:
		RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("checkType is error, %v.", checkType)))
		return "", nil, nil, nil, nil, false
	}

	return checkId, waitingOn, errorOn, successOn, checkMap, true
}

func (api *api) getPolicyDetailsHandler(
	ctx context.Context,
	w http.ResponseWriter,
	checkType model.ComplianceCheckType,
	policyId, checkID string,
) (*model.PolicyDetails, bool) {

	policyDetails := &model.PolicyDetails{}
	policyDetails.CheckID = checkID

	scapService, _ := scapper.GetService(ctx)

	switch checkType {
	case model.ComplianceCheckTargetTypeKube:
		err := scapService.GetKubePolicyDetails(ctx, policyDetails, policyId, string(checkType), checkID)
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get kube policy details: %w", err)))
			return nil, false
		}
	case model.ComplianceCheckTargetTypeDocker:
		err := scapService.GetDockerPolicyDetails(ctx, policyDetails, policyId, string(checkType), checkID)
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get docker policy details: %w", err)))
			return nil, false
		}
	case model.ComplianceCheckTargetTypeHost:
		err := scapService.GetHostPolicyDetails(ctx, policyDetails, policyId, string(checkType), checkID)
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get host policy details: %w", err)))
			return nil, false
		}
	default:
		RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("checkType is error, %v.", checkType)))
		return nil, false
	}

	return policyDetails, true
}
