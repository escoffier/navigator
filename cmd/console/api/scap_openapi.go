package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) scapCheckOpenApi() http.HandlerFunc {

	type scapCheckReq struct {
		// 操作人 必填
		Operator string `json:"operator" query:"operator" form:"operator" binding:"required"`
		// 检测类型，docker:表示检测Docker，host:表示检测主机，kube：表示检测kubernetes 必填
		CheckType string `json:"checkType" query:"checkType" form:"checkType" binding:"required"`
		// 集群Key 必填
		ClusterKey string `json:"clusterKey" query:"clusterKey" form:"clusterKey"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		var req scapCheckReq

		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewFieldError(http.StatusBadRequest, errors.New("couldn't parse params")))
			return
		}

		if req.CheckType != "docker" && req.CheckType != "host" && req.CheckType != "kube" {
			apperror.RespAndLog(w, ctx, apperror.NewFieldError(http.StatusBadRequest, errors.New("invaild check type")))
			return
		}

		if req.ClusterKey == "" && req.Operator == "" {
			apperror.RespAndLog(w, ctx, apperror.NewFieldError(http.StatusBadRequest, errors.New("param can't be empty")))
			return
		}

		api.scapCheckHandler(ctx, w, model.ComplianceCheckType(req.CheckType), req.ClusterKey, req.Operator)
	}
}

func (api *api) getLatestScanRecordOpenApi() http.HandlerFunc {
	type result struct {
		// 检测任务UUID
		CheckUUID string `json:"checkUUID" query:"checkUUID" form:"checkUUID"`
		// 等保对齐
		Classified string `json:"classified" query:"classified" form:"classified"`
		// 具体要求
		Description string `json:"description" query:"description" form:"description"`
		// 合规条目
		Section string `json:"section" query:"section" form:"section"`
		// 不合规数
		NumFailed int64 `json:"numFailed" query:"numFailed" form:"numFailed"`
		// 警告数
		NumWarn int64 `json:"numWarn" query:"numWarn" form:"numWarn"`
		// 合规数
		NumSuccessful int64 `json:"numSuccessful" query:"numSuccessful" form:"numSuccessful"`
		// 合规ID
		PolicyNumber string `json:"policyNumber" query:"policyNumber" form:"policyNumber"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		clusterKey, err := param.QueryString(r, "clusterKey")
		if err != nil || clusterKey == "" {
			apperror.RespAndLog(w, ctx, apperror.NewFieldError(http.StatusBadRequest, errors.New("clusterKey is empty")))
			return
		}

		checkType, err := param.QueryString(r, "checkType")
		if err != nil || (checkType != "docker" && checkType != "host" && checkType != "kube") {
			apperror.RespAndLog(w, ctx, apperror.NewFieldError(http.StatusBadRequest, errors.New("invaild check type parameter")))
			return
		}

		limit, err := param.QueryInt64(r, "limit")
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewFieldError(http.StatusBadRequest, errors.New("invaild limit parameter")))
			return
		}

		if limit == 0 {
			limit = 10
		}

		if limit > 100 {
			limit = 100
		}

		offset, err := param.QueryInt64(r, "offset")
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewFieldError(http.StatusBadRequest, errors.New("invaild offset parameter")))
			return
		}

		checkId, _, _, _, checkMap, ok := api.getLatestScanRecordHandler(ctx, w, clusterKey, model.ComplianceCheckType(checkType), "desc")
		if !ok {
			return
		}

		var results = make([]*result, 0, len(checkMap))
		for _, v := range checkMap {
			results = append(results, &result{
				CheckUUID:     checkId,
				Classified:    v.Classified,
				Description:   v.Description,
				Section:       v.Section,
				NumFailed:     v.NumFailed,
				NumWarn:       v.NumWarn,
				NumSuccessful: v.NumSuccessful,
				PolicyNumber:  v.PolicyNumber,
			})
		}

		resultsOffset := int(math.Min(float64(offset), float64(len(results))))
		resultsLimit := int(math.Min(float64(offset+limit), float64(len(results))))

		response.Ok(w,
			response.WithItems(results[resultsOffset:resultsLimit]),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset),
			response.WithTotalItems(int64(len(results))))
	}
}

func (api *api) getCheckHistoryOpenApi() http.HandlerFunc {

	// TaskDetail 合规检测任务详情
	type taskDetail struct {
		// 任务ID
		CheckId string `json:"checkId" query:"checkId" form:"checkId"`
		// 检测类型，docker:表示检测Docker,host:表示检测主机，kube：表示检测kubernetes
		CheckType string `json:"checkType" query:"checkType" form:"checkType"`
		// 集群ID
		ClusterId string `json:"clusterId" query:"clusterId" form:"clusterId"`
		// 集群名
		ClusterName string `json:"clusterName" query:"clusterName" form:"clusterName"`
		// 创建时间
		CreatedAt int64 `json:"createAt" query:"createAt" form:"createAt"`
		// 任务创建人
		Operator string `json:"operator" query:"operator" form:"operator"`
		// 任务完成时间,等于0时说明任务正在扫描中
		FinishedAt int64 `json:"finishedAt" query:"finishedAt" form:"finishedAt"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		clusterKey, err := param.QueryString(r, "clusterKey")
		if err != nil || clusterKey == "" {
			apperror.RespAndLog(w, r.Context(), apperror.NewFieldError(http.StatusBadRequest, errors.New("clusterKey is empty")))
			return
		}

		checkType, err := param.QueryString(r, "checkType")
		if err != nil || (checkType != "docker" && checkType != "host" && checkType != "kube") {
			apperror.RespAndLog(w, ctx, apperror.NewFieldError(http.StatusBadRequest, errors.New("invaild check type parameter")))
			return
		}

		sortBy := "created_at"
		sortOrder, err := api.sortOrderFromQuery(r, "desc")
		if err != nil {
			apperror.RespAndLog(w, r.Context(), err)
			return
		}

		offset, limit := api.getOffsetAndLimit(r)
		scapService, _ := scapper.GetService(ctx)

		items, _, err := scapService.GetCheckHistory(ctx, offset, limit, clusterKey, string(checkType), sortBy, sortOrder)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("couldn't get host history entries: %w", err)))
			return
		}

		var results = make([]*taskDetail, 0, len(items))
		for i := range items {
			results = append(results, &taskDetail{
				CheckId:     items[i].CheckID,
				CheckType:   items[i].CheckType,
				ClusterId:   items[i].ClusterID,
				ClusterName: items[i].ClusterName,
				CreatedAt:   items[i].CreatedAt,
				Operator:    items[i].Operator,
				FinishedAt:  items[i].FinishedAt,
			})
		}

		response.Ok(w,
			response.WithItems(results),
			response.WithTotalItems(int64(len(results))),
		)
	}
}

func (api *api) getPolicyDetailsOpenApi() http.HandlerFunc {

	// NodeInfo 节点信息
	type NodeInfo struct {
		// 节点名
		NodeName string `json:"nodeName" query:"nodeName" form:"nodeName"`
		// 扫描结果解释
		Remediation string `json:"remediation" query:"remediation" form:"remediation"`
	}

	// Detail 合规检测详情
	type Detail struct {
		// 合规节点信息
		SuccessOn []NodeInfo `json:"successOn" query:"successOn" form:"successOn"`
		// 不合规节点信息
		FailedOn []NodeInfo `json:"failedOn" query:"failedOn" form:"failedOn"`
		// 含有警告的信息
		WarnOn []NodeInfo `json:"warnOn" query:"warnOn" form:"warnOn"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		taskId := chi.URLParam(r, "taskId")
		if taskId == "" {
			apperror.RespAndLog(w, ctx, apperror.NewMongoError(http.StatusInternalServerError, errors.New("task id can't be empty")))
			return
		}

		checkType, err := param.QueryString(r, "checkType")
		if err != nil || (checkType != "docker" && checkType != "host" && checkType != "kube") {
			apperror.RespAndLog(w, ctx, apperror.NewFieldError(http.StatusBadRequest, errors.New("invaild check type parameter")))
			return
		}

		checkId, err := param.QueryString(r, "checkId")
		if err != nil || checkId == "" {
			apperror.RespAndLog(w, ctx, apperror.NewMongoError(http.StatusInternalServerError, errors.New("invalid check id")))
			return
		}

		result, ok := api.getPolicyDetailsHandler(ctx, w, model.ComplianceCheckType(checkType), taskId, checkId)
		if !ok {
			return
		}

		response.Ok(w, response.WithItem(result))
	}
}

func (api *api) scapOpenApi() func(chi.Router) {
	return func(r chi.Router) {
		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Post("/scan/scantask", api.scapCheckOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Get("/scan/record", api.getLatestScanRecordOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Get("/scan/task", api.getCheckHistoryOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Get("/scan/record/tasks/{taskId}", api.getPolicyDetailsOpenApi())
	}
}
