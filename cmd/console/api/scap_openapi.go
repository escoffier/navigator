package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/console/models/scap"
	scapservice "gitlab.com/piccolo_su/vegeta/cmd/console/service/scap"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/security-rd/go-pkg/logging"
)

func (api *api) createScapScanTaskOpenApi() http.HandlerFunc {

	type Response struct {
		CheckUUID []string `json:"checkUUID"`
	}

	type ClusterInfo struct {
		ClusterKey string  `json:"clusterKey"`
		Nodes      []int64 `json:"nodes"`
		IsAllNodes bool    `json:"isAllNodes"`
	}

	type scapCheckReq struct {
		// 操作人 必填
		Operator string `json:"operator" query:"operator" form:"operator" binding:"required"`
		// 检测类型，docker:表示检测Docker，host:表示检测主机，kube：表示检测kubernetes 必填
		CheckType string `json:"checkType" query:"checkType" form:"checkType" binding:"required"`
		// 集群Key 必填
		ClusterKey   string             `json:"clusterKey" query:"clusterKey" form:"clusterKey"`
		ClusterInfos []scap.ClusterInfo `json:"clusterInfos"`
		PolicyID     uint               `json:"policyId"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		var req scapCheckReq
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
				http.StatusBadRequest,
				fmt.Errorf("invalid request parameters")),
			)
			return
		}

		job := scap.Job{ClusterInfos: req.ClusterInfos, PolicyID: req.PolicyID}

		if err := job.VerifyJob(); err != nil {
			apperror.RespAndLog(
				w,
				ctx,
				apperror.NewErrorWithCode(
					http.StatusBadRequest,
					err,
				),
			)
			return
		}

		scapApiV2 := scapservice.NewService(api.rdb, api.redisClient)

		res, err := scapApiV2.CreateJob(ctx, &scapservice.Job{Job: job, UserName: req.Operator, Type: req.CheckType})
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
				http.StatusInternalServerError,
				fmt.Errorf("create job failed")),
			)
			return
		}

		response.Ok(w, response.WithItems(res))
	}
}

func (api *api) getLatestScanRecordOpenApi() http.HandlerFunc {
	type result struct {
		// 检测任务UUID
		CheckId string `json:"checkId" query:"checkId" form:"checkId"`
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
		PolicyID     int64  `json:"policyId" query:"policyId" form:"policyId"`
		CheckType    string `json:"checkType"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		clusterKey, err := param.QueryString(r, "clusterKey")
		if err != nil || clusterKey == "" {
			apperror.RespAndLog(w, ctx, apperror.NewFieldError(http.StatusBadRequest, errors.New("clusterKey is empty")))
			return
		}

		// 如果没有传就是空，就会取默认值，所以这里不处理错误
		checkID, _ := param.QueryString(r, "checkId")

		complianceType, err := param.QueryString(r, "checkType")
		if err != nil || !model.ComplianceCheckType(complianceType).IsValid() {
			apperror.RespAndLog(w, ctx, apperror.NewFieldError(http.StatusBadRequest, errors.New("invaild check type parameter")))
			return
		}
		// 如果没有传就赋默认值，所以这里忽略错误
		limit, _ := param.QueryInt(r, "limit")
		if limit == 0 {
			limit = 10
		}

		if limit > 10000 {
			limit = 10000
		}

		offset, _ := param.QueryInt(r, "offset")
		if offset < 0 {
			offset = 0
		}

		svc, _ := scapper.GetService(ctx)
		if checkID == "" {
			checkID, _, err = svc.GetLatestHistory(ctx, clusterKey, model.ComplianceCheckType(complianceType))
			if err != nil {
				if err != gorm.ErrRecordNotFound {
					apperror.RespAndLog(w, ctx, err)
					return
				}

				response.Ok(w, response.WithItems([]string{}), response.WithTotalItems(0))
				return
			}
		}

		list, err := svc.FindBreakdownEntries(ctx, checkID, model.ComplianceCheckType(complianceType), "", "", "", "")
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		var results = make([]*result, 0, len(list))
		for _, v := range list {
			results = append(results, &result{
				CheckId:       checkID,
				Classified:    v.UDBCP,
				Description:   v.Description,
				Section:       v.Section,
				NumFailed:     int64(v.Fail),
				NumWarn:       int64(v.Warn),
				NumSuccessful: int64(v.Pass),
				PolicyNumber:  v.PolicyNumber,
				CheckType:     complianceType,
			})
		}

		resultsOffset := int(math.Min(float64(offset), float64(len(results))))
		resultsLimit := int(math.Min(float64(offset+limit), float64(len(results))))

		response.Ok(w,
			response.WithItems(results[resultsOffset:resultsLimit]),
			response.WithItemsPerPage(int64(limit)),
			response.WithStartIndex(int64(offset)),
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

		complianceType, err := param.QueryString(r, "checkType")
		if err != nil || !model.ComplianceCheckType(complianceType).IsValid() {
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

		items, _, err := scapService.GetCheckHistory(ctx, offset, limit, clusterKey, string(complianceType), sortBy, sortOrder)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("couldn't get host history entries: %w", err)))
			return
		}

		var results = make([]*taskDetail, 0, len(items))
		for i := range items {
			results = append(results, &taskDetail{
				CheckId:     items[i].TaskID,
				CheckType:   items[i].CheckType,
				ClusterId:   items[i].ClusterKey,
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
		// 执行状态
		Status string `json:"status"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		policyNumber, _ := param.QueryString(r, "policyNumber")
		if policyNumber == "" {
			apperror.RespAndLog(w, ctx, apperror.NewMongoError(http.StatusInternalServerError, errors.New("policyNumber id can't be empty")))
			return
		}

		complianceType, err := param.QueryString(r, "checkType")
		if err != nil || !model.ComplianceCheckType(complianceType).IsValid() {
			apperror.RespAndLog(w, ctx, apperror.NewFieldError(http.StatusBadRequest, errors.New("invaild check type parameter")))
			return
		}

		checkId := chi.URLParam(r, "checkId")
		if checkId == "" {
			apperror.RespAndLog(w, ctx, apperror.NewMongoError(http.StatusInternalServerError, errors.New("invalid check id")))
			return
		}

		nodes := make([]*struct {
			NodeName string
			State    model.ScapScanResultStateType
		}, 0)
		err = api.rdb.GetReadDB().WithContext(ctx).Model(&model.ScanResult{}).
			Where("check_type = ? AND task_id = ? AND policy_id = ?", complianceType, checkId, policyNumber).
			Select("node_name,state").
			Find(&nodes).Error
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			apperror.RespAndLog(w, ctx, err)
			return
		}

		scapService, _ := scapper.GetService(ctx)
		policy, err := scapService.GetPolicyInfo(ctx, policyNumber, model.ComplianceCheckType(complianceType))
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, err))
			return
		}

		res := Detail{
			SuccessOn: make([]NodeInfo, 0),
			FailedOn:  make([]NodeInfo, 0),
			WarnOn:    make([]NodeInfo, 0),
		}

		for _, v := range nodes {
			node := NodeInfo{NodeName: v.NodeName, Remediation: policy.RemediationZh}
			if v.State == model.ScapScanResultStateFAIL {
				res.FailedOn = append(res.FailedOn, node)
			} else if v.State == model.ScapScanResultStateWARN {
				res.WarnOn = append(res.WarnOn, node)
			} else {
				res.SuccessOn = append(res.SuccessOn, node)
			}
		}

		response.Ok(w, response.WithItem(res))
	}
}

func (api *api) getScapCheckStatus() http.HandlerFunc {
	type detail struct {
		CheckID     string          `json:"checkId" bson:"checkId"`
		CheckType   string          `json:"checkType" bson:"checkType"`
		ClusterID   string          `json:"clusterId" bson:"clusterId"`
		Operator    string          `json:"operator" bson:"operator"`
		ClusterName string          `json:"clusterName" bson:"-"`
		CreatedAt   int64           `json:"createdAt" bson:"createdAt"`
		FinishedAt  int64           `json:"finishedAt,omitempty" bson:"finishedAt,omitempty"`
		PolicyID    uint            `json:"policyId" bson:"policyId"`
		PolicyName  string          `json:"policyName" bson:"policyName"`
		State       model.ScanState `json:"state" bson:"state"`
	}

	// NodeInfo 节点信息
	type Response struct {
		CheckUUID string `json:"checkUUID"`
		Status    string `json:"status"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		checkUUID, _ := param.QueryString(r, "checkUUID")
		if checkUUID == "" {
			apperror.RespAndLog(w, ctx, apperror.NewMongoError(http.StatusInternalServerError, errors.New("checkUUID id can't be empty")))
			return
		}

		scapApiV2 := scapservice.NewService(api.rdb, api.redisClient)

		value, err := scapApiV2.RecordDetail(ctx, checkUUID)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMongoError(http.StatusInternalServerError, errors.New("get check status error")))
			return
		}

		data := detail{
			CheckID:     value.TaskID,
			CheckType:   value.CheckType,
			ClusterID:   value.ClusterKey,
			Operator:    value.Operator,
			ClusterName: value.ClusterName,
			CreatedAt:   value.CreatedAt,
			FinishedAt:  value.FinishedAt,
			PolicyID:    value.PolicyID,
		}

		// data.NumFailed = value.FailNode
		// check finish state
		if value.State == model.ScanStateInProgress {
			data.State = 1
		} else if value.State == model.ScanStateCompleted {
			data.State = 2
		} else {
			data.State = 3
		}

		res := Response{Status: "", CheckUUID: data.CheckID}
		switch data.State {
		case 1:
			res.Status = "inprogress"
		case 2:
			res.Status = "finished"
		case 3:
			res.Status = "failed"
		}
		response.Ok(w, response.WithItem(res))
	}
}

func (api *api) getKubeScapCheckDetail() http.HandlerFunc {

	type Rule struct {
		PolicyId      int      `json:"policyId"`      // 合规的数据库ID
		DefaultValue  string   `json:"defaultValue"`  // 默认值
		Description   string   `json:"description"`   // 规则描述
		Rationale     string   `json:"rationale"`     // 解释
		FixSuggestion string   `json:"fixSuggestion"` // 修复建议
		Impact        string   `json:"impact"`        // 影响
		Audit         string   `json:"audit"`         // 验证方法
		References    []string `json:"references"`    // 参考
	}

	return func(w http.ResponseWriter, r *http.Request) {

		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		policyId, _ := param.QueryInt(r, "policyId")
		if policyId <= 0 {
			apperror.RespAndLog(w, ctx, apperror.NewMongoError(http.StatusInternalServerError, errors.New("policyId id can't be empty")))
			return
		}
		scapApiV2 := scapservice.NewService(api.rdb, api.redisClient)

		rule, err := scapApiV2.RuleDetail(ctx, "kube", policyId)

		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMongoError(http.StatusInternalServerError, errors.New("get check status error")))
			return
		}
		if rule.PolicyDetailInfoExtraDetail == nil {
			apperror.RespAndLog(w, ctx, apperror.NewMongoError(http.StatusInternalServerError, errors.New("not get kube scap detail")))
			return
		}

		resp := Rule{
			PolicyId:      policyId,
			DefaultValue:  rule.PolicyDetailInfoExtraDetail.DefaultValue,
			Description:   rule.PolicyDetailInfoExtraDetail.Description,
			Rationale:     rule.PolicyDetailInfoExtraDetail.Rationale,
			FixSuggestion: rule.PolicyDetailInfoExtraDetail.Remediation,
			Impact:        rule.PolicyDetailInfoExtraDetail.Impact,
			Audit:         rule.PolicyDetailInfoExtraDetail.Audit,
			References:    rule.PolicyDetailInfoExtraDetail.References,
		}
		if resp.References == nil {
			resp.References = make([]string, 0)
		}
		response.Ok(w, response.WithItem(resp))
	}
}

func (api *api) getScapScanPolicy() http.HandlerFunc {
	type reso struct {
		ID        uint64 `json:"id"`
		Name      string `json:"name"`
		Operator  string `json:"operator"`
		CreatedAt int64  `json:"createdAt"`
		UpdatedAt int64  `json:"updatedAt"`
		Comment   string `json:"comment"`
		IsDefault bool   `json:"isDefault"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		scapApiV2 := scapservice.NewService(api.rdb, api.redisClient)

		scanCheckType, _ := param.QueryString(r, "checkType")
		if scanCheckType == "" {
			apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
				http.StatusBadRequest,
				fmt.Errorf("not fond checkType"),
			))
			return
		}

		result, count, err := scapApiV2.PolicyBatch(ctx, scanCheckType, math.MaxInt32, 0, "")
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
				http.StatusInternalServerError,
				err,
			))
			return
		}

		var resp = make([]reso, 0, len(result))
		for i := range result {

			s := reso{
				ID:        result[i].ID,
				Name:      result[i].Name,
				Comment:   result[i].Comment,
				Operator:  result[i].Operator,
				CreatedAt: result[i].CreatedAt.Unix(),
				UpdatedAt: result[i].UpdatedAt.Unix(),
				IsDefault: result[i].IsDefault,
			}

			resp = append(resp, s)
		}

		response.Ok(w, response.WithItems(resp), response.WithTotalItems(count))
	}
}

func (api *api) scapOpenApi() func(chi.Router) {
	rate, err := strconv.Atoi(os.Getenv("OPENAPI_RATE_LIMIT_PER_MIN"))
	if err != nil || rate <= 0 {
		rate = 20
	}

	return func(r chi.Router) {
		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Post("/scan/scantask", api.createScapScanTaskOpenApi()) // 创建合规扫描任务

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/scan/record", api.getLatestScanRecordOpenApi()) // 获取扫描结果列表

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/scan/task", api.getCheckHistoryOpenApi()) // 合规扫描任务列表

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/scan/record/tasks/{checkId}", api.getPolicyDetailsOpenApi()) // 合规检测详情

		// 检测状态的接口请求会频繁一些
		r.With(RateLimitMiddleware(api.redisClient, 60)).
			Get("/scan/record/status", api.getScapCheckStatus()) // 合规检测状态

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/scan/record/kube/detail", api.getKubeScapCheckDetail()) // kube合规检测详情

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/scan/policies", api.getScapScanPolicy()) // 合规策略列表

	}
}
