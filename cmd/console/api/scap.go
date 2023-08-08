package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/console/api/scap"
	scapservice "gitlab.com/piccolo_su/vegeta/cmd/console/service/scap"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
)

const defaultScapTimeout = time.Second * 5

func (api *api) scap() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/{checkType}/breakdown/{checkID}/{policyNumber}/details", api.getPolicyDetails())
		r.Get("/{checkType}/{clusterKey}/suggest", api.findSuggest())
		r.Get("/{checkType}/{clusterKey}/overview", api.getScapScanOverview())
		r.Get("/{checkType}/{clusterKey}/breakdown", api.findCheckBreakdown())
		r.Get("/{checkType}/{clusterKey}/breakdown/detail/list", api.findBreakdownDetailList())

		r.Get("/{checkType}/{clusterKey}/scan/node", api.findScanRecordWithNode())
		r.Get("/{checkType}/{nodeName}/{checkID}/details", api.getNodeCheckDetails())
		r.Get("/{checkType}/{clusterKey}/scan/node/detail/list", api.findScanNodeDetailList())

		r.Get("/{checkType}/{checkID}/exportfile", api.exportFile())
		r.Get("/{checkID}/getfile", api.getFile())

		scapApiV2 := scap.NewAipServer(scapservice.NewService(api.rdb, api.redisClient))
		r.Route("/v2", scapApiV2.InitRouter())
	}
}

func (api *api) scapInternal() func(chi.Router) {
	return func(r chi.Router) {
		r.Put("/scanResults", api.addScanResults())             // 已经废弃，应该移除(中移子集群升级后)
		r.Post("/nodeRecordVariate", api.updateRecordVariate()) // 已经废弃，应该移除(中移子集群升级后)
		r.Post("/scanCallback", api.scanCallback())
	}
}

func (api *api) getNodeCheckDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		taskID := chi.URLParam(r, "checkID")
		if taskID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkID param missing")))
			return
		}

		nodeName := chi.URLParam(r, "nodeName")
		if nodeName == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("nodeName param missing")))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing")))
			return
		}
		if !checkType.IsValid() {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest,
				fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)")))
			return
		}

		scapService, _ := scapper.GetService(ctx)
		nodeCheckDetails := &model.NodeCheckDetails{}
		err := scapService.GetNodeCheckDetails(ctx, nodeName, taskID, nodeCheckDetails)
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get kube history entries: %w", err)))
			return
		}

		response.Ok(w, response.WithItem(*nodeCheckDetails))
	}
}

func (a *api) findScanNodeDetailList() http.HandlerFunc {
	type resp struct {
		Pass        int `json:"pass"`
		Warn        int `json:"warn"`
		Info        int `json:"info"`
		Fail        int `json:"fail"`
		Compliances []*struct {
			PolicyNumber string                            `json:"policyNumber" gorm:"column:policy_id"`
			PolicyId     uint                              `json:"policyId" gorm:"-"`
			Section      string                            `json:"section"`
			Description  string                            `json:"description"`
			TestStatus   model.ScapScanResultStateType     `json:"testStatus"`
			TestResult   string                            `json:"testResult"`
			UDBCP        string                            `json:"udbcp"`
			ExtraDetail  model.PolicyDetailInfoExtraDetail `json:"extraDetail"  gorm:"-"`
			Runtime      string                            `json:"runtime,omitempty"`
		} `json:"compliances" gorm:"-"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultScapTimeout)
		defer cancel()

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing")))
			return
		}
		if !checkType.IsValid() {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)")))
			return
		}

		taskID, _ := param.QueryString(r, "taskID")
		if taskID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("taskId param missing")))
			return
		}
		hostname, _ := param.QueryString(r, "hostname")
		if hostname == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("hostname param missing")))
			return
		}
		keyword, _ := param.QueryString(r, "keyword")

		db := a.rdb.GetReadDB().WithContext(ctx).Model(&model.ScanResult{}).
			Where("check_type = ? AND task_id = ? AND node_name = ?", checkType, taskID, hostname)
		if keyword != "" {
			keywordParam := "%" + keyword + "%"
			db = db.Where("policy_id LIKE ? OR section LIKE ?", keywordParam, keywordParam)
		}

		result := resp{}
		err := db.Session(&gorm.Session{}).
			Select("COUNT(CASE WHEN state=? THEN 1 END) AS pass,"+
				"COUNT(CASE WHEN state=? THEN 1 END) AS warn,"+
				"COUNT(CASE WHEN state=? THEN 1 END) AS info,"+
				"COUNT(CASE WHEN state=? THEN 1 END) AS fail",
				model.ScapScanResultStatePASS, model.ScapScanResultStateWARN,
				model.ScapScanResultStateINFO, model.ScapScanResultStateFAIL).
			Limit(1).Find(&result).Error
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			RespAndLog(w, ctx, err)
			return
		}

		err = db.Select("policy_id,state AS test_status,actual_value AS test_result,udbcp").
			Find(&result.Compliances).Error
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			RespAndLog(w, ctx, err)
			return
		}

		language := lang.Language(ctx)
		svc, _ := scapper.GetService(ctx)
		for i, c := range result.Compliances {
			if checkType == model.ComplianceCheckTargetTypeDocker {
				if strings.HasPrefix(result.Compliances[i].PolicyNumber, "co") {
					result.Compliances[i].Runtime = "cri-o"
				} else if strings.HasPrefix(result.Compliances[i].PolicyNumber, "cd") {
					result.Compliances[i].Runtime = "containerd"
				} else {
					result.Compliances[i].Runtime = "docker"
				}
			}

			policy, err := svc.GetPolicyInfo(ctx, c.PolicyNumber, checkType)
			if err != nil {
				logging.Get().Warn().Err(err).Msg("svc.GetPolicyInfo")
				continue
			}

			result.Compliances[i].PolicyId = policy.Id
			if language == lang.LanguageEN {
				result.Compliances[i].Description = policy.DetailEn
				result.Compliances[i].Section = policy.TitleEn
				result.Compliances[i].UDBCP = policy.ClassifiedEn
			} else {
				result.Compliances[i].Description = policy.DetailZh
				result.Compliances[i].Section = policy.TitleZh
				result.Compliances[i].UDBCP = policy.ClassifiedZh
			}

			if policy.PolicyDetailInfoExtraDetail != nil {
				if language == lang.LanguageEN {
					result.Compliances[i].ExtraDetail.Description = policy.PolicyDetailInfoExtraDetail.DescriptionEn
					result.Compliances[i].ExtraDetail.Rationale = policy.PolicyDetailInfoExtraDetail.RationaleEn
					result.Compliances[i].ExtraDetail.Audit = policy.PolicyDetailInfoExtraDetail.AuditEn
					result.Compliances[i].ExtraDetail.Remediation = policy.PolicyDetailInfoExtraDetail.RemediationEn
					result.Compliances[i].ExtraDetail.Impact = policy.PolicyDetailInfoExtraDetail.ImpactEn
					result.Compliances[i].ExtraDetail.DefaultValue = policy.PolicyDetailInfoExtraDetail.DefaultValueEn
				} else {
					result.Compliances[i].ExtraDetail = policy.PolicyDetailInfoExtraDetail.PolicyDetailInfoExtraDetail
				}
			} else {
				result.Compliances[i].ExtraDetail = model.PolicyDetailInfoExtraDetail{
					Description: policy.DetailZh,
					Rationale:   policy.TitleZh,
					Audit:       policy.Audit,
					Remediation: policy.RemediationZh,
					References:  []string{},
				}
				if language == lang.LanguageEN {
					result.Compliances[i].ExtraDetail.Description = policy.DetailEn
					result.Compliances[i].ExtraDetail.Rationale = policy.TitleEn
					result.Compliances[i].ExtraDetail.Remediation = policy.RemediationEn
				}
			}
		}

		response.Ok(w, response.WithItems(result.Compliances),
			response.WithCustomField("pass", result.Pass),
			response.WithCustomField("info", result.Info),
			response.WithCustomField("warn", result.Warn),
			response.WithCustomField("fail", result.Fail))
	}
}

func (a *api) findSuggest() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultScapTimeout)
		defer cancel()

		clusterKey := chi.URLParam(r, "clusterKey")
		if clusterKey == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("couldn't read ClusterID")))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing")))
			return
		}
		if !checkType.IsValid() {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)")))
			return
		}

		taskID, _ := param.QueryString(r, "taskID")
		if taskID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("taskId param missing")))
			return
		}

		keyword, _ := param.QueryString(r, "keyword")
		suggestType, _ := param.QueryString(r, "suggestType")

		result, err := scap.GetSuggestProvider(suggestType).
			FindSuggestList(ctx, a.rdb.GetReadDB(), taskID, keyword, 0, 500)
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			RespAndLog(w, ctx, err)
			return
		}

		if language := lang.Language(ctx); language == lang.LanguageEN {
			if suggestType == "udbcp" {
				for i := range result {
					label, ok := model.UDBCPTranslateMap[strings.TrimSpace(result[i].Label)]
					if ok {
						result[i].Label = label
					}
				}
			} else if suggestType == "section" {
				for i := range result {
					label, ok := model.SectionPTranslateMap[strings.TrimSpace(result[i].Label)]
					if ok {
						result[i].Label = label
					}
				}
			}
		}

		response.Ok(w, response.WithItems(result))
	}
}

func (a *api) getScapScanOverview() http.HandlerFunc {
	type resp struct {
		CheckPass     int `json:"check_pass"`
		CheckFail     int `json:"check_fail"`
		CompletedNode int `json:"completedNode"`
		FailedNode    int `json:"failedNode"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultScapTimeout)
		defer cancel()

		clusterKey := chi.URLParam(r, "clusterKey")
		if clusterKey == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("couldn't read ClusterID")))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing")))
			return
		}
		if !checkType.IsValid() {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)")))
			return
		}

		taskID, _ := param.QueryString(r, "taskID")
		svc, _ := scapper.GetService(ctx)
		var err error

		if taskID == "" {
			taskID, _, err = svc.GetLatestHistory(ctx, clusterKey, checkType)
			if err != nil {
				if err != gorm.ErrRecordNotFound {
					RespAndLog(w, ctx, err)
					return
				}

				response.Ok(w, response.WithItem(struct{}{}))
				return
			}
		}

		result := resp{}
		if err = a.rdb.GetReadDB().WithContext(ctx).Model(&model.ScanNodeRecord{}).
			Select("COUNT(CASE WHEN state=? THEN 1 END) AS completed_node,"+
				"COUNT(CASE WHEN state=? THEN 1 END) AS failed_node",
				model.ScanStateCompleted, model.ScanStateFailed).
			Where("task_id = ?", taskID).
			Find(&result).Error; err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		list := make([]*model.CheckBreakdown, 0)
		err = a.rdb.GetReadDB().Model(&model.ScanResult{}).
			Select("COUNT(CASE WHEN state=? THEN 1 END) AS pass,"+
				"COUNT(CASE WHEN state=? THEN 1 END) AS warn,"+
				"COUNT(CASE WHEN state=? THEN 1 END) AS info,"+
				"COUNT(CASE WHEN state=? THEN 1 END) AS fail,"+
				"policy_id", model.ScapScanResultStatePASS, model.ScapScanResultStateWARN,
				model.ScapScanResultStateINFO, model.ScapScanResultStateFAIL).
			Group("policy_id").
			Find(&list, "task_id = ?", taskID).Error
		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		for _, v := range list {
			if v.Fail > 0 {
				result.CheckFail++
			} else {
				result.CheckPass++
			}
		}
		response.Ok(w, response.WithItem(result), response.WithCustomField("taskID", taskID))
	}
}

// @Router /api/v1/scap/{checkType}/breakdown [get]
func (a *api) findCheckBreakdown() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultScapTimeout)
		defer cancel()

		clusterKey := chi.URLParam(r, "clusterKey")
		if clusterKey == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("couldn't read ClusterID")))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing")))
			return
		}
		if !checkType.IsValid() {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)")))
			return
		}

		udbcp, _ := param.QueryString(r, "udbcp")
		section, _ := param.QueryString(r, "section")
		policyID, _ := param.QueryString(r, "policyID")
		taskID, _ := param.QueryString(r, "taskID")
		checkStatus, _ := param.QueryString(r, "checkStatus") // compliance=合规 unCompliance=不合规
		svc, _ := scapper.GetService(ctx)
		var (
			err            error
			taskFinishedAt int64
		)

		if taskID == "" {
			taskID, taskFinishedAt, err = svc.GetLatestHistory(ctx, clusterKey, checkType)
			if err != nil {
				if err != gorm.ErrRecordNotFound {
					RespAndLog(w, ctx, err)
					return
				}

				response.Ok(w, response.WithItems([]string{}), response.WithTotalItems(0))
				return
			}
		} else {
			var scanHistory model.ScanHistory
			err = a.rdb.GetReadDB().WithContext(ctx).Select("task_id", "finished_at").
				Where("check_type = ? AND task_id = ? AND state = ?", checkType, taskID, model.ScanStateCompleted).
				First(&scanHistory).Error
			if err != nil {
				logging.Get().Warn().Err(err).Msg("gets scan result fail by taskId")

				response.Ok(w, response.WithItems([]string{}),
					response.WithTotalItems(0),
					response.WithCustomField("taskID", taskID),
					response.WithCustomField("taskFinishedAt", taskFinishedAt))
				return
			}
			taskFinishedAt = scanHistory.FinishedAt
		}

		list, err := svc.FindBreakdownEntries(ctx, taskID, checkType, section, udbcp, policyID, checkStatus)
		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItems(list),
			response.WithTotalItems(int64(len(list))),
			response.WithCustomField("taskID", taskID),
			response.WithCustomField("taskFinishedAt", taskFinishedAt))
	}
}

func (a *api) findBreakdownDetailList() http.HandlerFunc {
	type resp struct {
		Pass  int `json:"pass"`
		Warn  int `json:"warn"`
		Info  int `json:"info"`
		Fail  int `json:"fail"`
		Nodes []*struct {
			ClusterKey string                        `json:"clusterKey"`
			Hostname   string                        `json:"hostname"`
			CreateAt   int64                         `json:"createAt"`
			TestStatus model.ScapScanResultStateType `json:"testStatus"`
			TestResult string                        `json:"testResult"`
		} `json:"nodes"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultScapTimeout)
		defer cancel()

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing")))
			return
		}
		if !checkType.IsValid() {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)")))
			return
		}

		offset, limit := a.getOffsetAndLimit(r)
		policyID, _ := param.QueryString(r, "policyID")
		if policyID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("policyID param missing")))
			return
		}
		taskID, _ := param.QueryString(r, "taskID")
		if taskID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("taskId param missing")))
			return
		}
		keyword, _ := param.QueryString(r, "keyword")

		db := a.rdb.GetReadDB().WithContext(ctx).Model(&model.ScanResult{}).
			Where("check_type = ? AND task_id = ? AND policy_id = ?", checkType, taskID, policyID)
		if keyword != "" {
			db = db.Where("node_name LIKE ?", "%"+keyword+"%")
		}

		result := resp{}
		err := db.Session(&gorm.Session{}).
			Select("COUNT(CASE WHEN state=? THEN 1 END) AS pass,"+
				"COUNT(CASE WHEN state=? THEN 1 END) AS warn,"+
				"COUNT(CASE WHEN state=? THEN 1 END) AS info,"+
				"COUNT(CASE WHEN state=? THEN 1 END) AS fail",
				model.ScapScanResultStatePASS, model.ScapScanResultStateWARN,
				model.ScapScanResultStateINFO, model.ScapScanResultStateFAIL).
			Limit(1).Find(&result).Error
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			RespAndLog(w, ctx, err)
			return
		}

		err = db.Select("node_name AS hostname,create_at,state AS test_status,actual_value AS test_result,cluster_key").
			Offset(offset).Limit(limit).Find(&result.Nodes).Error
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItems(result.Nodes),
			response.WithCustomField("total", result.Pass+result.Warn+result.Info+result.Fail),
			response.WithCustomField("pass", result.Pass),
			response.WithCustomField("info", result.Info),
			response.WithCustomField("warn", result.Warn),
			response.WithCustomField("fail", result.Fail))
	}
}

// findLatestScanRecordWithNode 节点视角列表
func (a *api) findScanRecordWithNode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultScapTimeout)
		defer cancel()

		clusterKey := chi.URLParam(r, "clusterKey")
		if clusterKey == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("couldn't read ClusterID")))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing")))
			return
		}
		if !checkType.IsValid() {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)")))
			return
		}

		offset, limit := a.getOffsetAndLimit(r)
		name, _ := param.QueryString(r, "name")
		status, _ := param.QueryInt(r, "status")              // 1=完成 2=失败
		checkStatus, _ := param.QueryString(r, "checkStatus") // compliance=合规 unCompliance=不合规
		taskID, _ := param.QueryString(r, "taskID")
		var (
			err            error
			taskFinishedAt int64
		)

		if taskID == "" {
			svc, _ := scapper.GetService(ctx)
			taskID, taskFinishedAt, err = svc.GetLatestHistory(ctx, clusterKey, checkType)
			if err != nil {
				if err != gorm.ErrRecordNotFound {
					RespAndLog(w, ctx, err)
					return
				}

				response.Ok(w, response.WithItems([]string{}), response.WithTotalItems(0))
				return
			}
		} else {
			var scanHistory model.ScanHistory
			err = a.rdb.GetReadDB().WithContext(ctx).Select("task_id", "finished_at").
				Where("check_type = ? AND task_id = ? AND state = ?", checkType, taskID, model.ScanStateCompleted).
				First(&scanHistory).Error
			if err != nil {
				RespAndLog(w, ctx, NewNotFoundError(http.StatusBadRequest, err))
				return
			}
			taskFinishedAt = scanHistory.FinishedAt
		}

		db := a.rdb.GetReadDB().WithContext(ctx).Where("task_id = ?", taskID)
		if name != "" {
			db = db.Where("node_name", name)
		}
		if status != 0 {
			db = db.Where("state", status)
		}
		if checkStatus == "compliance" {
			db = db.Where("fail=0")
		} else if checkStatus == "unCompliance" {
			db = db.Where("fail>0")
		}

		var total int64
		if err = db.Session(&gorm.Session{}).Model(&model.ScanNodeRecord{}).
			Count(&total).Error; err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		list := make([]*model.ScanNodeRecord, 0)
		err = db.Offset(offset).Limit(limit).Order("pass_rate ASC").Find(&list).Error
		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		items := make([]*model.ScapScanRecordNodeItem, len(list))
		for i, v := range list {
			items[i] = &model.ScapScanRecordNodeItem{
				TaskID:     v.TaskID,
				CheckType:  v.CheckType,
				ClusterKey: v.ClusterKey,
				NodeName:   v.NodeName,
				State:      v.State,
				FinishedAt: v.FinishedAt,
				Pass:       v.Pass,
				Fail:       v.Fail,
				Warn:       v.Warn,
				Info:       v.Info,
			}
		}

		response.Ok(w, response.WithItems(items),
			response.WithTotalItems(total),
			response.WithCustomField("taskID", taskID),
			response.WithCustomField("taskFinishedAt", taskFinishedAt))
	}
}

// --
func (api *api) getPolicyDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		policyId := chi.URLParam(r, "policyNumber")
		if policyId == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("policyNumber param missing")))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing")))
			return

		}
		if !checkType.IsValid() {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)")))
			return
		}

		policyDetails := &model.PolicyDetails{}
		scapService, _ := scapper.GetService(ctx)
		if err := scapService.GetPolicyDetails(ctx, policyDetails, policyId, checkType); err != nil {
			logging.Get().Error().Err(err).Msg("")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w, response.WithItem(*policyDetails))
	}
}

// @Router /{checkType}/exportfile  {get}
func (api *api) exportFile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		// username
		username := model.GetUsernameFromContext(r.Context())
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
		err := api.rdb.Get().WithContext(ctx).Table(tbname).Take(&task, query, checkID, username).Error
		if err == nil {
			if task.Status == 1 && (time.Now().Unix()-task.CreatedAt > 300) {
				task.Status = 2
			}

			if task.Status == 2 {
				delErr := api.rdb.Get().WithContext(ctx).Table(tbname).Where(query, checkID, username).Delete(&task).Error
				if delErr != nil {
					logging.Get().WithContext(ctx).Errorf(delErr, "delete export tasks error")
				}
			}

			response.Ok(w, response.WithExportFileStatus(task.Status))
			return
		}
		task.Status = 1
		task.UserName = username
		task.CheckType = string(checkType)
		task.CheckId = checkID
		task.CreatedAt = time.Now().Unix()
		task.FileName = fmt.Sprintf("/var/www/%s-%d.xlsx", string(checkType), task.CreatedAt)
		// insert task data to mongo
		err = api.rdb.Get().WithContext(ctx).Create(&task).Error
		if err != nil {
			task.Status = 2
		} else {
			language := lang.Language(ctx)

			// run export file task
			scap, _ := scapper.GetScapper(ctx)
			go scap.RunExportFileTask(language, &task)
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
		username := model.GetUsernameFromContext(r.Context()) // get token

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, errors.Errorf("checkID param missing")))
			return
		}
		var task model.ExportTask
		tbname := task.TableName()
		query := "task_id = ? and username = ?"
		err := api.rdb.Get().WithContext(ctx).Table(tbname).Take(&task, query, checkID, username).Error
		if err != nil {
			logging.Get().Error().Msgf("get export task failed, taskId : %v, username : %v, %v", checkID, username, err)
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, errors.Errorf("get export task failed, %v", err)))
			return
		}
		// task status
		if task.Status == 1 {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, errors.Errorf("Please wait while the file is being exported.")))
			return
		}
		// delete record
		err = api.rdb.Get().WithContext(ctx).Table(tbname).Where(query, checkID, username).Delete(&task).Error
		if err != nil {
			logging.Get().WithContext(ctx).Errorf(err, "delete export tasks error")
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
			logging.Get().Error().Msgf("download file failed, %v", err)
		}
		logging.Get().Info().Msgf("file bytes : %v.", dataLen)
	}
}

func (api *api) addScanResults() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		var scanResults []*model.ScanResult
		err := json.NewDecoder(r.Body).Decode(&scanResults)
		if err != nil {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		defer r.Body.Close()

		svc, ok := scapper.GetService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		err = svc.AddScapScanResults(ctx, scanResults)
		if err != nil {
			logging.Get().Err(err).Msg("add scanning result error")
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
		ctx, cancel := context.WithTimeout(r.Context(), defaultScapTimeout)
		defer cancel()

		record := &scanNodeRecord{}
		err := util.DecodeJSONBody(w, r, record)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		svc, ok := scapper.GetService(ctx)
		if !ok {
			logging.Get().Error().Msg("service instance get error")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("service instance get error")))
			return
		}

		err = svc.UpdateSnrVariate(ctx, record.TaskID, record.NodeName, record.CheckType, record.AutoVariate)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("update ScanNodeRecord err")))
			return
		}

		response.Ok(w)
	}
}

func (api *api) scanCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultScapTimeout)
		defer cancel()

		req := scapper.RecvScanResultReq{}
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		err = scapper.RecvScanResults(ctx, api.rdb.Get(), &req)

		response.Ok(w)
	}
}
