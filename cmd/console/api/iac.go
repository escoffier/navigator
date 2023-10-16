package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"github.com/robfig/cron/v3"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/iac"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	iacModel "gitlab.com/piccolo_su/vegeta/pkg/model/iac"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	goPkgIac "gitlab.com/security-rd/go-pkg/iac"
	goPkgIacConst "gitlab.com/security-rd/go-pkg/iac/consts"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/translate"
)

func (api *api) iac() func(chi.Router) {
	return func(r chi.Router) {
		// yaml
		r.Post("/yaml/scan", api.YamlScan())
		r.Get("/yaml/resources", api.YamlResources())
		r.Get("/yaml/resources/types", api.YamlResourcesType())
		r.Get("/yaml/templates", api.YamlTemplates())
		r.Post("/yaml/templates", api.YamlTemplatesCreate())
		r.Put("/yaml/templates", api.YamlTemplatesUpdate())
		r.Delete("/yaml/templates", api.YamlTemplatesDelete())
		r.Get("/yaml/templates/deleteConfirm", api.YamlTemplatesDeleteConfirm())
		r.Get("/yaml/templates/detail", api.YamlTemplatesDetail())
		r.Get("/yaml/templateSnapshots/detail", api.YamlTemplateSnapshotsDetail())
		r.Get("/yaml/rules", api.YamlRules())
		r.Get("/yaml/configs", api.YamlConfigs())
		r.Put("/yaml/configs", api.YamlConfigsUpdate())
		r.Get("/yaml/tasks", api.YamlTasks())
		r.Get("/yaml/records", api.YamlRecords())
		r.Get("/yaml/records/detail", api.YamlRecordsDetail())

		// dockerfile
		r.Post("/dockerfile/scan", api.DockerfileScan())
		r.Get("/dockerfile/records", api.DockerfileRecords())
		r.Get("/dockerfile/results", api.DockerfileResults())
		r.Get("/dockerfile/results/detail", api.DockerfileResultsDetail())
		r.Get("/dockerfile/templates", api.DockerfileTemplates())
		r.Post("/dockerfile/templates", api.DockerfileTemplatesCreate())
		r.Put("/dockerfile/templates", api.DockerfileTemplatesUpdate())
		r.Delete("/dockerfile/templates", api.DockerfileTemplatesDelete())
		r.Get("/dockerfile/templates/detail", api.DockerfileTemplatesDetail())
		r.Get("/dockerfile/templateSnapshots/detail", api.DockerfileTemplateSnapshotsDetail())
		r.Get("/dockerfile/rules", api.DockerfileRules())
		r.Get("/dockerfile/configs", api.DockerfileConfigs())
		r.Put("/dockerfile/configs", api.DockerfileConfigsUpdate())
	}
}

// yaml

func (api *api) YamlScan() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Request struct {
			TemplateID int                     `json:"template_id"`
			Filter     *map[string]interface{} `json:"filter"`     // 根据条件筛选
			RecordIDs  *[]int                  `json:"record_ids"` // 根据id勾选
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		data, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("err read request body")))
			return
		}

		req := Request{}
		err = json.Unmarshal(data, &req)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("unmarshal req data fails")))
			return
		}

		templateSnapshots, err := iacModel.FindYamlTemplateSnapshots(ctx, api.rdb.GetReadDB(),
			map[string]interface{}{"template_id": req.TemplateID},
			map[string]interface{}{"order": "id desc", "limit": 1},
		)
		if err != nil || len(templateSnapshots) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindYamlTemplateSnapshots err: %v, len: %d", err, len(templateSnapshots))).Msg("FindYamlTemplateSnapshots fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("FindYamlTemplateSnapshots fails")))
			return
		}

		var taskTotal int64
		var f func(offset, limit int) ([]iacModel.Resource, error)
		if req.Filter != nil {
			filterM := *req.Filter

			name, ok := filterM["name"].(string)
			if !ok {
				name = ""
			}
			namespace, ok := filterM["namespace"].(string)
			if !ok {
				namespace = ""
			}
			templateName, ok := filterM["template_name"].(string)
			if !ok {
				templateName = ""
			}
			hackEqualTemplateName := ""
			if lang.Language(r.Context()) == lang.LanguageZH {
				if strings.Contains("默认基线", templateName) {
					hackEqualTemplateName = iac.DefaultTemplateName
				}
			}
			clusterKey, ok := filterM["cluster_key"].(string)
			clusterKeys := strings.Split(clusterKey, ",")
			if !ok {
				clusterKey = ""
				clusterKeys = []string{}
			}

			kind, ok := filterM["kind"].(string)
			kinds := strings.Split(kind, ",")
			if !ok {
				kind = ""
				kinds = []string{}
			}
			status, ok := filterM["status"].(string)
			statuses := strings.Split(status, ",")
			if !ok {
				status = ""
				statuses = []string{}
			}
			startTime, ok := filterM["start_time"].(int64)
			if !ok {
				startTime = 0
			}
			endTime, ok := filterM["end_time"].(int64)
			if !ok {
				endTime = 0
			}

			taskTotal, err = iacModel.CountYamlRecordsByConditions(ctx, api.rdb.GetReadDB(),
				name, namespace, templateName, hackEqualTemplateName, clusterKeys, kinds, statuses, startTime, endTime,
			)

			if err != nil {
				logging.Get().Err(err).
					Str("name", name).
					Str("namespace", namespace).
					Str("template_name", templateName).
					Strs("cluster_keys", clusterKeys).
					Strs("kinds", kinds).
					Strs("statuses", statuses).
					Int64("start_time", startTime).
					Int64("end_time", endTime).
					Msgf("CountYamlRecordsByConditions fails")
				RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
				return
			}

			f = func(offset, limit int) ([]iacModel.Resource, error) {
				timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
				defer cancel()
				records, err := iacModel.FindYamlRecordsByConditions(timeoutCtx, api.rdb.GetReadDB(),
					name, namespace, templateName, hackEqualTemplateName, clusterKeys, kinds, statuses, startTime, endTime,
					map[string]interface{}{"order": "resource_name asc", "offset": offset, "limit": limit},
				)
				if err != nil {
					logging.Get().Err(err).
						Str("name", name).
						Str("namespace", namespace).
						Str("template_name", templateName).
						Strs("cluster_keys", clusterKeys).
						Strs("kinds", kinds).
						Strs("statuses", statuses).
						Int64("start_time", startTime).
						Int64("end_time", endTime).
						Msgf("FindYamlRecordsByConditions fails")
					return []iacModel.Resource{}, err
				}
				res := make([]iacModel.Resource, len(records))
				for i := range records {
					res[i].ClusterKey = records[i].ResourceClusterKey
					res[i].Namespace = records[i].ResourceNamespace
					res[i].Kind = records[i].ResourceKind
					res[i].Name = records[i].ResourceName
				}
				return res, nil
			}
		} else if req.RecordIDs != nil {
			taskTotal = int64(len(*req.RecordIDs))
			f = func(offset, limit int) ([]iacModel.Resource, error) {
				timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
				defer cancel()
				records, err := iacModel.FindYamlRecordsByIDs(timeoutCtx, api.rdb.GetReadDB(), *req.RecordIDs, map[string]interface{}{"order": "resource_name asc", "offset": offset, "limit": limit})
				if err != nil {
					logging.Get().Error().Err(fmt.Errorf("FindYamlRecords err: %v", err)).Msg("FindYamlRecords fails")
					return []iacModel.Resource{}, err
				}
				res := make([]iacModel.Resource, len(records))
				for i := range records {
					res[i].ClusterKey = records[i].ResourceClusterKey
					res[i].Namespace = records[i].ResourceNamespace
					res[i].Kind = records[i].ResourceKind
					res[i].Name = records[i].ResourceName
				}
				return res, nil
			}
		} else {
			logging.Get().Error().Interface("req", req).Msg("invalid req")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("invalid req")))
			return
		}

		task, err := iacModel.CreateYamlTask(ctx, api.rdb.Get(), iacModel.YamlTask{
			ScanType:     iacModel.YamlTaskScanTypeManual,
			ScheduleID:   -1,                        // 手动触发没有schedule
			TemplateID:   templateSnapshots[0].ID,   // 模板快照id
			TemplateName: templateSnapshots[0].Name, // 模板快照name
			Total:        int(taskTotal),
			Status:       iacModel.YamlTaskStatusPreparing,
			Duration:     -1, // 扫描后更新
			Creator:      request.GetAccountFromContext(ctx),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		})
		if err != nil {
			logging.Get().Error().Err(err).Msg("CreateYamlTask fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("CreateYamlTask fails")))
			return
		}

		// 异步创建子任务 和 发送扫描
		go addRecordsAndSendJob(api, taskTotal, task, f)

		response.Ok(w)
		return
	}
}

func addRecordsAndSendJob(api *api, taskTotal int64, task iacModel.YamlTask, f func(offset, limit int) ([]iacModel.Resource, error)) {
	ctx := context.Background()
	recordsToRun := make([]iacModel.RecordToRun, 0)
	offset, limit := 0, 100
	for offset < int(taskTotal) {
		resources, err := f(offset, limit)
		offset += limit
		if err != nil {
			logging.Get().Error().Err(err).Msg("find resources fails")
			return
		}
		for i := range resources {
			clientSet, ok := api.clusterManager.GetClient(resources[i].ClusterKey)
			if !ok {
				err = fmt.Errorf("clientset of cluster: %s not available", resources[i].ClusterKey)
				logging.Get().Error().Err(err).Msg("clusterManager.GetClient fails")
				continue
			}
			yamlData, resourceGeneration, err := iac.GetYamlFromK8s(ctx, clientSet, resources[i])
			if err != nil {
				logging.Get().Error().Err(err).Interface("resource", resources[i]).Msg("getYamlFromK8s fails")
				err = iacModel.UpdateYamlRecord(ctx, api.rdb.Get(), map[string]interface{}{
					"resource_cluster_key": resources[i].ClusterKey,
					"resource_namespace":   resources[i].Namespace,
					"resource_kind":        resources[i].Kind,
					"resource_name":        resources[i].Name,
					"resource_online":      1,
				}, map[string]interface{}{
					"resource_online": 0,
				})
				if err != nil {
					logging.Get().Error().Err(err).Interface("resource", resources[i]).Msg("UpdateYamlRecord fails")
				}
				continue
			}

			// 每个资源创建一个result record，保证先完成
			// ivan_iac_yaml_results
			timeOutCtx, cancel := context.WithTimeout(ctx, time.Second)
			now := time.Now()
			result, err := iacModel.FirstOrCreateResult(timeOutCtx, api.rdb.Get(), iacModel.YamlResult{
				ResourceClusterKey: resources[i].ClusterKey,
				ResourceNamespace:  resources[i].Namespace,
				ResourceKind:       resources[i].Kind,
				ResourceName:       resources[i].Name,
				ResourceGeneration: resourceGeneration,
				Duration:           0,
				Status:             iacModel.YamlResultStatusWaiting,
				Result:             "",
				Yaml:               string(yamlData),
				CreatedAt:          now,
				UpdatedAt:          now,
			})
			if err != nil {
				logging.Get().Error().Err(err).Msg("CreateYamlResult fails")
				cancel()
				continue
			}
			cancel()

			// 查询出历史记录，直接使用result，创建record
			if result.CreatedAt != now && result.Result != "" {
				// ivan_iac_yaml_records
				_, successRate, err := iacModel.FilterYamlResultByTemplate(ctx, api.rdb.Get(), result.Result, task.TemplateID)
				if err != nil {
					logging.Get().Error().Err(err).Msg("FilterYamlResultByTemplate fails")
					continue
				}
				_, err = iacModel.CreateYamlRecordAndNewOnline(ctx, api.rdb.Get(), iacModel.YamlRecord{
					TaskID:             task.ID,
					TemplateID:         task.TemplateID,
					TemplateName:       task.TemplateName,
					ResourceClusterKey: resources[i].ClusterKey,
					ResourceNamespace:  resources[i].Namespace,
					ResourceKind:       resources[i].Kind,
					ResourceName:       resources[i].Name,
					ResourceGeneration: resourceGeneration,
					Status:             iacModel.YamlRecordStatusWaiting,
					SuccessRate:        successRate,
					ResultID:           result.ID,
					CreatedAt:          time.Now(),
					UpdatedAt:          time.Now(),
				})
				if err != nil {
					logging.Get().Error().Err(err).Msg("CreateYamlRecord fails")
					continue
				}
				continue
			} else {
				// ivan_iac_yaml_records
				record, err := iacModel.CreateYamlRecordAndNewOnline(ctx, api.rdb.Get(), iacModel.YamlRecord{
					TaskID:             task.ID,
					TemplateID:         task.TemplateID,
					TemplateName:       task.TemplateName,
					ResourceClusterKey: resources[i].ClusterKey,
					ResourceNamespace:  resources[i].Namespace,
					ResourceKind:       resources[i].Kind,
					ResourceName:       resources[i].Name,
					ResourceGeneration: resourceGeneration,
					Status:             iacModel.YamlRecordStatusWaiting,
					SuccessRate:        -1,
					ResultID:           result.ID,
					CreatedAt:          time.Now(),
					UpdatedAt:          time.Now(),
				})
				if err != nil {
					logging.Get().Error().Err(err).Msg("CreateYamlRecord fails")
					continue
				}
				recordsToRun = append(recordsToRun, iacModel.RecordToRun{Record: record, Result: result, Yaml: yamlData})
			}
		}
	}

	if len(recordsToRun) != 0 {
		err := iacModel.UpdateYamlTask(ctx, api.rdb.Get(), map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusWaiting})
		if err != nil {
			logging.Get().Error().Err(err).Int("task_id", task.ID).Msg("UpdateYamlTask to scanning fails")
			err = iacModel.UpdateYamlTask(ctx, api.rdb.Get(), map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusFailed, "fail_reason": iacModel.YamlTaskFailReasonDBFails})
			return
		}

		for i := range recordsToRun {
			// 每个资源发送一个job
			iac.SendScan(ctx, len(recordsToRun), task, recordsToRun[i].Record, recordsToRun[i].Result, iacModel.Resource{
				ClusterKey: recordsToRun[i].Record.ResourceClusterKey,
				Namespace:  recordsToRun[i].Record.ResourceNamespace,
				Kind:       recordsToRun[i].Record.ResourceKind,
				Name:       recordsToRun[i].Record.ResourceName,
				Generation: recordsToRun[i].Record.ResourceGeneration,
			}, recordsToRun[i].Yaml)
			if i == 0 {
				// 子任务开始执行，修改任务状态 waiting -> scanning
				err = iacModel.UpdateYamlTask(ctx, api.rdb.Get(), map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusScanning})
				if err != nil {
					logging.Get().Error().Err(err).Int("task_id", task.ID).Msg("UpdateYamlTask to scanning fails")
					err = iacModel.UpdateYamlTask(ctx, api.rdb.Get(), map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusFailed, "fail_reason": iacModel.YamlTaskFailReasonDBFails})
					return
				}
			}
		}
	} else {
		err := iacModel.UpdateYamlTask(ctx, api.rdb.Get(), map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusComplete, "success": task.Total})
		if err != nil {
			logging.Get().Error().Err(err).Int("task_id", task.ID).Msg("UpdateYamlTask to scanning fails")
			err = iacModel.UpdateYamlTask(ctx, api.rdb.Get(), map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusFailed, "fail_reason": iacModel.YamlTaskFailReasonDBFails})
			return
		}
		err = iacModel.UpdateYamlRecord(ctx, api.rdb.Get(), map[string]interface{}{"task_id": task.ID}, map[string]interface{}{"status": iacModel.YamlRecordStatusComplete})
		if err != nil {
			return
		}
	}
}

type responseRecord struct {
	ID                 int    `json:"id"`
	TaskID             int    `json:"task_id"`
	TemplateID         int    `json:"template_id"`
	TemplateName       string `json:"template_name"`
	ResourceClusterKey string `json:"resource_cluster_key"`
	ResourceNamespace  string `json:"resource_namespace"`
	ResourceKind       string `json:"resource_kind"`
	ResourceName       string `json:"resource_name"`
	ResourceGeneration int64  `json:"resource_generation"`
	Status             string `json:"status"`
	SuccessRate        string `json:"success_rate"`
	ResultID           int    `json:"result_id"`
	FailReason         string `json:"fail_reason"`
	CreatedAt          int64  `json:"created_at"`
	UpdatedAt          int64  `json:"updated_at"`
}

func (api *api) YamlResources() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		name, err := param.QueryString(r, "name")
		if err != nil {
			name = ""
		}
		namespace, err := param.QueryString(r, "namespace")
		if err != nil {
			namespace = ""
		}
		templateName, err := param.QueryString(r, "template_name")
		if err != nil {
			templateName = ""
		}
		hackEqualTemplateName := ""
		if lang.Language(r.Context()) == lang.LanguageZH {
			if strings.Contains("默认基线", templateName) {
				hackEqualTemplateName = iac.DefaultTemplateName
			}
		}
		clusterKey, err := param.QueryString(r, "cluster_key")
		clusterKeys := strings.Split(clusterKey, ",")
		if err != nil {
			clusterKey = ""
			clusterKeys = []string{}
		}

		kind, err := param.QueryString(r, "kind")
		kinds := strings.Split(kind, ",")
		if err != nil {
			kind = ""
			kinds = []string{}
		}
		status, err := param.QueryString(r, "status")
		statuses := strings.Split(status, ",")
		if err != nil {
			status = ""
			statuses = []string{}
		}
		startTime, err := param.QueryInt64(r, "start_time")
		if err != nil {
			startTime = 0
		}
		endTime, err := param.QueryInt64(r, "end_time")
		if err != nil {
			endTime = 0
		}

		records, err := iacModel.FindYamlRecordsByConditions(ctx, api.rdb.GetReadDB(),
			name, namespace, templateName, hackEqualTemplateName, clusterKeys, kinds, statuses, startTime, endTime,
			map[string]interface{}{"order": "resource_name asc", "offset": offset, "limit": limit},
		)
		if err != nil {
			logging.Get().Err(err).
				Str("name", name).
				Str("namespace", namespace).
				Str("template_name", templateName).
				Strs("cluster_keys", clusterKeys).
				Strs("kinds", kinds).
				Strs("statuses", statuses).
				Int64("start_time", startTime).
				Int64("end_time", endTime).
				Msgf("FindYamlRecordsByConditions fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		res := make([]responseRecord, len(records))
		for i := range records {
			res[i] = responseRecord{
				ID:                 records[i].ID,
				TaskID:             records[i].TaskID,
				TemplateID:         records[i].TemplateID,
				TemplateName:       api.translation.One(translate.DomainIacYaml, translate.KeyTemplateName, records[i].TemplateName, string(lang.Language(r.Context()))),
				ResourceClusterKey: records[i].ResourceClusterKey,
				ResourceNamespace:  records[i].ResourceNamespace,
				ResourceKind:       records[i].ResourceKind,
				ResourceName:       records[i].ResourceName,
				ResourceGeneration: records[i].ResourceGeneration,
				Status:             records[i].Status,
				SuccessRate:        fmt.Sprintf("%.2f", records[i].SuccessRate),
				ResultID:           records[i].ResultID,
				FailReason:         records[i].FailReason,
				CreatedAt:          records[i].CreatedAt.UnixMilli(),
				UpdatedAt:          records[i].UpdatedAt.UnixMilli(),
			}
			// init状态为资源刚刚初始化
			// waiting或scanning状态，且还没有成功率的资源为创建后正在扫描
			if (res[i].Status == iacModel.YamlRecordStatusInitial) ||
				((res[i].Status == iacModel.YamlRecordStatusWaiting || res[i].Status == iacModel.YamlRecordStatusScanning) && records[i].SuccessRate == -1) {
				res[i].Status = iacModel.YamlRecordRateStatusUnknown
				res[i].SuccessRate = "0.0"
			} else {
				res[i].Status = iacModel.SuccessRateToRateStatus(records[i].SuccessRate)
			}
		}
		count, err := iacModel.CountYamlRecordsByConditions(ctx, api.rdb.GetReadDB(),
			name, namespace, templateName, hackEqualTemplateName, clusterKeys, kinds, statuses, startTime, endTime,
		)

		if err != nil {
			logging.Get().Err(err).
				Str("name", name).
				Str("namespace", namespace).
				Str("template_name", templateName).
				Strs("cluster_keys", clusterKeys).
				Strs("kinds", kinds).
				Strs("statuses", statuses).
				Int64("start_time", startTime).
				Int64("end_time", endTime).
				Msgf("CountYamlRecordsByConditions fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		response.Ok(w, response.WithItems(res), response.WithTotalItems(count))
	}
}

func (api *api) YamlResourcesType() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resourceTypes := []string{
			"Deployment",
			"DaemonSet",
			"ReplicaSet",
			"StatefulSet",
			"ReplicationController",
			"Job",
			"CronJob",
			"Pod",
		}
		count := int64(8)
		response.Ok(w, response.WithItems(resourceTypes), response.WithTotalItems(count))
	}
}

func (api *api) YamlTemplates() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		name, err := param.QueryString(r, "name")
		if err != nil {
			name = ""
		}

		hackEqualName := ""
		if lang.Language(r.Context()) == lang.LanguageZH {
			if strings.Contains("默认基线", name) {
				hackEqualName = iac.DefaultTemplateName
			}
		}

		count, templates, err := iacModel.FindYamlTemplatesByName(ctx, api.rdb.GetReadDB(), name, hackEqualName, map[string]interface{}{"order": "builtin desc, created_at desc", "offset": offset, "limit": limit})
		if err != nil {
			logging.Get().Error().Err(err).Str("name", name).Msg("FindYamlTemplatesByName fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		defaultTemplateIndex := -1
		for i := range templates {
			if templates[i].Name == iac.DefaultTemplateName {
				defaultTemplateIndex = i
				templates[i].Name = api.translation.One(translate.DomainIacYaml, translate.KeyTemplateName, templates[i].Name, string(lang.Language(r.Context())))
			}
		}
		nt := make([]iacModel.YamlTemplate, 0)
		if defaultTemplateIndex != -1 {
			nt = append(nt, templates[defaultTemplateIndex])
			for i := range templates {
				if i != defaultTemplateIndex {
					nt = append(nt, templates[i])
				}
			}
		} else {
			nt = templates
		}

		response.Ok(w, response.WithItems(nt), response.WithTotalItems(count))
	}
}

func (api *api) YamlTemplatesCreate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Request struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Rules       []string `json:"rules"`
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		data, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("err read request body")))
			return
		}

		req := Request{}
		err = json.Unmarshal(data, &req)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("unmarshal req data fails")))
			return
		}

		if len(req.Rules) == 0 {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid empty rules")))
			return
		}
		if req.Name == "" || len(req.Name) > 50 {
			RespAndLog(w, ctx, NewFieldInvalidError(http.StatusBadRequest, ErrFieldBenchmarkName, errors.New("invalid request name")))
			return
		}
		if !util.MatchName(req.Name) {
			RespAndLog(w, ctx, NewFieldInvalidError(http.StatusBadRequest, ErrFieldBenchmarkName, errors.New("invalid request name")))
			return
		}
		if len(req.Description) > 100 {
			RespAndLog(w, ctx, NewFieldInvalidError(http.StatusBadRequest, ErrFieldBenchmarkDescription, errors.New("invalid request description")))
			return
		}

		template, err := iacModel.CreateYamlTemplate(ctx, api.rdb.Get(), iacModel.YamlTemplate{
			Name:        req.Name,
			Description: req.Description,
			Rules:       req.Rules,
			Creator:     request.GetAccountFromContext(r.Context()),
			Updater:     request.GetAccountFromContext(r.Context()),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
		if err != nil {
			logging.Get().Err(err).
				Str("name", req.Name).
				Str("description", req.Description).
				Strs("rules", req.Rules).
				Msgf("CreateYamlTemplate fails")
			if strings.Contains(err.Error(), "Error 1062 (23000)") && strings.Contains(err.Error(), ".uni_name") {
				RespAndLog(w, ctx, NewFieldDuplicateError(http.StatusBadRequest, ErrFieldBenchmarkName, errors.New("db operate fails")))
			} else {
				RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			}
			return
		}
		_, err = iacModel.CreateYamlTemplateSnapshot(ctx, api.rdb.Get(), iacModel.YamlTemplateSnapshot{
			TemplateID:  template.ID,
			Name:        req.Name,
			Description: req.Description,
			Rules:       req.Rules,
			Creator:     request.GetAccountFromContext(r.Context()),
			Updater:     request.GetAccountFromContext(r.Context()),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
		if err != nil {
			logging.Get().Err(err).
				Int("id", template.ID).
				Str("name", req.Name).
				Str("description", req.Description).
				Strs("rules", req.Rules).
				Msgf("CreateYamlTemplateSnapshot fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		response.Ok(w, response.WithItem(template))
	}
}

func (api *api) YamlTemplatesUpdate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Request struct {
			ID          int      `json:"id"`
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Rules       []string `json:"rules"`
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		data, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("err read request body")))
			return
		}

		req := Request{}
		err = json.Unmarshal(data, &req)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("unmarshal req data fails")))
			return
		}

		if req.ID == 0 {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid id")))
			return
		}
		if len(req.Rules) == 0 {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid empty rules")))
			return
		}
		if req.Name == "" || len(req.Name) > 50 {
			RespAndLog(w, ctx, NewFieldInvalidError(http.StatusBadRequest, ErrFieldBenchmarkName, errors.New("invalid request name")))
			return
		}
		if !util.MatchName(req.Name) {
			RespAndLog(w, ctx, NewFieldInvalidError(http.StatusBadRequest, ErrFieldBenchmarkName, errors.New("invalid request name")))
			return
		}
		if len(req.Description) > 100 {
			RespAndLog(w, ctx, NewFieldInvalidError(http.StatusBadRequest, ErrFieldBenchmarkDescription, errors.New("invalid request description")))
			return
		}

		templates, err := iacModel.FindYamlTemplates(ctx, api.rdb.Get(), map[string]interface{}{"id": req.ID})
		if err != nil || len(templates) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindYamlTemplates err: %v, len: %d", err, len(templates))).Msg("FindYamlTemplateSnapshots fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		if templates[0].Builtin {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("builtin template cannot be updated")))
			return
		}

		br, err := json.Marshal(req.Rules)
		if err != nil {
			logging.Get().Error().Err(err).Strs("req.Rules", req.Rules).Msg("marshal req.rules fails")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid req.rules")))
			return
		}
		err = iacModel.UpdateYamlTemplate(ctx, api.rdb.Get(), map[string]interface{}{"id": req.ID}, map[string]interface{}{
			"name": req.Name, "description": req.Description, "rules": br, "updater": request.GetAccountFromContext(r.Context()),
		})
		if err != nil {
			logging.Get().Err(err).
				Int("id", req.ID).
				Str("name", req.Name).
				Str("description", req.Description).
				Strs("rules", req.Rules).
				Msgf("UpdateYamlTemplate fails")
			if strings.Contains(err.Error(), "Error 1062 (23000)") && strings.Contains(err.Error(), ".uni_name") {
				RespAndLog(w, ctx, NewFieldDuplicateError(http.StatusBadRequest, ErrFieldBenchmarkName, errors.New("db operate fails")))
			} else {
				RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			}
			return
		}
		_, err = iacModel.CreateYamlTemplateSnapshot(ctx, api.rdb.Get(), iacModel.YamlTemplateSnapshot{
			TemplateID:  req.ID,
			Name:        req.Name,
			Description: req.Description,
			Rules:       req.Rules,
			Creator:     request.GetAccountFromContext(r.Context()),
			Updater:     request.GetAccountFromContext(r.Context()),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
		if err != nil {
			logging.Get().Err(err).
				Int("id", req.ID).
				Str("name", req.Name).
				Str("description", req.Description).
				Strs("rules", req.Rules).
				Msgf("CreateYamlTemplateSnapshot fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		response.Ok(w)
	}
}

func (api *api) YamlTemplatesDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Request struct {
			ID int `json:"id"`
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		data, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("err read request body")))
			return
		}

		req := Request{}
		err = json.Unmarshal(data, &req)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("unmarshal req data fails")))
			return
		}

		templates, err := iacModel.FindYamlTemplates(ctx, api.rdb.Get(), map[string]interface{}{"id": req.ID})
		if err != nil || len(templates) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindYamlTemplates err: %v, len: %d", err, len(templates))).Msg("FindYamlTemplates fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		if templates[0].Builtin {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("builtin template cannot be removed")))
			return
		}

		defaultTemplates, err := iacModel.FindYamlTemplates(ctx, api.rdb.Get(), map[string]interface{}{"name": iac.DefaultTemplateName})
		if err != nil || len(defaultTemplates) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindYamlTemplates err: %v, len: %d", err, len(defaultTemplates))).Msg("FindYamlTemplates fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		schedules, err := iacModel.FindYamlSchedules(ctx, api.rdb.GetReadDB(), map[string]interface{}{})
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("FindYamlSchedules fails")))
			return
		}
		// 检查并更新schedule的基线（db）
		for i := range schedules {
			if schedules[i].TemplateID == req.ID {
				// 更新成默认基线
				err = iacModel.UpdateYamlSchedule(ctx, api.rdb.Get(), map[string]interface{}{"id": schedules[i].ID}, map[string]interface{}{"template_id": defaultTemplates[0].ID})
				if err != nil {
					logging.Get().Error().Err(err).Msg("UpdateYamlSchedule fails")
					RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
					return
				}
			}
		}
		// 检查并更新schedule的基线（内存）
		if iac.BuiltInPeriodSchedule.TemplateID == req.ID {
			iac.BuiltInPeriodSchedule.TemplateID = defaultTemplates[0].ID
		}
		if iac.BuiltInUpdateSchedule.TemplateID == req.ID {
			iac.BuiltInUpdateSchedule.TemplateID = defaultTemplates[0].ID
		}

		err = iacModel.DeleteYamlTemplate(ctx, api.rdb.Get(), map[string]interface{}{"id": req.ID})
		if err != nil {
			logging.Get().Err(err).
				Int("id", req.ID).
				Msgf("DeleteYamlTemplate fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		response.Ok(w)
	}
}

const (
	defaultDeleteConfirm           = "After deletion, the benchmark will be unable to recovered. Are you sure to delete %s ?"
	addUpdateDeleteConfirm         = "After deletion, when adding / modifying a YAML file, the scanning benchmark will revert to the default benchmark. Are you sure to delete %s ?"
	periodDeleteConfirm            = "After deletion, when period scanning, the scanning benchmark will revert to the default benchmark. Are you sure to delete %s ?"
	addUpdateOrPeriodDeleteConfirm = "After deletion, when adding / modifying a YAML file or period scanning, the scanning benchmark will revert to the default benchmark. Are you sure to delete %s ?"
)

func (api *api) YamlTemplatesDeleteConfirm() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		templateID, err := param.QueryInt(r, "id")
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusBadRequest, errors.New("invalid template id")))
			return
		}

		templates, err := iacModel.FindYamlTemplates(ctx, api.rdb.Get(), map[string]interface{}{"id": templateID})
		if err != nil || len(templates) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindYamlTemplates err: %v, len: %d", err, len(templates))).Msg("FindYamlTemplates fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		templateName := templates[0].Name
		if templates[0].Builtin {
			templateName = api.translation.One(translate.DomainIacYaml, translate.KeyTemplateName, templates[0].Name, string(lang.Language(r.Context())))
			return
		}

		schedules, err := iacModel.FindYamlSchedules(ctx, api.rdb.GetReadDB(), map[string]interface{}{})
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("FindYamlSchedules fails")))
			return
		}

		confirmText := defaultDeleteConfirm
		x := 0
		for i := range schedules {
			if schedules[i].TemplateID == templateID && schedules[i].Name == iac.DBPeriodScheduleName {
				x += 1
			}
			if schedules[i].TemplateID == templateID && schedules[i].Name == iac.DBUpdateScheduleName {
				x += 2
			}
		}
		if x == 1 {
			confirmText = periodDeleteConfirm
		} else if x == 2 {
			confirmText = addUpdateDeleteConfirm
		} else if x != 0 {
			confirmText = addUpdateOrPeriodDeleteConfirm
		}

		confirmText = fmt.Sprintf(confirmText, templateName)
		confirmText = api.translation.One(translate.DomainIacYaml, translate.KeyTemplateDeleteConfirm, confirmText, string(lang.Language(r.Context())))

		response.Ok(w, response.WithItem(struct {
			Text string `json:"text"`
		}{Text: confirmText}))
	}
}

func (api *api) YamlTemplatesDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		id, err := param.QueryString(r, "id")
		if err != nil {
			logging.Get().Err(err).Msgf("invalid param id")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid param id")))
			return
		}

		templates, err := iacModel.FindYamlTemplates(ctx, api.rdb.GetReadDB(), map[string]interface{}{"id": id})
		if err != nil || len(templates) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindYamlTemplates err: %v, len: %d", err, len(templates))).Msg("FindYamlTemplates fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		rules, err := iacModel.FindYamlRulesByBuiltinIDs(ctx, api.rdb.GetReadDB(), templates[0].Rules)
		if err != nil {
			logging.Get().Error().Err(err).Msg("FindYamlRulesByBuiltinIDs fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		type ResponseRule struct {
			ID          int    `json:"id"`
			BuiltinID   string `json:"builtin_id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Severity    string `json:"severity"`
		}

		type Response struct {
			iacModel.YamlTemplate
			Rules []ResponseRule `json:"rules"`
		}

		res := Response{}
		res.YamlTemplate = templates[0]
		if res.YamlTemplate.Builtin {
			res.YamlTemplate.Name = api.translation.One(translate.DomainIacYaml, translate.KeyTemplateName, res.YamlTemplate.Name, string(lang.Language(r.Context())))
			res.YamlTemplate.Description = api.translation.One(translate.DomainIacYaml, translate.KeyTemplateDescription, res.YamlTemplate.Description, string(lang.Language(r.Context())))
		}
		for i := range rules {
			res.Rules = append(res.Rules, ResponseRule{
				ID:          rules[i].ID,
				BuiltinID:   rules[i].BuiltinID,
				Name:        api.translation.One(translate.DomainIacYaml, translate.KeyRuleName, rules[i].Name, string(lang.Language(r.Context()))),
				Description: api.translation.One(translate.DomainIacYaml, translate.KeyRuleDescription, rules[i].Description, string(lang.Language(r.Context()))),
				Severity:    rules[i].Severity,
			})
		}
		sort.Slice(res.Rules, func(i, j int) bool {
			return res.Rules[i].BuiltinID < res.Rules[j].BuiltinID
		})
		response.Ok(w, response.WithItem(res))
	}
}

func (api *api) YamlTemplateSnapshotsDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		id, err := param.QueryString(r, "id")
		if err != nil {
			logging.Get().Err(err).Msgf("invalid param id")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid param id")))
			return
		}

		snapshots, err := iacModel.FindYamlTemplateSnapshots(ctx, api.rdb.GetReadDB(), map[string]interface{}{"id": id}, map[string]interface{}{})
		if err != nil || len(snapshots) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindYamlTemplates err: %v, len: %d", err, len(snapshots))).Msg("FindYamlTemplateSnapshots fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		rules, err := iacModel.FindYamlRulesByBuiltinIDs(ctx, api.rdb.GetReadDB(), snapshots[0].Rules)
		if err != nil {
			logging.Get().Error().Err(err).Msg("FindYamlRulesByBuiltinIDs fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		type ResponseRule struct {
			ID          int    `json:"id"`
			BuiltinID   string `json:"builtin_id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Severity    string `json:"severity"`
		}

		type Response struct {
			iacModel.YamlTemplateSnapshot
			Rules []ResponseRule `json:"rules"`
		}

		res := Response{}
		res.YamlTemplateSnapshot = snapshots[0]
		res.YamlTemplateSnapshot.Name = api.translation.One(translate.DomainIacYaml, translate.KeyTemplateName, res.YamlTemplateSnapshot.Name, string(lang.Language(r.Context())))
		res.YamlTemplateSnapshot.Description = api.translation.One(translate.DomainIacYaml, translate.KeyTemplateDescription, res.YamlTemplateSnapshot.Description, string(lang.Language(r.Context())))

		for i := range rules {
			res.Rules = append(res.Rules, ResponseRule{
				ID:          rules[i].ID,
				BuiltinID:   rules[i].BuiltinID,
				Name:        api.translation.One(translate.DomainIacYaml, translate.KeyRuleName, rules[i].Name, string(lang.Language(r.Context()))),
				Description: api.translation.One(translate.DomainIacYaml, translate.KeyRuleDescription, rules[i].Description, string(lang.Language(r.Context()))),
				Severity:    rules[i].Severity,
			})
		}
		sort.Slice(res.Rules, func(i, j int) bool {
			return res.Rules[i].BuiltinID < res.Rules[j].BuiltinID
		})
		response.Ok(w, response.WithItem(res))
	}
}

func (api *api) YamlRules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		name, err := param.QueryString(r, "name")
		if err != nil {
			name = ""
		}
		severities := make([]string, 0)
		severity, err := param.QueryString(r, "severity")
		if err == nil {
			severities = strings.Split(severity, ",")
		}

		count, rules, err := iacModel.FindYamlRulesByConditions(ctx, api.rdb.GetReadDB(), name, severities, map[string]interface{}{"order": "builtin_id asc", "offset": offset, "limit": limit})
		if err != nil {
			logging.Get().Error().Err(err).Str("name", name).Msg("FindYamlRulesByConditions fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		viewRules := make([]iacModel.ViewRule, len(rules))
		for i := range rules {
			viewRules[i].Name = api.translation.One(translate.DomainIacYaml, translate.KeyRuleName, rules[i].Name, string(lang.Language(r.Context())))
			viewRules[i].Description = api.translation.One(translate.DomainIacYaml, translate.KeyRuleDescription, rules[i].Description, string(lang.Language(r.Context())))
			viewRules[i].BuiltinID = rules[i].BuiltinID
			viewRules[i].Severity = rules[i].Severity
		}
		sort.Slice(viewRules, func(i, j int) bool {
			return viewRules[i].BuiltinID < viewRules[j].BuiltinID
		})

		response.Ok(w, response.WithItems(viewRules), response.WithTotalItems(count))
	}
}

func (api *api) YamlConfigs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		schedules, err := iacModel.FindYamlSchedules(ctx, api.rdb.GetReadDB(), map[string]interface{}{})
		if err != nil || len(schedules) != 2 {
			logging.Get().Error().Err(fmt.Errorf("FindYamlSchedules err: %v, len: %d", err, len(schedules))).Msg("FindYamlSchedules fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		resp := iacModel.ViewYamlConfig{}
		for i := range schedules {
			if schedules[i].Name == iac.DBPeriodScheduleName {
				if schedules[i].Status == 1 {
					resp.PeriodToggle = true
				}
				// 每天10点：0 10 * * *
				// 每周一三五10点：0 10 * * 1,3,5
				// 每月10号11号10点：0 10 10,11 * *
				parts := strings.Split(schedules[i].Schedule, " ")

				if parts[2] == "*" && parts[3] == "*" && parts[4] == "*" { // 每天
					hour, err := strconv.Atoi(parts[1])
					if err != nil {
						logging.Get().Error().Err(err).Str("schedule", schedules[i].Schedule).Msg("convert period schedule fails")
						RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("convert period schedule fails")))
						return
					}
					minute, err := strconv.Atoi(parts[0])
					if err != nil {
						logging.Get().Error().Err(err).Str("schedule", schedules[i].Schedule).Msg("convert period schedule fails")
						RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("convert period schedule fails")))
						return
					}
					resp.PeriodSchedule = iacModel.ViewYamlConfigPeriodSchedule{
						Type: "day",
						Time: fmt.Sprintf("%02d:%02d:00", hour, minute),
					}
				} else if parts[2] == "*" && parts[3] == "*" { // 每周
					hour, err := strconv.Atoi(parts[1])
					if err != nil {
						logging.Get().Error().Err(err).Str("schedule", schedules[i].Schedule).Msg("convert period schedule fails")
						RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("convert period schedule fails")))
						return
					}
					minute, err := strconv.Atoi(parts[0])
					if err != nil {
						logging.Get().Error().Err(err).Str("schedule", schedules[i].Schedule).Msg("convert period schedule fails")
						RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("convert period schedule fails")))
						return
					}
					days := strings.Split(parts[4], ",")
					resp.PeriodSchedule = iacModel.ViewYamlConfigPeriodSchedule{
						Type: "week",
						Time: fmt.Sprintf("%02d:%02d:00", hour, minute),
						Days: days,
					}
				} else if parts[3] == "*" && parts[4] == "*" { // 每月
					hour, err := strconv.Atoi(parts[1])
					if err != nil {
						logging.Get().Error().Err(err).Str("schedule", schedules[i].Schedule).Msg("convert period schedule fails")
						RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("convert period schedule fails")))
						return
					}
					minute, err := strconv.Atoi(parts[0])
					if err != nil {
						logging.Get().Error().Err(err).Str("schedule", schedules[i].Schedule).Msg("convert period schedule fails")
						RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("convert period schedule fails")))
						return
					}
					days := strings.Split(parts[2], ",")
					resp.PeriodSchedule = iacModel.ViewYamlConfigPeriodSchedule{
						Type: "month",
						Time: fmt.Sprintf("%02d:%02d:00", hour, minute),
						Days: days,
					}
				} else {
					logging.Get().Error().Str("schedule", schedules[i].Schedule).Msg("invalid config schedule")
					RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("invalid config schedule")))
					return
				}
				templates, err := iacModel.FindYamlTemplates(ctx, api.rdb.GetReadDB(), map[string]interface{}{"id": schedules[i].TemplateID})
				if err != nil || len(templates) != 1 {
					logging.Get().Error().Err(fmt.Errorf("FindYamlTemplates err: %v, len: %d", err, len(templates))).Msg("FindYamlTemplates fails")
					RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
					return
				}
				resp.PeriodTemplate = iacModel.ViewYamlConfigTemplate{
					ID:   templates[0].ID,
					Name: api.translation.One(translate.DomainIacYaml, translate.KeyTemplateName, templates[0].Name, string(lang.Language(r.Context()))),
				}

				config := map[string]interface{}{}
				err = json.Unmarshal(schedules[i].Config, &config)
				if err != nil {
					logging.Get().Error().Err(err).Msg("unmarshal schedule config")
					RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
					return
				}
				allClusters, ok := config["all"].(bool)
				if ok && allClusters {
					resp.PeriodObjects.All = true
				} else {
					iClusterKeys, ok := config["clusters"].([]interface{})
					if !ok {
						resp.PeriodObjects.Clusters = make([]string, 0)
					} else {
						clusterKeys := make([]string, len(iClusterKeys))
						for j := range iClusterKeys {
							clusterKeys[j] = iClusterKeys[j].(string)
						}
						resp.PeriodObjects.Clusters = clusterKeys
					}
				}
			}
			if schedules[i].Name == iac.DBUpdateScheduleName {
				if schedules[i].Status == 1 {
					resp.UpdateToggle = true
				}
				templates, err := iacModel.FindYamlTemplates(ctx, api.rdb.GetReadDB(), map[string]interface{}{"id": schedules[i].TemplateID})
				if err != nil || len(templates) != 1 {
					logging.Get().Error().Err(fmt.Errorf("FindYamlTemplates err: %v, len: %d", err, len(schedules))).Msg("FindYamlTemplates fails")
					RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
					return
				}
				resp.UpdateTemplate = iacModel.ViewYamlConfigTemplate{
					ID:   templates[0].ID,
					Name: api.translation.One(translate.DomainIacYaml, translate.KeyTemplateName, templates[0].Name, string(lang.Language(r.Context()))),
				}
			}
		}
		response.Ok(w, response.WithItem(resp))
	}
}

func (api *api) YamlConfigsUpdate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Request iacModel.ViewYamlConfig

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		data, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("err read request body")))
			return
		}

		req := Request{}
		err = json.Unmarshal(data, &req)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("unmarshal req data fails")))
			return
		}

		filter := map[string]interface{}{}
		updates := map[string]interface{}{}
		filter["name"] = iac.DBPeriodScheduleName
		status := 0
		if req.PeriodToggle {
			status = 1
		} else {
			status = 0
		}
		updates["status"] = status
		iac.BuiltInPeriodSchedule.Status = status

		if req.PeriodTemplate.ID != 0 {
			updates["template_id"] = req.PeriodTemplate.ID
			iac.BuiltInPeriodSchedule.TemplateID = req.PeriodTemplate.ID
		}
		// 每天10点：0 10 * * *
		// 每周一三五10点：0 10 * * 1,3,5
		// 每月10号11号10点：0 10 10,11 * *
		timeParts := strings.Split(req.PeriodSchedule.Time, ":")
		if len(timeParts) != 3 {
			RespAndLog(w, ctx,
				NewAnError(http.StatusBadRequest, errors.New("invalid req.PeriodSchedule.Time")))
			return
		}
		timeParts = timeParts[:2]
		schedule := ""
		if req.PeriodSchedule.Type == "day" && len(timeParts) == 2 {
			schedule = fmt.Sprintf("%s %s * * *", timeParts[1], timeParts[0])
		}
		if req.PeriodSchedule.Type == "week" && len(req.PeriodSchedule.Days) != 0 && len(timeParts) == 2 {
			schedule = fmt.Sprintf("%s %s * * %s", timeParts[1], timeParts[0], strings.Join(req.PeriodSchedule.Days, ","))
		}
		if req.PeriodSchedule.Type == "month" && len(req.PeriodSchedule.Days) != 0 && len(timeParts) == 2 {
			schedule = fmt.Sprintf("%s %s %s * *", timeParts[1], timeParts[0], strings.Join(req.PeriodSchedule.Days, ","))
		}
		updates["schedule"] = schedule
		iac.BuiltInPeriodSchedule.Schedule = schedule
		scheduleCron, _ := cron.ParseStandard(iac.BuiltInPeriodSchedule.Schedule)
		// fixme: schedule是前端通过字符串设置过来的，隐含的带了时区
		nextTime := scheduleCron.Next(time.Now().Add(time.Hour * 8)).Add(time.Hour * -8)
		updates["next_time"] = nextTime
		iac.BuiltInPeriodSchedule.NextTime = nextTime
		if !req.PeriodObjects.All && len(req.PeriodObjects.Clusters) == 0 {
			err = errors.New("req PeriodObjects invalid")
			logging.Get().Error().Err(err).Msg("req PeriodObjects invalid")
			RespAndLog(w, ctx, NewFieldInvalidError(http.StatusBadRequest, ErrFieldPeriodObjects, err))
			return
		}
		bpo, err := json.Marshal(req.PeriodObjects)
		if err != nil {
			logging.Get().Error().Err(err).Msg("marshal req PeriodObjects fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("marshal req PeriodObjects fails")))
			return
		}
		updates["config"] = string(bpo)
		iac.BuiltInPeriodSchedule.Config = bpo

		err = iacModel.UpdateYamlSchedule(ctx, api.rdb.Get(), filter, updates)
		if err != nil {
			logging.Get().Error().Err(err).Msg("UpdateYamlSchedule fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("UpdateYamlSchedule period fails")))
			return
		}

		filter = map[string]interface{}{}
		updates = map[string]interface{}{}
		filter["name"] = iac.DBUpdateScheduleName
		status = 0
		if req.UpdateToggle {
			status = 1
		} else {
			status = 0
		}
		updates["status"] = status
		iac.BuiltInUpdateSchedule.Status = status

		if req.UpdateTemplate.ID != 0 {
			updates["template_id"] = req.UpdateTemplate.ID
			iac.BuiltInUpdateSchedule.TemplateID = req.UpdateTemplate.ID
		}
		err = iacModel.UpdateYamlSchedule(ctx, api.rdb.Get(), filter, updates)
		if err != nil {
			logging.Get().Error().Err(err).Msg("UpdateYamlSchedule fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("UpdateYamlSchedule update fails")))
			return
		}

		response.Ok(w)
	}
}

func (api *api) YamlTasks() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}

		scanTypes := make([]string, 0)
		scanType, err := param.QueryString(r, "scan_type")
		if err == nil {
			scanTypes = strings.Split(scanType, ",")
		}
		statuses := make([]string, 0)
		status, err := param.QueryString(r, "status")
		if err == nil {
			statuses = strings.Split(status, ",")
		}

		count, tasks, err := iacModel.FindYamlTasksByScanTypeStatus(ctx, api.rdb.GetReadDB(), scanTypes, statuses, map[string]interface{}{"order": "created_at desc", "offset": offset, "limit": limit})
		if err != nil {
			logging.Get().Err(err).Msgf("FindYamlTasks fails")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("FindYamlTasks fails")))
			return
		}

		viewTasks := make([]iacModel.ViewTask, len(tasks))
		for i := range tasks {
			viewTasks[i].TemplateName = api.translation.One(translate.DomainIacYaml, translate.KeyTemplateName, tasks[i].TemplateName, string(lang.Language(r.Context())))
			viewTasks[i].CreatedAt = tasks[i].CreatedAt.UnixMilli()
			viewTasks[i].UpdatedAt = tasks[i].UpdatedAt.UnixMilli()
			viewTasks[i].ID = tasks[i].ID
			viewTasks[i].ScanType = tasks[i].ScanType
			viewTasks[i].ScheduleID = tasks[i].ScheduleID
			viewTasks[i].TemplateID = tasks[i].TemplateID
			viewTasks[i].Total = tasks[i].Total
			viewTasks[i].Success = tasks[i].Success
			viewTasks[i].Status = tasks[i].Status
			viewTasks[i].Duration = tasks[i].Duration
			viewTasks[i].Creator = tasks[i].Creator
		}

		response.Ok(w, response.WithItems(viewTasks), response.WithTotalItems(count))
	}
}

func (api *api) YamlRecords() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		taskID, err := param.QueryInt(r, "task_id")
		if err != nil || taskID == 0 {
			logging.Get().Err(err).Msgf("get task_id query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no task_id given in params")))
			return
		}
		statuses := make([]string, 0)
		status, err := param.QueryString(r, "status")
		if err == nil {
			statuses = strings.Split(status, ",")
		}

		count, records, err := iacModel.FindYamlRecordsByStatus(ctx, api.rdb.GetReadDB(), taskID, statuses, map[string]interface{}{"order": "resource_name asc", "offset": offset, "limit": limit})
		if err != nil {
			logging.Get().Err(err).Msgf("FindYamlRecords fails")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("FindYamlRecords fails")))
			return
		}

		response.Ok(w, response.WithItems(records), response.WithTotalItems(count))
	}
}

func (api *api) YamlRecordsDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		records := make([]iacModel.YamlRecord, 0)
		id, err := param.QueryInt(r, "id")
		if err == nil && id != 0 {
			records, err = iacModel.FindYamlRecords(ctx, api.rdb.GetReadDB(), map[string]interface{}{"id": id}, map[string]interface{}{"limit": 1})
			if err != nil || len(records) != 1 {
				logging.Get().Error().Err(fmt.Errorf("FindYamlRecords err: %v, len: %d", err, len(records))).Msg("FindYamlRecords fails")
				RespAndLog(w, ctx,
					NewAnError(http.StatusInternalServerError, errors.New("FindYamlRecords fails")))
				return
			}
		} else {
			resourceClusterKey, err := param.QueryString(r, "resource_cluster_key")
			if err != nil || len(resourceClusterKey) == 0 {
				logging.Get().Error().Err(fmt.Errorf("err: %v, resource_cluster_key: %d", err, resourceClusterKey)).Msg("invalid param resource_cluster_key")
				RespAndLog(w, ctx,
					NewAnError(http.StatusBadRequest, errors.New("invalid param resource_cluster_key")))
				return
			}
			resourceNamespace, err := param.QueryString(r, "resource_namespace")
			if err != nil || len(resourceNamespace) == 0 {
				logging.Get().Error().Err(fmt.Errorf("err: %v, resource_namespace: %d", err, resourceNamespace)).Msg("invalid param resource_namespace")
				RespAndLog(w, ctx,
					NewAnError(http.StatusBadRequest, errors.New("invalid param resource_namespace")))
				return
			}
			resourceKind, err := param.QueryString(r, "resource_kind")
			if err != nil || len(resourceKind) == 0 {
				logging.Get().Error().Err(fmt.Errorf("err: %v, resource_kind: %d", err, resourceKind)).Msg("invalid param resource_kind")
				RespAndLog(w, ctx,
					NewAnError(http.StatusBadRequest, errors.New("invalid param resource_kind")))
				return
			}
			resourceName, err := param.QueryString(r, "resource_name")
			if err != nil || len(resourceName) == 0 {
				logging.Get().Error().Err(fmt.Errorf("err: %v, resource_name: %d", err, resourceName)).Msg("invalid param resource_name")
				RespAndLog(w, ctx,
					NewAnError(http.StatusBadRequest, errors.New("invalid param resource_name")))
				return
			}

			records, err = iacModel.FindYamlRecords(ctx, api.rdb.GetReadDB(), map[string]interface{}{"resource_cluster_key": resourceClusterKey, "resource_namespace": resourceNamespace, "resource_kind": resourceKind, "resource_name": resourceName}, map[string]interface{}{"order": "created_at desc", "limit": 1})
			if err != nil || len(records) != 1 {
				logging.Get().Error().Err(fmt.Errorf("FindYamlRecords err: %v, len: %d", err, len(records))).Msg("FindYamlRecords fails")
				RespAndLog(w, ctx,
					NewAnError(http.StatusInternalServerError, errors.New("FindYamlRecords fails")))
				return
			}
		}

		results, err := iacModel.FindYamlResults(ctx, api.rdb.GetReadDB(), map[string]interface{}{"id": records[0].ResultID}, map[string]interface{}{"limit": 1})
		if err != nil || len(results) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindYamlResults err: %v, len: %d", err, len(results))).Msg("FindYamlResults fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("FindYamlResults fails")))
			return
		}

		type Response struct {
			RecordID             int                           `json:"record_id"`
			ResourceClusterKey   string                        `json:"resource_cluster_key"`
			ResourceNamespace    string                        `json:"resource_namespace"`
			ResourceKind         string                        `json:"resource_kind"`
			ResourceName         string                        `json:"resource_name"`
			TemplateSnapshotID   int                           `json:"template_snapshot_id"`
			TemplateSnapshotName string                        `json:"template_snapshot_name"`
			RateStatus           string                        `json:"rate_status"`
			CreatedAt            int64                         `json:"created_at"`
			Yaml                 string                        `json:"yaml"`
			Result               []iacModel.ViewYamlScanResult `json:"result"`
			ResultCount          map[string]int                `json:"result_count"`
		}

		respResult := make([]iacModel.ViewYamlScanResult, 0)
		resultCount := make(map[string]int)
		rateStatus := iacModel.YamlRecordRateStatusUnknown

		// records[0].TemplateID == 0 该资源尚未扫描，初始化
		// records[0].TemplateID != 0 有实际扫描结果
		if records[0].TemplateID != 0 {
			rateStatus = iacModel.SuccessRateToRateStatus(records[0].SuccessRate)
			filterResult, _, err := iacModel.FilterYamlResultByTemplate(ctx, api.rdb.GetReadDB(), results[0].Result, records[0].TemplateID)
			if err != nil {
				logging.Get().Err(err).Msgf("FilterYamlResultByTemplate fails")
				RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("FilterYamlResultByTemplate fails")))
				return
			}
			respResult = make([]iacModel.ViewYamlScanResult, 0)
			err = json.Unmarshal([]byte(filterResult), &respResult)
			if err != nil {
				logging.Get().Err(err).Msgf("unmarshal result fails")
				RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("unmarshal result fails")))
				return
			}

			rules, err := iacModel.FindYamlRules(ctx, api.rdb.GetReadDB(), map[string]interface{}{}, map[string]interface{}{})
			if err != nil {
				logging.Get().Err(err).Msgf("unmarshal result fails")
				RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("FindYamlRules fails")))
				return
			}
			rulesMap := make(map[string]string)
			for i := range rules {
				rulesMap[rules[i].ThirdPartyID] = rules[i].Name
			}

			sort.Slice(respResult, func(i, j int) bool {
				return respResult[i].Location.StartLine < respResult[j].Location.StartLine
			})

			resultCount = make(map[string]int)
			for i := range respResult {
				respResult[i].SeqNo = i + 1
				respResult[i].RuleName = api.translation.One(translate.DomainIacYaml, translate.KeyRuleName, rulesMap[respResult[i].RuleID], string(lang.Language(r.Context())))
				respResult[i].RuleDescription = api.translation.One(translate.DomainIacYaml, translate.KeyRuleDescription, respResult[i].RuleDescription, string(lang.Language(r.Context())))
				respResult[i].Description = api.translation.One(translate.DomainIacYaml, translate.KeyRuleMessage, respResult[i].Description, string(lang.Language(r.Context())))
				respResult[i].Resolution = api.translation.One(translate.DomainIacYaml, translate.KeyRuleResolution, respResult[i].Resolution, string(lang.Language(r.Context())))
				count, _ := resultCount[respResult[i].Severity]
				resultCount[respResult[i].Severity] = count + 1
				// Yaml文件整体的问题，hack成全文高亮
				if respResult[i].Location.StartLine == 0 && respResult[i].Location.EndLine == 0 {
					respResult[i].Location.StartLine = 1
					respResult[i].Location.EndLine = 9999
				}
			}
		}

		resp := Response{
			RecordID:             records[0].ID,
			ResourceClusterKey:   records[0].ResourceClusterKey,
			ResourceNamespace:    records[0].ResourceNamespace,
			ResourceKind:         records[0].ResourceKind,
			ResourceName:         records[0].ResourceName,
			TemplateSnapshotID:   records[0].TemplateID,
			TemplateSnapshotName: api.translation.One(translate.DomainIacYaml, translate.KeyTemplateName, records[0].TemplateName, string(lang.Language(r.Context()))),
			RateStatus:           rateStatus,
			CreatedAt:            records[0].CreatedAt.UnixMilli(),
			Yaml:                 results[0].Yaml,
			Result:               respResult,
			ResultCount:          resultCount,
		}

		response.Ok(w, response.WithItem(resp))
	}
}

// dockerfile

func (api *api) DockerfileScan() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		type request struct {
			TemplateID int    `json:"template_id"`
			Dockerfile string `json:"dockerfile"`
		}

		data, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("err read request body")))
			return
		}

		req := request{}
		err = json.Unmarshal(data, &req)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("unmarshal req data fails")))
			return
		}

		if len(req.Dockerfile) == 0 {
			RespAndLog(w, ctx,
				NewAnError(http.StatusBadRequest, errors.New("invalid dockerfile content")))
			return
		}

		dockerfileData := strings.ReplaceAll(req.Dockerfile, "\\n", "\n")
		parseErr, result, err := goPkgIac.RunWithData([]byte(dockerfileData), goPkgIacConst.ScanTypeDockerFile, time.Second*10)
		if err != nil {
			logging.Get().Error().Err(err).Str("dockerfile", req.Dockerfile).Msg("RunWithData fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("RunWithData fails")))
			return
		}

		type resp struct {
			Result      []iacModel.ViewDockerfileScanResult `json:"result"`
			ParseError  string                              `json:"parse_error"`
			ResultCount map[string]int                      `json:"result_count"`
		}

		bf, err := json.Marshal(result.GetFailed().Flatten())
		if err != nil {
			logging.Get().Error().Err(err).Str("dockerfile", req.Dockerfile).Msg("marshal flatten fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("marshal flatten fails")))
			return
		}
		snapshots, err := iacModel.FindDockerfileTemplateSnapshots(ctx, api.rdb.GetReadDB(), map[string]interface{}{"template_id": req.TemplateID}, map[string]interface{}{})
		if err != nil || len(snapshots) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileTemplateSnapshots err: %v, len: %d", err, len(snapshots))).Msg("FindDockerfileTemplateSnapshots fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		filterResult, _, err := iacModel.FilterDockerfileResultByTemplate(ctx, api.rdb.GetReadDB(), string(bf), snapshots[0].ID)
		if err != nil {
			logging.Get().Err(err).Msgf("FilterDockerfileResultByTemplate fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("FilterDockerfileResultByTemplate fails")))
			return
		}
		respResult := make([]iacModel.ViewDockerfileScanResult, 0)
		err = json.Unmarshal([]byte(filterResult), &respResult)
		if err != nil {
			logging.Get().Err(err).Msgf("unmarshal result fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("unmarshal result fails")))
			return
		}

		rules, err := iacModel.FindDockerfileRules(ctx, api.rdb.GetReadDB(), map[string]interface{}{}, map[string]interface{}{})
		if err != nil {
			logging.Get().Err(err).Msgf("unmarshal result fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("FindDockerfileRules fails")))
			return
		}
		rulesMap := make(map[string]string)
		for i := range rules {
			rulesMap[rules[i].ThirdPartyID] = rules[i].Name
		}

		sort.Slice(respResult, func(i, j int) bool {
			return respResult[i].Location.StartLine < respResult[j].Location.StartLine
		})

		resultCount := make(map[string]int)
		for i := range respResult {
			respResult[i].SeqNo = i + 1
			respResult[i].RuleName = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleName, rulesMap[respResult[i].RuleID], string(lang.Language(r.Context())))
			respResult[i].RuleDescription = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleDescription, respResult[i].RuleDescription, string(lang.Language(r.Context())))
			respResult[i].Description = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleMessage, respResult[i].Description, string(lang.Language(r.Context())))
			respResult[i].Resolution = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleResolution, respResult[i].Resolution, string(lang.Language(r.Context())))
			count, _ := resultCount[respResult[i].Severity]
			resultCount[respResult[i].Severity] = count + 1
			// Dockerfile文件整体的问题，hack成全文高亮
			if respResult[i].Location.StartLine == 0 && respResult[i].Location.EndLine == 0 {
				respResult[i].Location.StartLine = 1
				respResult[i].Location.EndLine = 9999
			}
		}

		res := resp{
			Result:      respResult,
			ParseError:  string(parseErr),
			ResultCount: resultCount,
		}

		response.Ok(w, response.WithItem(res))
	}
}

func (api *api) DockerfileRecords() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		dockerfilePath, err := param.QueryString(r, "dockerfile_path")
		if err != nil {
			dockerfilePath = ""
		}
		pipelineName, err := param.QueryString(r, "pipeline_name")
		if err != nil {
			pipelineName = ""
		}
		templateName, err := param.QueryString(r, "template_name")
		if err != nil {
			templateName = ""
		}
		status, err := param.QueryString(r, "status")
		statuses := strings.Split(status, ",")
		if err != nil {
			status = ""
			statuses = []string{}
		}
		startTime, err := param.QueryInt64(r, "start_time")
		if err != nil {
			startTime = 0
		}
		endTime, err := param.QueryInt64(r, "end_time")
		if err != nil {
			endTime = 0
		}

		count, records, err := iacModel.FindDockerfileRecordsByConditions(ctx, api.rdb.GetReadDB(),
			dockerfilePath, pipelineName, templateName, statuses, startTime, endTime,
			map[string]interface{}{"order": "created_at desc", "offset": offset, "limit": limit},
		)
		if err != nil {
			logging.Get().Err(err).
				Str("dockerfile_path", dockerfilePath).
				Str("pipeline_name", pipelineName).
				Str("template_name", templateName).
				Strs("statuses", statuses).
				Int64("start_time", startTime).
				Int64("end_time", endTime).
				Msgf("FindDockerfileRecordsByConditions fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		response.Ok(w, response.WithItems(records), response.WithTotalItems(count))
	}
}

func (api *api) DockerfileResults() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		recordID, err := param.QueryInt(r, "record_id")
		if err != nil {
			logging.Get().Err(err).Msgf("get record_id query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no record_id given in params")))
			return
		}

		count, results, err := iacModel.FindDockerfileResults(ctx, api.rdb.GetReadDB(),
			map[string]interface{}{"record_id": recordID},
			map[string]interface{}{"order": "created_at desc", "offset": offset, "limit": limit},
		)
		if err != nil {
			logging.Get().Err(err).
				Int("record_id", recordID).
				Msgf("FindDockerfileResults fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		response.Ok(w, response.WithItems(results), response.WithTotalItems(count))
	}
}

func (api *api) DockerfileResultsDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		id, err := param.QueryInt(r, "id")
		if err != nil {
			logging.Get().Err(err).Msgf("get id query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no id given in params")))
			return
		}

		_, results, err := iacModel.FindDockerfileResults(ctx, api.rdb.GetReadDB(),
			map[string]interface{}{"id": id},
			map[string]interface{}{},
		)
		if err != nil || len(results) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileResults err: %v, len: %d", err, len(results))).Msg("FindDockerfileResults fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("FindDockerfileResults fails")))
			return
		}

		_, records, err := iacModel.FindDockerfileRecords(ctx, api.rdb.GetReadDB(), map[string]interface{}{"id": results[0].RecordID}, map[string]interface{}{})
		if err != nil || len(records) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileRecords err: %v, len: %d", err, len(records))).Msg("FindDockerfileRecords fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("FindDockerfileRecords fails")))
			return
		}

		type resp struct {
			ResultID             int                                 `json:"result_id"`
			DockerfilePath       string                              `json:"dockerfile_path"`
			PipelineName         string                              `json:"pipeline_name"`
			HitWhitelist         bool                                `json:"hit_whitelist"`
			Status               string                              `json:"status"`
			TemplateSnapshotID   int                                 `json:"template_snapshot_id"`
			TemplateSnapshotName string                              `json:"template_snapshot_name"`
			CreatedAt            int64                               `json:"created_at"`
			Dockerfile           string                              `json:"dockerfile"`
			Result               []iacModel.ViewDockerfileScanResult `json:"result"`
			ParseError           string                              `json:"parse_error"`
			ResultCount          map[string]int                      `json:"result_count"`
		}

		filterResult, _, err := iacModel.FilterDockerfileResultByTemplate(ctx, api.rdb.GetReadDB(), results[0].Result, records[0].TemplateID)
		if err != nil {
			logging.Get().Err(err).Msgf("FilterDockerfileResultByTemplate fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("FilterDockerfileResultByTemplate fails")))
			return
		}
		respResult := make([]iacModel.ViewDockerfileScanResult, 0)
		err = json.Unmarshal([]byte(filterResult), &respResult)
		if err != nil {
			logging.Get().Err(err).Msgf("unmarshal result fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("unmarshal result fails")))
			return
		}

		rules, err := iacModel.FindDockerfileRules(ctx, api.rdb.GetReadDB(), map[string]interface{}{}, map[string]interface{}{})
		if err != nil {
			logging.Get().Err(err).Msgf("unmarshal result fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("FindDockerfileRules fails")))
			return
		}
		rulesMap := make(map[string]string)
		for i := range rules {
			rulesMap[rules[i].ThirdPartyID] = rules[i].Name
		}

		sort.Slice(respResult, func(i, j int) bool {
			return respResult[i].Location.StartLine < respResult[j].Location.StartLine
		})

		resultCount := make(map[string]int)
		for i := range respResult {
			respResult[i].SeqNo = i + 1
			respResult[i].RuleName = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleName, rulesMap[respResult[i].RuleID], string(lang.Language(r.Context())))
			respResult[i].RuleDescription = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleDescription, respResult[i].RuleDescription, string(lang.Language(r.Context())))
			respResult[i].Description = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleMessage, respResult[i].Description, string(lang.Language(r.Context())))
			respResult[i].Resolution = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleResolution, respResult[i].Resolution, string(lang.Language(r.Context())))
			count, _ := resultCount[respResult[i].Severity]
			resultCount[respResult[i].Severity] = count + 1
			// Dockerfile文件整体的问题，hack成全文高亮
			if respResult[i].Location.StartLine == 0 && respResult[i].Location.EndLine == 0 {
				respResult[i].Location.StartLine = 1
				respResult[i].Location.EndLine = 9999
			}
		}

		res := resp{
			ResultID:             results[0].ID,
			DockerfilePath:       results[0].DockerfilePath,
			PipelineName:         records[0].PipelineName,
			HitWhitelist:         results[0].HitWhitelist,
			Status:               results[0].Status,
			TemplateSnapshotID:   records[0].TemplateID,
			TemplateSnapshotName: records[0].TemplateName,
			CreatedAt:            results[0].CreatedAt.UnixMilli(),
			Dockerfile:           results[0].Dockerfile,
			Result:               respResult,
			ParseError:           results[0].ParseError,
			ResultCount:          resultCount,
		}

		response.Ok(w, response.WithItem(res))
	}
}

func (api *api) DockerfileTemplates() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		name, err := param.QueryString(r, "name")
		if err != nil {
			name = ""
		}

		hackEqualName := ""
		if lang.Language(r.Context()) == lang.LanguageZH {
			if strings.Contains("默认基线", name) {
				hackEqualName = iac.DefaultTemplateName
			}
		}

		count, templates, err := iacModel.FindDockerfileTemplatesByName(ctx, api.rdb.GetReadDB(), name, hackEqualName, map[string]interface{}{"order": "builtin desc, created_at desc", "offset": offset, "limit": limit})
		if err != nil {
			logging.Get().Error().Err(err).Str("name", name).Msg("FindDockerfileTemplatesByName fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		defaultTemplateIndex := -1
		for i := range templates {
			if templates[i].Name == iac.DefaultTemplateName {
				defaultTemplateIndex = i
			}
		}
		nt := make([]iacModel.DockerfileTemplate, 0)
		if defaultTemplateIndex != -1 {
			nt = append(nt, templates[defaultTemplateIndex])
			for i := range templates {
				if i != defaultTemplateIndex {
					nt = append(nt, templates[i])
				}
			}
		} else {
			nt = templates
		}

		response.Ok(w, response.WithItems(nt), response.WithTotalItems(count))
	}
}

func (api *api) DockerfileTemplatesCreate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Request struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Rules       []string `json:"rules"`
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		data, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("err read request body")))
			return
		}

		req := Request{}
		err = json.Unmarshal(data, &req)
		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("unmarshal req data fails")))
			return
		}

		if len(req.Rules) == 0 {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid empty rules")))
			return
		}
		if req.Name == "" || len(req.Name) > 50 {
			RespAndLog(w, ctx, NewFieldInvalidError(http.StatusBadRequest, ErrFieldBenchmarkName, errors.New("invalid request name")))
			return
		}
		if !util.MatchEnName(req.Name) {
			RespAndLog(w, ctx, NewFieldInvalidError(http.StatusBadRequest, ErrFieldBenchmarkName, errors.New("invalid request name")))
			return
		}
		if len(req.Description) > 100 {
			RespAndLog(w, ctx, NewFieldInvalidError(http.StatusBadRequest, ErrFieldBenchmarkDescription, errors.New("invalid request description")))
			return
		}

		template, err := iacModel.CreateDockerfileTemplate(ctx, api.rdb.Get(), iacModel.DockerfileTemplate{
			Name:        req.Name,
			Description: req.Description,
			Rules:       req.Rules,
			Creator:     request.GetAccountFromContext(r.Context()),
			Updater:     request.GetAccountFromContext(r.Context()),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})

		if err != nil {
			logging.Get().Err(err).
				Str("name", req.Name).
				Str("description", req.Description).
				Strs("rules", req.Rules).
				Msgf("CreateDockerfileTemplate fails")
			if strings.Contains(err.Error(), "Error 1062 (23000)") && strings.Contains(err.Error(), ".uni_name") {
				RespAndLog(w, ctx, NewFieldDuplicateError(http.StatusBadRequest, ErrFieldBenchmarkName, errors.New("db operate fails")))
			} else {
				RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			}
			return
		}
		_, err = iacModel.CreateDockerfileTemplateSnapshot(ctx, api.rdb.Get(), iacModel.DockerfileTemplateSnapshot{
			TemplateID:  template.ID,
			Name:        req.Name,
			Description: req.Description,
			Rules:       req.Rules,
			Creator:     request.GetAccountFromContext(r.Context()),
			Updater:     request.GetAccountFromContext(r.Context()),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
		if err != nil {
			logging.Get().Err(err).
				Int("id", template.ID).
				Str("name", req.Name).
				Str("description", req.Description).
				Strs("rules", req.Rules).
				Msgf("CreateDockerfileTemplateSnapshot fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		response.Ok(w, response.WithItem(template))
	}
}

func (api *api) DockerfileTemplatesUpdate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Request struct {
			ID          int      `json:"id"`
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Rules       []string `json:"rules"`
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		data, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("err read request body")))
			return
		}

		req := Request{}
		err = json.Unmarshal(data, &req)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("unmarshal req data fails")))
			return
		}

		if req.ID == 0 {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid id")))
			return
		}
		if len(req.Rules) == 0 {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid empty rules")))
			return
		}
		if req.Name == "" || len(req.Name) > 50 {
			RespAndLog(w, ctx, NewFieldInvalidError(http.StatusBadRequest, ErrFieldBenchmarkName, errors.New("invalid request name")))
			return
		}
		if !util.MatchEnName(req.Name) {
			RespAndLog(w, ctx, NewFieldInvalidError(http.StatusBadRequest, ErrFieldBenchmarkName, errors.New("invalid request name")))
			return
		}
		if len(req.Description) > 100 {
			RespAndLog(w, ctx, NewFieldInvalidError(http.StatusBadRequest, ErrFieldBenchmarkDescription, errors.New("invalid request description")))
			return
		}

		templates, err := iacModel.FindDockerfileTemplates(ctx, api.rdb.Get(), map[string]interface{}{"id": req.ID})
		if err != nil || len(templates) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileTemplates err: %v, len: %d", err, len(templates))).Msg("FindDockerfileTemplates fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		if templates[0].Builtin {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("builtin template cannot be updated")))
			return
		}

		br, err := json.Marshal(req.Rules)
		if err != nil {
			logging.Get().Error().Err(err).Strs("req.Rules", req.Rules).Msg("marshal req.rules fails")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid req.rules")))
			return
		}
		err = iacModel.UpdateDockerfileTemplate(ctx, api.rdb.Get(), map[string]interface{}{"id": req.ID}, map[string]interface{}{
			"name": req.Name, "description": req.Description, "rules": br, "updater": request.GetAccountFromContext(r.Context()),
		})
		if err != nil {
			logging.Get().Err(err).
				Int("id", req.ID).
				Str("name", req.Name).
				Str("description", req.Description).
				Strs("rules", req.Rules).
				Msgf("UpdateDockerfileTemplate fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		_, err = iacModel.CreateDockerfileTemplateSnapshot(ctx, api.rdb.Get(), iacModel.DockerfileTemplateSnapshot{
			TemplateID:  req.ID,
			Name:        req.Name,
			Description: req.Description,
			Rules:       req.Rules,
			Creator:     request.GetAccountFromContext(r.Context()),
			Updater:     request.GetAccountFromContext(r.Context()),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
		if err != nil {
			logging.Get().Err(err).
				Int("id", req.ID).
				Str("name", req.Name).
				Str("description", req.Description).
				Strs("rules", req.Rules).
				Msgf("CreateDockerfileTemplateSnapshot fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		response.Ok(w)
	}
}

func (api *api) DockerfileTemplatesDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Request struct {
			ID int `json:"id"`
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		data, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("err read request body")))
			return
		}

		req := Request{}
		err = json.Unmarshal(data, &req)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("unmarshal req data fails")))
			return
		}

		templates, err := iacModel.FindDockerfileTemplates(ctx, api.rdb.Get(), map[string]interface{}{"id": req.ID})
		if err != nil || len(templates) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileTemplates err: %v, len: %d", err, len(templates))).Msg("FindDockerfileTemplates fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		if templates[0].Builtin {
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("builtin template cannot be removed")))
			return
		}

		err = iacModel.DeleteDockerfileTemplate(ctx, api.rdb.Get(), map[string]interface{}{"id": req.ID})
		if err != nil {
			logging.Get().Err(err).
				Int("id", req.ID).
				Msgf("DeleteDockerfileTemplate fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}
		response.Ok(w)
	}
}

func (api *api) DockerfileTemplatesDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		id, err := param.QueryString(r, "id")
		if err != nil {
			logging.Get().Err(err).Msgf("invalid param id")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid param id")))
			return
		}

		templates, err := iacModel.FindDockerfileTemplates(ctx, api.rdb.GetReadDB(), map[string]interface{}{"id": id})
		if err != nil || len(templates) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileTemplates err: %v, len: %d", err, len(templates))).Msg("FindDockerfileTemplates fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		rules, err := iacModel.FindDockerfileRulesByBuiltinIDs(ctx, api.rdb.GetReadDB(), templates[0].Rules)
		if err != nil {
			logging.Get().Error().Err(err).Msg("FindDockerfileRulesByBuiltinIDs fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		type ResponseRule struct {
			ID          int    `json:"id"`
			BuiltinID   string `json:"builtin_id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Severity    string `json:"severity"`
		}

		type Response struct {
			iacModel.DockerfileTemplate
			Rules []ResponseRule `json:"rules"`
		}

		resp := Response{}
		resp.DockerfileTemplate = templates[0]
		for i := range rules {
			resp.Rules = append(resp.Rules, ResponseRule{
				ID:          rules[i].ID,
				BuiltinID:   rules[i].BuiltinID,
				Name:        api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleName, rules[i].Name, string(lang.Language(r.Context()))),
				Description: api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleDescription, rules[i].Description, string(lang.Language(r.Context()))),
				Severity:    rules[i].Severity,
			})
		}
		sort.Slice(resp.Rules, func(i, j int) bool {
			return resp.Rules[i].BuiltinID < resp.Rules[j].BuiltinID
		})
		response.Ok(w, response.WithItem(resp))
	}
}

func (api *api) DockerfileTemplateSnapshotsDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		id, err := param.QueryString(r, "id")
		if err != nil {
			logging.Get().Err(err).Msgf("invalid param id")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("invalid param id")))
			return
		}

		snapshots, err := iacModel.FindDockerfileTemplateSnapshots(ctx, api.rdb.GetReadDB(), map[string]interface{}{"id": id}, map[string]interface{}{})
		if err != nil || len(snapshots) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileTemplateSnapshots err: %v, len: %d", err, len(snapshots))).Msg("FindDockerfileTemplateSnapshots fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		rules, err := iacModel.FindDockerfileRulesByBuiltinIDs(ctx, api.rdb.GetReadDB(), snapshots[0].Rules)
		if err != nil {
			logging.Get().Error().Err(err).Msg("FindDockerfileRulesByBuiltinIDs fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		type ResponseRule struct {
			ID          int    `json:"id"`
			BuiltinID   string `json:"builtin_id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Severity    string `json:"severity"`
		}

		type Response struct {
			iacModel.DockerfileTemplateSnapshot
			Rules []ResponseRule `json:"rules"`
		}

		resp := Response{}
		resp.DockerfileTemplateSnapshot = snapshots[0]
		for i := range rules {
			resp.Rules = append(resp.Rules, ResponseRule{
				ID:          rules[i].ID,
				BuiltinID:   rules[i].BuiltinID,
				Name:        api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleName, rules[i].Name, string(lang.Language(r.Context()))),
				Description: api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleDescription, rules[i].Description, string(lang.Language(r.Context()))),
				Severity:    rules[i].Severity,
			})
		}
		sort.Slice(resp.Rules, func(i, j int) bool {
			return resp.Rules[i].BuiltinID < resp.Rules[j].BuiltinID
		})
		response.Ok(w, response.WithItem(resp))
	}
}

func (api *api) DockerfileRules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		name, err := param.QueryString(r, "name")
		if err != nil {
			name = ""
		}
		severities := make([]string, 0)
		severity, err := param.QueryString(r, "severity")
		if err == nil {
			severities = strings.Split(severity, ",")
		}

		count, rules, err := iacModel.FindDockerfileRulesByConditions(ctx, api.rdb.GetReadDB(), name, severities, map[string]interface{}{"order": "builtin_id desc", "offset": offset, "limit": limit})
		if err != nil {
			logging.Get().Error().Err(err).Str("name", name).Msg("FindDockerfileRulesByConditions fails")
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, errors.New("db operate fails")))
			return
		}

		viewRules := make([]iacModel.ViewRule, len(rules))
		for i := range rules {
			viewRules[i].Name = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleName, rules[i].Name, string(lang.Language(r.Context())))
			viewRules[i].Description = api.translation.One(translate.DomainIacDockerfile, translate.KeyRuleDescription, rules[i].Description, string(lang.Language(r.Context())))
			viewRules[i].BuiltinID = rules[i].BuiltinID
			viewRules[i].Severity = rules[i].Severity
		}
		sort.Slice(viewRules, func(i, j int) bool {
			return viewRules[i].BuiltinID < viewRules[j].BuiltinID
		})

		response.Ok(w, response.WithItems(viewRules), response.WithTotalItems(count))
	}
}

func (api *api) DockerfileConfigs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		type Resp struct {
			Status    bool                     `json:"status"`
			Action    string                   `json:"action"`
			WhiteList iacModel.DockerfilePaths `json:"white_list"`
		}

		config, err := iacModel.GetDockerfileConfig(ctx, api.rdb.GetReadDB())
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				response.Ok(w, response.WithItem(Resp{Status: false, Action: iacModel.DockerfileScanActionBlock, WhiteList: []string{}}))
				return
			}
			logging.Get().Error().Err(fmt.Errorf("GetDockerfileConfig err: %v", err)).Msg("GetDockerfileConfig fails")
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("GetDockerfileConfig fails")))
			return
		}

		toggle := false
		if config.Status == 1 {
			toggle = true
		}
		resp := Resp{Status: toggle, Action: config.Action, WhiteList: config.WhiteList}

		response.Ok(w, response.WithItem(resp))
	}
}

func (api *api) DockerfileConfigsUpdate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Request struct {
			Status    bool                     `json:"status"`
			Action    string                   `json:"action"`
			WhiteList iacModel.DockerfilePaths `json:"white_list"`
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		data, err := io.ReadAll(r.Body)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("err read request body")))
			return
		}

		req := Request{}
		err = json.Unmarshal(data, &req)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("unmarshal req data fails")))
			return
		}

		status := 1
		if !req.Status {
			status = 0
		}
		err = iacModel.CreateOrUpdateDockerfileConfig(ctx, api.rdb.Get(), iacModel.DockerfileConfig{
			ID:        1, // 只有一条配置
			Status:    status,
			Action:    req.Action,
			WhiteList: req.WhiteList,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError, errors.New("UpdateDockerfileConfig fails")))
			return
		}

		response.Ok(w)
	}
}
