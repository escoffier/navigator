package excel

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/iac"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	iacModel "gitlab.com/piccolo_su/vegeta/pkg/model/iac"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/iac/pkg/scan"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/translate"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

type YamlScanExportExcel struct {
	ExportTaskDao *store.ExportTaskDao
	UpdateTask    types.UpdateExportTask
	Db            *databases.RDBInstance
	FileDir       string
	translation   *translate.Translation
}

func NewYamlScanExportExcel(
	exportTaskDao *store.ExportTaskDao,
	updateTask types.UpdateExportTask,
	db *databases.RDBInstance,
	fileDir string,
	translation *translate.Translation,
) *YamlScanExportExcel {
	return &YamlScanExportExcel{
		ExportTaskDao: exportTaskDao,
		UpdateTask:    updateTask,
		Db:            db,
		FileDir:       fileDir,
		translation:   translation,
	}
}

func (y *YamlScanExportExcel) Run(ctx context.Context) {

	out := make(chan model.ExportTensorTask, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("GenTensorExportTaskChan")
			}
		}()
		defer close(out)

		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()

		for {
			<-tick.C

			tasks, _, err := y.ExportTaskDao.SearchExportTensorTask(ctx, store.SearchExportTensorTask{
				TaskType:    model.ExportExcel,
				ExecuteType: []string{consts.IACYamlExportType},
				Finished:    consts.FalseString,
				Failure:     consts.FalseString,
			}, &model.Filter{Limit: 1})
			if err != nil {
				logging.Get().Err(err).Str("ExecuteType", consts.IACYamlExportType).Msg("GetTensorTask")
				continue
			}
			for i := range tasks {
				out <- tasks[i]
			}
		}
	}()

	type PathTime struct {
		Path string
		Time time.Time
	}
	paths := make([]PathTime, 0)
	lock := sync.Mutex{}
	go func() {
		for task := range out {
			filepath, _ := y.export(ctx, task)
			lock.Lock()
			paths = append(paths, PathTime{Path: filepath, Time: time.Now()})
			lock.Unlock()
		}
	}()

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				lock.Lock()
				newPaths := make([]PathTime, 0)
				for _, path := range paths {
					if path.Time.Sub(time.Now()) < -time.Minute*5 {
						err := os.RemoveAll(path.Path)
						if err != nil {
							logging.Get().Error().Err(err).Str("path", path.Path).Msg("async remove yaml path fails")
							newPaths = append(newPaths, path)
							continue
						}
						logging.Get().Info().Str("path", path.Path).Msg("async remove yaml path success")
					} else {
						newPaths = append(newPaths, path)
					}
				}
				paths = newPaths
				lock.Unlock()
			}
		}
	}()

}

type taskParam struct {
	Filter    *map[string]interface{} `json:"filter"`     // 根据条件筛选
	TaskID    *int                    `json:"task_id"`    // 根据task_id下载
	RecordIDs *[]int                  `json:"record_ids"` // 根据id勾选
}

func (y *YamlScanExportExcel) export(ctx context.Context, task model.ExportTensorTask) (string, error) {
	if err := y.UpdateTask.Start(ctx, task.ID); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("Clean Start")
		return "", err
	}

	// 新建目录
	filePath := y.genFilePath(ctx, task)
	if err := util.MkdirIfNotExist(filePath, true); err != nil {
		logging.Get().Err(err).Str("filePath", filePath).Msg("YamlScanExportExcel export MkdirIfNotExist")
		if err := y.UpdateTask.Failure(ctx, task.ID, "YamlScanExportExcel export MkdirIfNotExist error"); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("YamlScanExportExcel UpdateExportTask Failure")
		}
		return "", err
	}

	param := taskParam{}
	err := json.Unmarshal([]byte(task.Parameter), &param)
	if err != nil {
		logging.Get().Error().Err(err).Str("param", task.Parameter).Msg("unmarshal task.Parameter fails")
		if err := y.UpdateTask.Failure(ctx, task.ID, "unmarshal task.Parameter fails"); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("YamlScanExportExcel UpdateExportTask Failure")
		}
		return "", err
	}
	var records []iacModel.YamlRecord
	if param.Filter != nil {
		filterM := *param.Filter

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
		if task.Lang == string(lang.LanguageZH) {
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

		records, err = iacModel.FindYamlRecordsByConditions(ctx, y.Db.GetReadDB(),
			name, namespace, templateName, hackEqualTemplateName, clusterKeys, kinds, statuses, startTime, endTime,
			map[string]interface{}{},
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
			return "", err
		}

	} else if param.TaskID != nil {
		records, err = iacModel.FindYamlRecords(ctx, y.Db.GetReadDB(), map[string]interface{}{"task_id": *param.TaskID}, map[string]interface{}{})
		if err != nil {
			logging.Get().Error().Err(fmt.Errorf("FindYamlRecords err: %v", err)).Msg("FindYamlRecords fails")
			if err := y.UpdateTask.Failure(ctx, task.ID, "FindYamlRecords fails"); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("YamlScanExportExcel UpdateExportTask Failure")
			}
			return "", err
		}
	} else if param.RecordIDs != nil {
		records, err = iacModel.FindYamlRecordsByIDs(ctx, y.Db.GetReadDB(), *param.RecordIDs, map[string]interface{}{})
		if err != nil {
			logging.Get().Error().Err(fmt.Errorf("FindYamlRecords err: %v", err)).Msg("FindYamlRecords fails")
			if err := y.UpdateTask.Failure(ctx, task.ID, "FindYamlRecords fails"); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("YamlScanExportExcel UpdateExportTask Failure")
			}
			return "", err
		}
	} else {
		err = fmt.Errorf("no invalid result ids")
		logging.Get().Error().Err(err).Msg("invalid request params")
		if err := y.UpdateTask.Failure(ctx, task.ID, "invalid request params"); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("YamlScanExportExcel UpdateExportTask Failure")
		}
		return "", err
	}
	var resultIDs []int
	resultTemplateSnapshotMap := make(map[int]int)
	resultIDs = make([]int, len(records))
	for i := range records {
		if records[i].Status == iacModel.YamlRecordStatusInitial { // 初始化未真正扫描的记录，跳过
			continue
		}
		resultIDs[i] = records[i].ResultID
		resultTemplateSnapshotMap[records[i].ResultID] = records[i].TemplateID
	}

	results, err := iacModel.FindYamlResults(ctx, y.Db.GetReadDB(), map[string]interface{}{"result_id": resultIDs}, map[string]interface{}{})
	if err != nil {
		logging.Get().Error().Err(fmt.Errorf("FindYamlResults err: %v", err)).Msg("FindYamlResults fails")
		if err := y.UpdateTask.Failure(ctx, task.ID, "FindYamlResults fails"); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("YamlScanExportExcel UpdateExportTask Failure")
		}
		return "", err
	}

	rules, err := iacModel.FindYamlRules(ctx, y.Db.GetReadDB(), map[string]interface{}{}, map[string]interface{}{})
	if err != nil {
		logging.Get().Error().Err(fmt.Errorf("FindYamlRules err: %v", err)).Msg("FindYamlRules fails")
		return "", err
	}
	rulesMap := make(map[string]iacModel.YamlRule)
	for i := range rules {
		rulesMap[rules[i].ThirdPartyID] = rules[i]
	}

	for i := range results {
		filterResult, _, err := iacModel.FilterYamlResultByTemplate(ctx, y.Db.GetReadDB(), results[i].Result, resultTemplateSnapshotMap[results[i].ID])
		if err != nil {
			logging.Get().Error().Err(err).Interface("results[i]", results[i]).Msg("filterYamlResultByTemplate fails")
			continue
		}
		csvRecord := make([][]string, 0)
		csvRecord = append(csvRecord, []string{
			y.translation.One(translate.DomainIacYaml, translate.KeyDownloadCsvColumnName, CsvColumnNameLines, task.Lang),
			y.translation.One(translate.DomainIacYaml, translate.KeyDownloadCsvColumnName, CsvColumnNameRuleName, task.Lang),
			y.translation.One(translate.DomainIacYaml, translate.KeyDownloadCsvColumnName, CsvColumnNameRuleDescription, task.Lang),
			y.translation.One(translate.DomainIacYaml, translate.KeyDownloadCsvColumnName, CsvColumnNameItemDescription, task.Lang),
			y.translation.One(translate.DomainIacYaml, translate.KeyDownloadCsvColumnName, CsvColumnNameResolution, task.Lang),
		})
		flattenResults := make([]scan.FlatResult, 0)
		err = json.Unmarshal([]byte(filterResult), &flattenResults)
		if err != nil {
			logging.Get().Error().Err(err).Interface("filterResult", filterResult).Msg("Unmarshal filterResult fails")
			continue
		}
		for j := range flattenResults {
			rule, ok := rulesMap[flattenResults[j].RuleID]
			if !ok {
				logging.Get().Error().Err(err).Interface("ruleID", flattenResults[j].RuleID).Msg("invalid rule id")
				continue
			}

			lines := fmt.Sprintf("%d ~ %d", flattenResults[j].Location.StartLine, flattenResults[j].Location.EndLine)
			if flattenResults[j].Location.StartLine == flattenResults[j].Location.EndLine && flattenResults[j].Location.StartLine == 0 {
				lines = "-"
			}
			csvRecord = append(csvRecord, []string{
				lines,
				y.translation.One(translate.DomainIacYaml, translate.KeyRuleName, rule.Name, task.Lang),
				y.translation.One(translate.DomainIacYaml, translate.KeyRuleDescription, rule.Description, task.Lang),
				y.translation.One(translate.DomainIacYaml, translate.KeyRuleMessage, flattenResults[j].Description, task.Lang),
				y.translation.One(translate.DomainIacYaml, translate.KeyRuleResolution, flattenResults[j].Resolution, task.Lang),
			})

		}

		csvPath := y.FileDir + "/" + strings.ReplaceAll(task.FilePath, ".zip", fmt.Sprintf("/%s(%s)_%s_%s.csv", results[i].ResourceName, results[i].ResourceKind, results[i].ResourceNamespace, results[i].ResourceClusterKey))
		csvFile, err := os.Create(csvPath)
		if err != nil {
			logging.Get().Error().Err(err).Msg("create csv fails")
			if err := y.UpdateTask.Failure(ctx, task.ID, "create csv fails"); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("YamlScanExportExcel UpdateExportTask Failure")
			}
			return "", err
		}

		csvFile.WriteString("\xEF\xBB\xBF")
		csvWriter := csv.NewWriter(csvFile)
		err = csvWriter.WriteAll(csvRecord)
		if err != nil {
			logging.Get().Error().Err(err).Msg("write csv fails")
			if err := y.UpdateTask.Failure(ctx, task.ID, "write csv fails"); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("YamlScanExportExcel UpdateExportTask Failure")
			}
			return "", err
		}
		csvWriter.Flush()
	}

	// 压缩zip
	zipFilename := y.FileDir + "/" + task.FilePath
	command := fmt.Sprintf("cd %s;zip -r %s %s", y.FileDir, task.FilePath, strings.ReplaceAll(task.FilePath, ".zip", ""))
	cmd := exec.Command("sh", "-c", command)
	if err := cmd.Run(); err != nil {
		logging.Get().Err(err).Str("zipFilename", zipFilename).Str("filePath", task.FilePath).
			Msg("YamlScanExportExcel ZipAndSave use zip")
		if err := y.UpdateTask.Failure(ctx, task.ID, "zip error"); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("YamlScanExportExcel UpdateExportTask Failure")
		}
	}

	if err := y.UpdateTask.Success(ctx, task.ID, zipFilename); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("YamlScanExportExcel Success export task success update task")
	}

	return filePath, nil
}

func (y *YamlScanExportExcel) genFilePath(ctx context.Context, task model.ExportTensorTask) string {
	return y.FileDir + "/" + strings.ReplaceAll(task.FilePath, ".zip", "") + "/"
}
