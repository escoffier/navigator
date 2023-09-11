package excel

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
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

type DockerfileScanExportExcel struct {
	ExportTaskDao *store.ExportTaskDao
	UpdateTask    types.UpdateExportTask
	Db            *databases.RDBInstance
	FileDir       string
	translation   *translate.Translation
}

func NewDockerfileScanExportExcel(
	exportTaskDao *store.ExportTaskDao,
	updateTask types.UpdateExportTask,
	db *databases.RDBInstance,
	fileDir string,
	translation *translate.Translation,
) *DockerfileScanExportExcel {
	return &DockerfileScanExportExcel{
		ExportTaskDao: exportTaskDao,
		UpdateTask:    updateTask,
		Db:            db,
		FileDir:       fileDir,
		translation:   translation,
	}
}

func (y *DockerfileScanExportExcel) Run(ctx context.Context) {

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
				ExecuteType: []string{consts.IACDockerfileExportType},
				Finished:    consts.FalseString,
				Failure:     consts.FalseString,
			}, &model.Filter{Limit: 1})
			if err != nil {
				logging.Get().Err(err).Str("ExecuteType", consts.IACDockerfileExportType).Msg("GetTensorTask")
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
							logging.Get().Error().Err(err).Str("path", path.Path).Msg("async remove dockerfile path fails")
							newPaths = append(newPaths, path)
							continue
						}
						logging.Get().Info().Str("path", path.Path).Msg("async remove dockerfile path success")
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

type dTaskParam struct {
	RecordID int `json:"record_id"` // 流水线扫描记录id
	ResultID int `json:"result_id"` // 具体文件扫描记录id
}

func (y *DockerfileScanExportExcel) export(ctx context.Context, task model.ExportTensorTask) (string, error) {
	if err := y.UpdateTask.Start(ctx, task.ID); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("Clean Start")
		return "", err
	}

	// 新建目录
	filePath := y.genFilePath(ctx, task)
	if err := util.MkdirIfNotExist(filePath, true); err != nil {
		logging.Get().Err(err).Str("filePath", filePath).Msg("DockerfileScanExportExcel export MkdirIfNotExist")
		if err := y.UpdateTask.Failure(ctx, task.ID, "DockerfileScanExportExcel export MkdirIfNotExist error"); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("DockerfileScanExportExcel genFilePath Failure")
		}
		return "", err
	}

	param := dTaskParam{}
	err := json.Unmarshal([]byte(task.Parameter), &param)
	if err != nil {
		logging.Get().Error().Err(err).Str("param", task.Parameter).Msg("unmarshal task.Parameter fails")
		if err := y.UpdateTask.Failure(ctx, task.ID, "unmarshal task.Parameter fails"); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("DockerfileScanExportExcel Unmarshal Failure")
		}
		return "", err
	}
	var records []iacModel.DockerfileRecord
	var results []iacModel.DockerfileResult
	if param.RecordID != 0 {
		_, records, err = iacModel.FindDockerfileRecords(ctx, y.Db.GetReadDB(), map[string]interface{}{"id": param.RecordID}, map[string]interface{}{})
		if err != nil || len(records) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileRecords err: %v, len: %d", err, len(records))).Msg("FindDockerfileRecordsByIDs fails")
			if err := y.UpdateTask.Failure(ctx, task.ID, "FindDockerfileRecordsByIDs fails"); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("DockerfileScanExportExcel FindDockerfileRecords Failure")
			}
			return "", err
		}

		_, results, err = iacModel.FindDockerfileResults(ctx, y.Db.GetReadDB(), map[string]interface{}{"record_id": param.RecordID}, map[string]interface{}{})
		if err != nil || len(results) == 0 {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileResults err: %v", err)).Msg("FindDockerfileResults fails")
			if err := y.UpdateTask.Failure(ctx, task.ID, "FindDockerfileResults fails"); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("DockerfileScanExportExcel FindDockerfileResults Failure")
			}
			return "", err
		}
	} else if param.ResultID != 0 {
		_, results, err = iacModel.FindDockerfileResults(ctx, y.Db.GetReadDB(), map[string]interface{}{"id": param.ResultID}, map[string]interface{}{})
		if err != nil || len(results) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileResults err: %v, len: %d", err, len(results))).Msg("FindDockerfileResults fails")
			if err := y.UpdateTask.Failure(ctx, task.ID, "FindDockerfileResults fails"); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("DockerfileScanExportExcel FindDockerfileResults Failure")
			}
			return "", err
		}

		_, records, err = iacModel.FindDockerfileRecords(ctx, y.Db.GetReadDB(), map[string]interface{}{"id": results[0].RecordID}, map[string]interface{}{})
		if err != nil || len(records) != 1 {
			logging.Get().Error().Err(fmt.Errorf("FindDockerfileRecords err: %v, len: %d", err, len(records))).Msg("FindDockerfileRecordsByIDs fails")
			if err := y.UpdateTask.Failure(ctx, task.ID, "FindDockerfileRecordsByIDs fails"); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("DockerfileScanExportExcel FindDockerfileRecords Failure")
			}
			return "", err
		}
	} else {
		err = errors.New("invalid params")
		logging.Get().Error().Err(err).Int("record_id", param.RecordID).Int("result_id", param.ResultID).Msg("invalid params")
		return "", err
	}

	rules, err := iacModel.FindDockerfileRules(ctx, y.Db.GetReadDB(), map[string]interface{}{}, map[string]interface{}{})
	if err != nil {
		logging.Get().Error().Err(fmt.Errorf("FindDockerfileRules err: %v", err)).Msg("FindDockerfileRules fails")
		return "", err
	}
	rulesMap := make(map[string]iacModel.DockerfileRule)
	for i := range rules {
		rulesMap[rules[i].ThirdPartyID] = rules[i]
	}

	for i := range results {
		if results[i].Result == "" || results[i].Result == "null" {
			continue
		}
		filterResult, _, err := iacModel.FilterDockerfileResultByTemplate(ctx, y.Db.GetReadDB(), results[i].Result, records[0].TemplateID)
		if err != nil {
			logging.Get().Error().Err(err).Interface("results[i]", results[i]).Msg("FilterDockerfileResultByTemplate fails")
			continue
		}
		csvRecord := make([][]string, 0)
		csvRecord = append(csvRecord, []string{"问题行数", "规则名称", "规则描述", "问题描述", "修复方案"})
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
				y.translation.One(translate.DomainIacDockerfile, translate.KeyRuleName, rule.Name, task.Lang),
				y.translation.One(translate.DomainIacDockerfile, translate.KeyRuleDescription, rule.Description, task.Lang),
				y.translation.One(translate.DomainIacDockerfile, translate.KeyRuleMessage, flattenResults[j].Description, task.Lang),
				y.translation.One(translate.DomainIacDockerfile, translate.KeyRuleResolution, flattenResults[j].Resolution, task.Lang),
			})

		}

		newPath := strings.ReplaceAll(results[i].DockerfilePath, "/", "_")
		if len(newPath) != 0 && strings.HasPrefix(newPath, "_") {
			newPath = newPath[1:]
		}
		csvPath := y.FileDir + "/" + strings.ReplaceAll(task.FilePath, ".zip", fmt.Sprintf("/%s.csv", newPath))
		csvFile, err := os.Create(csvPath)
		if err != nil {
			logging.Get().Error().Err(err).Msg("create csv fails")
			if err := y.UpdateTask.Failure(ctx, task.ID, "create csv fails"); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("DockerfileScanExportExcel UpdateExportTask Failure")
			}
			return "", err
		}

		csvFile.WriteString("\xEF\xBB\xBF")
		csvWriter := csv.NewWriter(csvFile)
		err = csvWriter.WriteAll(csvRecord)
		if err != nil {
			logging.Get().Error().Err(err).Msg("write csv fails")
			if err := y.UpdateTask.Failure(ctx, task.ID, "write csv fails"); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("DockerfileScanExportExcel UpdateExportTask Failure")
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
			Msg("DockerfileScanExportExcel ZipAndSave use zip")
		if err := y.UpdateTask.Failure(ctx, task.ID, "zip error"); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("DockerfileScanExportExcel UpdateExportTask Failure")
		}
	}

	if err := y.UpdateTask.Success(ctx, task.ID, zipFilename); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("DockerfileScanExportExcel Success export task success update task")
	}

	return filePath, nil
}

func (y *DockerfileScanExportExcel) genFilePath(ctx context.Context, task model.ExportTensorTask) string {
	return y.FileDir + "/" + strings.ReplaceAll(task.FilePath, ".zip", "") + "/"
}
