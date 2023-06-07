package excel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/xuri/excelize/v2"
	pkgelastic "gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	DefaultExportBathSize = 1000
	timeStampKey          = "Timestamp"
	DefaultLogsNumPerFile = 2000
)

var ErrESDocumentNotFound = errors.New("es document not found")

type AuditExport struct {
	exportTaskDal store.ExportTaskDal
	Interval      time.Duration
	exportingMap  *sync.Map // 正在执行的任务
	fileDir       string    // 文件存储的决对路径
	esCli         *pkgelastic.ESClient
	indexPrefix   string
}

type Resp struct {
	ID        string
	Time      time.Time
	UserName  string
	Ip        string
	Operation string
	Detail    string
}

func NewAuditExport(
	exportTaskDal store.ExportTaskDal,
	interval time.Duration,
	fileDir string,
	esCli *pkgelastic.ESClient,
	indexPrefix string,
) *AuditExport {
	return &AuditExport{
		exportTaskDal: exportTaskDal,
		Interval:      interval,
		exportingMap:  &sync.Map{},
		fileDir:       fileDir,
		esCli:         esCli,
		indexPrefix:   indexPrefix,
	}
}

func (e *AuditExport) Run(ctx context.Context) {
	tasks, err := e.GetTensorTask(ctx, consts.AuditExeType, DefaultExportBathSize)
	if err != nil {
		logging.Get().Err(err).Msg("get task err")
		return
	}
	for i := range tasks {
		task := tasks[i]
		if ex, ok := e.exportingMap.Load(task.ID); ok {
			if ex1, ok := ex.(bool); ok && ex1 == consts.TaskExporting {
				logging.Get().Info().Int64("taskID", task.ID).Msg("task is running")
				continue
			}
		}
		e.exportingMap.Store(task.ID, consts.TaskExporting)
		if err := e.Start(ctx, task.ID); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("Run.Start")
			continue
		}

		excelChan := e.Export(ctx, tasks[i], consts.ExportSingleImage)

		filename := tasks[i].FilePath
		fn := strings.TrimSuffix(filename, ".zip")
		if err := e.ZipAndSave(ctx, fn, excelChan); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ZipAndSave")
			e.exportingMap.Delete(task.ID)

			if err := e.Failure(ctx, task.ID, err.Error()); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("Failure export task failure update task")
			}
			continue
		}
		logging.Get().Info().Int64("taskID", task.ID).Str("filename", filename).Msg("export task success")
		e.exportingMap.Delete(task.ID)
		// 成功之后更新任务
		if err := e.Success(ctx, task.ID, fmt.Sprintf("%s/%s", e.fileDir, filename)); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
		}
	}
}

func (e *AuditExport) Start(ctx context.Context, id int64) error {
	updater := map[string]interface{}{"start_at": time.Now().Unix()}
	where := fmt.Sprintf("id = %d", id)
	if err := e.exportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.Get().Err(err).Int64("taskID", id).Msg("Start")
		return err
	}
	return nil
}

func (e *AuditExport) GetTensorTask(ctx context.Context, executeType string, n int64) ([]model.ExportTensorTask, error) {
	task, _, err := e.exportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{
		ExecuteType: []string{executeType},
		Finished:    consts.FalseString,
		Failure:     consts.FalseString,
	}, &model.Filter{Limit: n})
	if err != nil {
		logging.Get().Err(err).Str("ExecuteType", executeType).Msg("GetTensorTask")
		return nil, err
	}
	return task, nil
}

func (e *AuditExport) genFileName(_ context.Context, task model.ExportTensorTask) (string, error) {
	fileName := fmt.Sprintf("navi-audit-%d-%d", task.ID, task.CreatedAt.Unix())
	return fileName, nil
}

func (e *AuditExport) ZipAndSave(_ context.Context, filename string, files chan *excelize.File) error {
	file, err := common.ZipExcelFile(files)
	if err != nil {
		logging.Get().Err(err).Str("filename", filename).Msg("ZipAndSave.WriteToExcel")
		return err
	}
	if err := common.SaveFile(file, e.fileDir+"/"+filename); err != nil {
		logging.Get().Err(err).Str("filename", filename).Msg("ZipAndSave.SaveFile")
		return err
	}
	logging.Get().Info().Str("filename", filename).Msg("ZipAndSave.SaveFile success")
	return nil
}

func (e *AuditExport) Success(ctx context.Context, id int64, filePath string) error {

	updater := map[string]interface{}{"finish_at": time.Now().Unix(), "file_path": filePath}
	where := fmt.Sprintf("id = %d", id)
	if err := e.exportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.Get().Err(err).Int64("taskID", id).Msg("Success")
		return err
	}
	return nil
}

func (e *AuditExport) Failure(ctx context.Context, id int64, msg string) error {
	updater := map[string]interface{}{"err_msg": msg, "finish_at": time.Now().Unix()}
	where := fmt.Sprintf("id = %d", id)
	if err := e.exportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.Get().Err(err).Int64("taskID", id).Msg("Failure")
		return err
	}
	return nil
}

func (e *AuditExport) Export(ctx context.Context, task model.ExportTensorTask, executeType string) chan *excelize.File {
	out := make(chan *excelize.File, 1)
	go func(task model.ExportTensorTask) {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("AuditExport")
			}
		}()

		defer close(out)

		filename, err := e.genFileName(ctx, task)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("Export.genFilename")
			return
		}

		var offsetId string
		var index = 0
		for {
			auditLogs, err := e.getAuditLog(ctx, offsetId)
			if err != nil || len(auditLogs) == 0 {
				logging.Get().Err(err).Msg("get audit logs")
				return
			}
			offsetId = auditLogs[len(auditLogs)-1].ID
			logging.Get().Info().Msgf("offsetId: %s", offsetId)

			fn := fmt.Sprintf("%s_%d", filename, index)
			excelFile, err := writeExcelFile(fn, auditLogs)
			if err != nil {
				logging.Get().Err(err).Msg("Export.WriteToExcel")
				return
			}
			index++
			out <- excelFile
		}

	}(task)

	return out
}

func writeExcelFile(filenamePrefix string, auditLogs []*Resp) (*excelize.File, error) {
	file := excelize.NewFile()
	file.Path = filenamePrefix + ".xlsx"
	streamWriter, err := file.NewStreamWriter("Sheet1")

	if err != nil {
		return nil, err
	}
	header := []interface{}{"发生时间", "用户名", "IP", "操作", "具体行为"}
	cell, err := excelize.CoordinatesToCellName(1, 1)
	if err != nil {
		return nil, err
	}
	if err := streamWriter.SetRow(cell, header); err != nil {
		return nil, err
	}

	row := 2
	for i := range auditLogs {
		item := auditLogs[i]
		cell, err := excelize.CoordinatesToCellName(1, row)
		if err != nil {
			return nil, err
		}
		data := []interface{}{item.Time, item.UserName, item.Ip, item.Operation, item.Detail}

		if err := streamWriter.SetRow(cell, data); err != nil {
			return nil, err
		}
		row++
	}
	if err := streamWriter.Flush(); err != nil {
		return nil, err
	}
	return file, nil
}

func (e *AuditExport) getAuditLog(ctx context.Context, OffsetID string) ([]*Resp, error) {
	esCli, err := e.esCli.Get()
	if err != nil {
		return nil, err
	}
	searchService := esCli.Search(fmt.Sprintf("%s*", e.indexPrefix)).
		Sort(timeStampKey, true).Sort("_id", true).Size(DefaultLogsNumPerFile)

	if OffsetID != "" {
		record, err := e.GetRecordByID(ctx, OffsetID)
		if err == nil {
			searchService = searchService.SearchAfter(record.Timestamp, OffsetID)
		} else if err != ErrESDocumentNotFound {
			return nil, err
		}
	}

	searchResult, err := searchService.Do(ctx)
	if err != nil {
		return nil, err
	}

	var result = make([]*Resp, 0, len(searchResult.Hits.Hits))
	for _, item := range searchResult.Hits.Hits {
		record, err := parseRecord(item)
		if err != nil {
			logging.Get().Err(err).Msg("parse k8s audit log fail")
			continue
		}
		result = append(result, &Resp{
			ID:        item.Id,
			Time:      time.UnixMilli(record.Timestamp).In(time.FixedZone("CST", 8*3600)),
			UserName:  record.User.Name,
			Ip:        record.HttpRequest.RemoteIP,
			Operation: record.Verb,
			Detail:    record.Detail,
		})
	}

	return result, nil
}

func (e *AuditExport) GetRecordByID(ctx context.Context, id string) (*model.NaviAuditEvent, error) {
	esCli, err := e.esCli.Get()
	if err != nil {
		return nil, err
	}
	rsp, err := esCli.Search().Index(fmt.Sprintf("%s*", e.indexPrefix)).
		Query(elastic.NewTermQuery("_id", id)).Do(ctx)
	if err != nil {
		return nil, err
	}

	if len(rsp.Hits.Hits) != 1 {
		return nil, ErrESDocumentNotFound
	}

	return parseRecord(rsp.Hits.Hits[0])
}

func parseRecord(item *elastic.SearchHit) (*model.NaviAuditEvent, error) {
	var record model.NaviAuditEvent
	var err = json.Unmarshal(item.Source, &record)
	return &record, err
}
