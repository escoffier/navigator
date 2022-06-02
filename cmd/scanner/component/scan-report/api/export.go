package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ExportApiSrv struct {
	exportSrv service.ExportInterface
}

func NewExportApiSrv(exportSrv service.ExportInterface) *ExportApiSrv {
	return &ExportApiSrv{exportSrv: exportSrv}
}

func (s *ExportApiSrv) CreateImageExportTask(ctx *gin.Context) {

	type ImageExport struct {
		ImageID      int64  `json:"imageID"`
		FullRepoName string `json:"fullRepoName"`
		Tag          string `json:"tag"`
		Library      string `json:"library"`
	}
	type ExportTensorTask struct {
		Parameter ImageExport `json:"parameter"`
		Creator   string      `json:"creator"` // 任务创建人
	}

	data := &ExportTensorTask{}
	if err := ctx.BindJSON(data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if data.Parameter.ImageID <= 0 {
		response.JSONError(ctx, fmt.Errorf("no image id"))
		return
	}

	bys, err := json.Marshal(data.Parameter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	now := time.Now()
	fileName := fmt.Sprintf("%s_%s_%d.zip", strings.ReplaceAll(data.Parameter.FullRepoName, "/", "_"),
		data.Parameter.Tag, now.Unix())
	task := model.ExportTensorTask{
		ExecuteType: string(consts.ExportImage),
		Parameter:   string(bys),
		FilePath:    fileName,
		Creator:     data.Creator,
		CreatedAt:   now,
	}

	if err := s.exportSrv.CreateExportTask(ctx, task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(ResponseMsg{Msg: "创建导出任务成功"}))
}

func (s *ExportApiSrv) CreateScanResultExportTask(ctx *gin.Context) {
	type TaskExport struct {
		ScanTaskId   int64  `json:"scanTaskId"`
		TaskCreateAt string `json:"taskCreateAt"`
	}
	type ExportTensorTask struct {
		Parameter TaskExport `json:"parameter"`
		Creator   string     `json:"creator"` // 任务创建人
	}

	data := &ExportTensorTask{}
	if err := ctx.BindJSON(data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if data.Parameter.ScanTaskId <= 0 {
		response.JSONError(ctx, fmt.Errorf("no task id"))
		return
	}
	bys, err := json.Marshal(data.Parameter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	now := time.Now()

	fileName := fmt.Sprintf("%s_scan_result_export.zip", strings.ReplaceAll(data.Parameter.TaskCreateAt, " ", "T"))
	task := model.ExportTensorTask{
		ExecuteType: string(consts.ExportScanResult),
		Parameter:   string(bys),
		Creator:     data.Creator,
		FilePath:    fileName,
		CreatedAt:   now,
	}

	if err := s.exportSrv.CreateExportTask(ctx, task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(ResponseMsg{Msg: "创建导出任务成功"}))
}

func (s *ExportApiSrv) GetExportTaskDetail(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")

	task, err := s.exportSrv.GetExportTask(ctx, id)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(ModelToView(*task)))
}

func (s *ExportApiSrv) GetReportTaskList(ctx *gin.Context) {
	executeType := ctx.Query("executeType")

	filter := model.GetFilterWithDefaultValue(ctx)
	filter.SortFiled = "id"
	filter.SortBy = consts.SortByDesc
	tasks, cnt, err := s.exportSrv.SearchExportTask(ctx, executeType, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	ans := make([]ExportTensorTaskView, len(tasks))
	for i := range tasks {
		ans[i] = ModelToView(tasks[i])
	}

	response.JSONOK(ctx, response.WithItems(ans),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ExportApiSrv) DownLoad(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")

	task, err := s.exportSrv.GetExportTask(ctx, id)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	fp, err := os.OpenFile(task.FilePath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	defer func() {
		if err := fp.Close(); err != nil {
			logging.GetLogger().Err(err).Str("FilePath", task.FilePath).Msg("Close")
		}
	}()
	bys, err := ioutil.ReadAll(fp)
	if err != nil {
		logging.GetLogger().Err(err).Str("FilePath", task.FilePath).Msg("ReadAll")
		response.JSONError(ctx, err)
		return
	}
	logging.GetLogger().Info().Int("data length", len(bys)).Msg("DownLoad")

	splits := strings.Split(task.FilePath, "/")
	filename := task.FilePath
	if len(splits) > 0 {
		filename = splits[len(splits)-1]
	}

	ctx.Header("Content-Disposition", "attachment; filename="+filename) // 指定下载文件名
	ctx.Header("Content-Transfer-Encoding", "binary")
	// ctx.Header("Cache-Control", "no-cache")
	ctx.Header("Content-Type", "application/octet-stream;application/octet-stream;application/zip")
	ctx.Header("Content-Length", strconv.Itoa(len(bys)))

	ctx.Data(http.StatusOK, "application/octet-stream;application/octet-stream;application/zip", bys)

	return
}

type ResponseMsg struct {
	Msg string `json:"msg"`
}
