package api

import (
	"encoding/hex"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	json "github.com/json-iterator/go"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
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

func (s *ExportApiSrv) CheckScanTask(ctx *gin.Context) {

	scanTaskId := util.GetInt64FromQuery(ctx, "scanTaskId")

	exportLimit, err := s.exportSrv.CheckScanTask(ctx, scanTaskId)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(exportLimit))
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

func (s *ExportApiSrv) CreateAuditExportTask(ctx *gin.Context) {
	type ExportTensorTask struct {
		TaskCreateAt string `json:"taskCreateAt"`
		Creator      string `json:"creator"` // 任务创建人
	}
	data := &ExportTensorTask{}
	if err := ctx.BindJSON(data); err != nil {
		response.JSONError(ctx, err)
		return
	}

	fileName := fmt.Sprintf("audit_log_%s.zip", strings.ReplaceAll(data.TaskCreateAt, " ", "T"))
	task := model.ExportTensorTask{
		ExecuteType: export.AuditExeType,
		Creator:     data.Creator,
		FilePath:    fileName,
		CreatedAt:   time.Now(),
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

	task.FilePath = GetFilename(task.FilePath)

	urlPath := fmt.Sprintf("/api/v2/files/export/file/%s", GetFilename(task.FilePath))

	encrypted, err := util.AesEncryptCBC([]byte(urlPath), []byte(util.DownloadFileKey))
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	token, err := util.NewJWT(urlPath).GenJWTToken(hex.EncodeToString(encrypted), time.Minute*60)

	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	url := fmt.Sprintf("%s?jwt=%s", urlPath, token)
	response.JSONOK(ctx, response.WithItem(DownloadResponse{URL: url}))

	return
}

type ResponseMsg struct {
	Msg string `json:"msg"`
}

type DownloadResponse struct {
	URL string `json:"url"`
}
