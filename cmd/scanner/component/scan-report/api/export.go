package api

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	json "github.com/json-iterator/go"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ExportApiSrv struct {
	exportSrv service.ExportTaskInterface
}

func NewExportApiSrv(exportSrv service.ExportTaskInterface) *ExportApiSrv {
	return &ExportApiSrv{exportSrv: exportSrv}
}

func (s *ExportApiSrv) CreateImageSearchExportTask(ctx *gin.Context) {

	type ExportTensorTask struct {
		Parameter model.ImageListParam `json:"parameter"`
		Creator   string               `json:"creator"` // 任务创建人
		TaskType  string               `json:"taskType"`
	}

	data := &ExportTensorTask{}
	if err := ctx.BindJSON(data); err != nil {
		response.JSONError(ctx, err)
		return
	}

	bys, err := json.Marshal(data.Parameter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	now := time.Now()
	fileName := fmt.Sprintf("%d_image_search_%s.zip", now.Unix(), data.TaskType)
	task := &model.ExportTensorTask{
		ExecuteType: consts.ExportImageSearch,
		Parameter:   string(bys),
		FilePath:    fileName,
		Creator:     data.Creator,
		CreatedAt:   now,
		TaskType:    data.TaskType,
	}
	// 查询导出的镜像数
	_, cnt, err := s.exportSrv.ListImageWithScanInfo(ctx, data.Parameter, &model.Filter{Limit: 1, Offset: 0})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if cnt == 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("没有可导出的镜像")))
		return
	}

	if err := s.exportSrv.CreateExportTask(ctx, task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if data.TaskType == model.ExportHtml {
		go func() {
			if err := s.exportSrv.CreateSearchImage(ctx, task.ID, data.Parameter); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("CreateSearchImage")
			}

			updater := map[string]interface{}{"start_at": consts.ExportHtmlReady}
			if err := s.exportSrv.UpdateExportTask(ctx, task.ID, updater); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateExportTask")
			}
		}()
	}

	response.JSONOK(ctx, response.WithItem(ResponseMsg{Msg: "创建导出任务成功", TaskID: task.ID, FilePath: task.FilePath}))
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
		TaskType  string      `json:"taskType"`
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
	fileName := fmt.Sprintf("%s_%s_%s_%d.zip", strings.ReplaceAll(data.Parameter.FullRepoName, "/", "_"),
		data.Parameter.Tag, data.TaskType, now.Unix())
	task := &model.ExportTensorTask{
		ExecuteType: consts.ExportSingleImage,
		Parameter:   string(bys),
		FilePath:    fileName,
		Creator:     data.Creator,
		CreatedAt:   now,
		TaskType:    data.TaskType,
	}

	if err := s.exportSrv.CreateExportTask(ctx, task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if data.TaskType == model.ExportHtml {
		go func() {
			if err := s.exportSrv.CreateSearchImage(ctx, task.ID, model.ImageListParam{ImageIds: []int64{data.Parameter.ImageID}}); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("CreateSearchImage")
			}
			updater := map[string]interface{}{"start_at": consts.ExportHtmlReady}
			if err := s.exportSrv.UpdateExportTask(ctx, task.ID, updater); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateExportTask")
			}
		}()
	}

	response.JSONOK(ctx, response.WithItem(ResponseMsg{Msg: "创建导出任务成功", TaskID: task.ID, FilePath: task.FilePath}))
}

func (s *ExportApiSrv) CreateVulnExportTask(ctx *gin.Context) {

	type VulnExportParma struct {
		UniqueVuln string `json:"uniqueVuln"`
		Name       string `json:"name"`
		PkgName    string `json:"pkgName"`
		PkgVersion string `json:"pkgVersion"`
	}
	type ExportTensorTask struct {
		Parameter VulnExportParma `json:"parameter"`
		Creator   string          `json:"creator"` // 任务创建人
	}

	data := &ExportTensorTask{}
	if err := ctx.BindJSON(data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if data.Parameter.UniqueVuln == "" {
		response.JSONError(ctx, fmt.Errorf("no UniqueVuln"))
		return
	}

	bys, err := json.Marshal(data.Parameter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	now := time.Now()
	fileName := fmt.Sprintf("%s_%d.zip", data.Parameter.Name, now.Unix())
	task := &model.ExportTensorTask{
		ExecuteType: consts.ExportVuln,
		Parameter:   string(bys),
		FilePath:    fileName,
		Creator:     data.Creator,
		CreatedAt:   now,
		TaskType:    model.ExportExcel, // 漏洞只能是导出excel
	}

	if err := s.exportSrv.CreateExportTask(ctx, task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(ResponseMsg{Msg: "创建导出任务成功", TaskID: task.ID, FilePath: task.FilePath}))
}

func (s *ExportApiSrv) CheckScanTask(ctx *gin.Context) {

	scanTaskID := util.GetInt64FromQuery(ctx, "scanTaskID")

	exportLimit, err := s.exportSrv.CheckScanTask(ctx, scanTaskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(exportLimit))
}

func (s *ExportApiSrv) CreateScanResultExportTask(ctx *gin.Context) {
	type TaskExport struct {
		ScanTaskID   int64  `json:"scanTaskId"`
		TaskCreateAt string `json:"taskCreateAt"`
	}
	type ExportTensorTask struct {
		Parameter TaskExport `json:"parameter"`
		Creator   string     `json:"creator"`  // 任务创建人
		TaskType  string     `json:"taskType"` // 是html还是excel
	}

	data := &ExportTensorTask{}
	if err := ctx.BindJSON(data); err != nil {
		response.JSONError(ctx, err)
		return
	}

	if data.Parameter.ScanTaskID <= 0 {
		response.JSONError(ctx, fmt.Errorf("no task id"))
		return
	}
	bys, err := json.Marshal(data.Parameter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	now := time.Now()

	fileName := fmt.Sprintf("%s_scan_result_export_%s_%d.zip", strings.ReplaceAll(data.Parameter.TaskCreateAt, " ", "T"), data.TaskType, now.Unix())
	task := &model.ExportTensorTask{
		ExecuteType: consts.ExportScanResult,
		Parameter:   string(bys),
		Creator:     data.Creator,
		FilePath:    fileName,
		CreatedAt:   now,
		TaskType:    data.TaskType,
	}

	if err := s.exportSrv.CreateExportTask(ctx, task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if data.TaskType == model.ExportHtml {
		go func() {
			if err := s.exportSrv.CreateScanTaskImage(ctx, task.ID, data.Parameter.ScanTaskID); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("CreateSearchImage")
			}
			updater := map[string]interface{}{"start_at": consts.ExportHtmlReady}
			if err := s.exportSrv.UpdateExportTask(ctx, task.ID, updater); err != nil {
				return
			}
		}()

	}

	response.JSONOK(ctx, response.WithItem(ResponseMsg{Msg: "创建导出任务成功", TaskID: task.ID, FilePath: task.FilePath}))
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
	task := &model.ExportTensorTask{
		ExecuteType: consts.AuditExeType,
		Creator:     data.Creator,
		FilePath:    fileName,
		CreatedAt:   time.Now(),
		TaskType:    model.ExportExcel, // 日志审计现只支持excel，所以这里赋默认值
	}
	if err := s.exportSrv.CreateExportTask(ctx, task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(ResponseMsg{Msg: "创建导出任务成功", TaskID: task.ID, FilePath: task.FilePath}))
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
	for i := range ans {
		if ans[i].Status == consts.ExportStatusRunning {
			if sch, err := s.exportSrv.GetTaskSchedule(ctx, tasks[i]); err == nil {
				ans[i].AllImage = sch.All
				ans[i].FinishedImage = sch.Finished
			}
		}
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
	Msg      string `json:"msg"`
	TaskID   int64  `json:"taskID"`
	FilePath string `json:"filePath"`
}

type DownloadResponse struct {
	URL string `json:"url"`
}
