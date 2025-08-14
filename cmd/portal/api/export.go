package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/service"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/utils"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// ExportHandler handles export-related forwarding requests
type ExportHandler struct {
	ExportSrv service.ExportTaskInterface
}

// NewExportHandler creates new export handler
func NewExportHandler(srv service.ExportTaskInterface) *ExportHandler {
	return &ExportHandler{ExportSrv: srv}
}

func (s *ExportHandler) CreateExportTask(ctx *gin.Context) {
	// Get original URL
	task := &imagesec.ExportTensorTask{}
	if err := ctx.BindJSON(task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if err := s.ExportSrv.CreateExportTask(ctx, task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(task))
}

func (s *ExportHandler) SearchExportTask(ctx *gin.Context) {
	filter := imagesec.GetFilterWithDefaultValue(ctx)
	filter.SortFiled = "id"
	filter.SortBy = consts.SortByDesc

	param := imagesec.SearchExportTaskParam{
		ExecuteType: []string{consts.ExportPortalProject},
		Filter:      filter,
	}
	tasks, cnt, err := s.ExportSrv.SearchExportTask(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	ans := make([]imagesec.ExportTensorTaskView, len(tasks))
	for i := range tasks {
		ans[i] = imagesec.ModelToView(tasks[i], ctx.GetString(consts.LangKey))
	}
	param.Finished = imagesec.FalseString

	// 前端需要知道当前有多少个任务未完成
	_, notFinished, err := s.ExportSrv.SearchExportTask(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(ans),
		response.WithCustomField("notFinished", notFinished),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func GetFilename(filePath string) string {
	split := strings.Split(filePath, "/")
	if len(split) == 0 {
		return ""
	}
	return split[len(split)-1]
}

func (s *ExportHandler) DownLoadFile(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "id")
	if taskID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get taskID"))
		return
	}

	tasks, _, err := s.ExportSrv.SearchExportTask(ctx, imagesec.SearchExportTaskParam{ID: taskID})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(tasks) == 0 {
		response.JSONError(ctx, fmt.Errorf("not get task"))
		return
	}
	task := tasks[0]
	if task.FinishAt == 0 {
		response.JSONError(ctx, fmt.Errorf("task is not finished"))
		return
	}
	if task.ErrMsg != "" {
		response.JSONError(ctx, fmt.Errorf("task is failed"))
		return
	}
	// Read file content and send in binary format
	// add file name
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.zip\"", GetFilename(task.FilePath)))
	ctx.File(task.FilePath)
}

// StartScanResponse start scan export task response
type StartScanResponse struct {
	TaskID   int64  `json:"taskId"`   // Task ID
	FilePath string `json:"filePath"` // File path
	Message  string `json:"message"`  // Response message
}

// CreateExportProject starts scan export task
func (s *ExportHandler) CreateExportProject(ctx *gin.Context) {
	type ExportTensorTask struct {
		Parameter imagesec.PortalProjectExportParam `json:"parameter"`
		Creator   string                            `json:"creator"` // 任务创建人
		TaskType  string                            `json:"taskType"`
		Filename  string                            `json:"filename"`
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
	if data.Filename == "" {
		data.Filename = fmt.Sprintf("portal_%d", now.UnixMilli())
	}
	if data.TaskType == "" {
		data.TaskType = imagesec.ExportExcel
	}
	data.Filename = fmt.Sprintf("%s_%s.zip", data.Filename, data.TaskType)

	task := &imagesec.ExportTensorTask{
		ExecuteType: consts.ExportPortalProject,
		Parameter:   string(bys),
		FilePath:    data.Filename,
		Creator:     data.Creator,
		CreatedAt:   now,
		TaskType:    data.TaskType,
		Lang:        util.GetLanguage(ctx),
	}

	if err := s.ExportSrv.CreateExportTask(ctx, task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(StartScanResponse{TaskID: task.ID}))
}

func (s *ExportHandler) DownLoad(ctx *gin.Context) {

	taskID := util.GetInt64FromQuery(ctx, "id")
	if taskID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get taskID"))
		return
	}

	tasks, _, err := s.ExportSrv.SearchExportTask(ctx, imagesec.SearchExportTaskParam{ID: taskID})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(tasks) == 0 {
		response.JSONError(ctx, fmt.Errorf("not get task"))
		return
	}
	task := tasks[0]
	if task.FinishAt == 0 {
		response.JSONError(ctx, fmt.Errorf("task is not finished"))
		return
	}
	if task.ErrMsg != "" {
		response.JSONError(ctx, fmt.Errorf("task is failed"))
		return
	}

	filename := GetFilename(task.FilePath)

	urlPath := fmt.Sprintf("/api/v2/files/export/file/%s", filename)
	str := utils.EncryptTimestamp(time.Now().Unix())

	url := fmt.Sprintf("%s?jwt=%s:%s", urlPath, "PORTAL", str)
	response.JSONOK(ctx, response.WithItem(DownloadResponse{URL: url}))
}

type DownloadResponse struct {
	URL string `json:"url"`
}
