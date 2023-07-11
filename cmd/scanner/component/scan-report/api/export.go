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
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
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
		Parameter imagesec.ImageListParam `json:"parameter"`
		Creator   string                  `json:"creator"` // 任务创建人
		TaskType  string                  `json:"taskType"`
	}

	data := &ExportTensorTask{}
	if err := ctx.BindJSON(data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if data.Parameter.ImageFromType == "" {
		data.Parameter.ImageFromType = util.GetKeywordFromQuery(ctx, "imageFromType")
	}

	bys, err := json.Marshal(data.Parameter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	now := time.Now()
	fileName := fmt.Sprintf("%d_image_search_%s.zip", now.UnixMilli(), data.TaskType)
	task := &model.ExportTensorTask{
		ExecuteType: consts.ExportLibImageSearch,
		Parameter:   string(bys),
		FilePath:    fileName,
		Creator:     data.Creator,
		CreatedAt:   now,
		TaskType:    data.TaskType,
		Lang:        util.GetLanguage(ctx),
	}

	if data.Parameter.ImageFromType == imagesec.ImageFromNode {
		task.ExecuteType = consts.ExportNodeImageSearch
	}
	data.Parameter.Filter = &model.Filter{Limit: 1, Offset: 0}
	// 查询导出的镜像数
	_, cnt, err := s.exportSrv.ListImageWithScanInfo(ctx, data.Parameter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if cnt == 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("no images to export")))
		return
	}

	if err := s.exportSrv.CreateExportTask(ctx, task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	// todo(liuqianli) 糟糕的做法，这部分逻辑应该把在service 层
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
	response.JSONOK(ctx, response.WithItem(
		GenResponseMsg(ctx, task.ID, task.FilePath)),
		response.WithTarget(&response.TargetRef{Name: "export", ID: "0"}))
}

func (s *ExportApiSrv) CreateImageExportTask(ctx *gin.Context) {

	type ExportTensorTask struct {
		Parameter types.SingeImageExportParam `json:"parameter"`
		Creator   string                      `json:"creator"` // 任务创建人
		TaskType  string                      `json:"taskType"`
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
		Lang:        util.GetLanguage(ctx),
	}

	if err := s.exportSrv.CreateExportTask(ctx, task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if data.TaskType == model.ExportHtml {
		go func() {
			if err := s.exportSrv.CreateSearchImage(ctx, task.ID, imagesec.ImageListParam{
				ImageIds: []int64{data.Parameter.ImageID}, ImageFromType: data.Parameter.ImageFromType,
			}); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("CreateSearchImage")
			}
			updater := map[string]interface{}{"start_at": consts.ExportHtmlReady}
			if err := s.exportSrv.UpdateExportTask(ctx, task.ID, updater); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateExportTask")
			}
		}()
	}
	response.JSONOK(ctx, response.WithItem(
		GenResponseMsg(ctx, task.ID, task.FilePath)),
		response.WithTarget(&response.TargetRef{Name: "export", ID: "0"}))
}

func (s *ExportApiSrv) CreateVulnExportTask(ctx *gin.Context) {

	type VulnExportParma struct {
		UniqueID   string `json:"uniqueID"`
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
	if data.Parameter.UniqueID != "" {
		vu := data.Parameter
		data.Parameter.UniqueID = fmt.Sprintf(consts.UniqueVulnFamat, vu.Name, vu.PkgName, vu.PkgVersion)
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
		Lang:        util.GetLanguage(ctx),
	}

	if err := s.exportSrv.CreateExportTask(ctx, task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(
		GenResponseMsg(ctx, task.ID, task.FilePath)),
		response.WithTarget(&response.TargetRef{}))
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

	type ExportTensorTask struct {
		Parameter types.ScanTaskExportParam `json:"parameter"`
		Creator   string                    `json:"creator"`  // 任务创建人
		TaskType  string                    `json:"taskType"` // 是html还是excel
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
	if data.Parameter.ImageFromType == "" {
		data.Parameter.ImageFromType = util.GetKeywordFromQuery(ctx, "imageFromType")
	}

	bys, err := json.Marshal(data.Parameter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	now := time.Now()

	fileName := fmt.Sprintf("%s_scan_result_export_%s_%d.zip", strings.ReplaceAll(data.Parameter.TaskCreateAt, " ", "T"), data.TaskType, now.Unix())
	task := &model.ExportTensorTask{
		ExecuteType: consts.ExportLibTask,
		Parameter:   string(bys),
		Creator:     data.Creator,
		FilePath:    fileName,
		CreatedAt:   now,
		TaskType:    data.TaskType,
		Lang:        util.GetLanguage(ctx),
	}
	if data.Parameter.ImageFromType == imagesec.ImageFromNode {
		task.ExecuteType = consts.ExportNodeTask
	}

	if err := s.exportSrv.CreateExportTask(ctx, task); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if data.TaskType == model.ExportHtml {
		go func() {
			if data.Parameter.ImageFromType == imagesec.ImageFromNode {
				if err := s.exportSrv.CreateLibScanTaskImage(ctx, task.ID, data.Parameter.ScanTaskID); err != nil {
					logging.Get().Err(err).Int64("taskID", task.ID).Msg("CreateSearchImage")
				}
			} else {
				if err := s.exportSrv.CreateLibScanTaskImage(ctx, task.ID, data.Parameter.ScanTaskID); err != nil {
					logging.Get().Err(err).Int64("taskID", task.ID).Msg("CreateSearchImage")
				}
			}
			updater := map[string]interface{}{"start_at": consts.ExportHtmlReady}
			if err := s.exportSrv.UpdateExportTask(ctx, task.ID, updater); err != nil {
				return
			}
		}()

	}
	response.JSONOK(ctx, response.WithItem(
		GenResponseMsg(ctx, task.ID, task.FilePath)),
		response.WithTarget(&response.TargetRef{Name: "export", ID: "0"}))
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
	response.JSONOK(ctx, response.WithItem(
		GenResponseMsg(ctx, task.ID, task.FilePath)))
}

func (s *ExportApiSrv) GetExportTaskDetail(ctx *gin.Context) {
	param := types.GetExportTaskParam{
		ID: util.GetInt64FromQuery(ctx, "id"),
	}
	ty := strings.ToLower(strings.TrimSpace(ctx.Query("type")))
	if ty == consts.ExportCIType {
		param.UUID = ctx.Query("id")
	}

	task, err := s.exportSrv.GetExportTask(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	ans := ModelToView(*task, ctx.GetString(consts.LangKey))
	if ty == consts.ExportCIType {
		ans.CiUUID = ctx.Query("id")
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

	ans.FilePath = fmt.Sprintf("%s?jwt=%s", urlPath, token)

	response.JSONOK(ctx, response.WithItem(ans))
}

func (s *ExportApiSrv) GetReportTaskList(ctx *gin.Context) {
	filter := model.GetFilterWithDefaultValue(ctx)
	filter.SortFiled = "id"
	filter.SortBy = consts.SortByDesc

	needCiReport := util.GetBoolStringFromQuery(ctx, "needCiReport")
	if needCiReport == "" {
		needCiReport = consts.FalseString
	}
	tasks, cnt, err := s.exportSrv.SearchExportTask(ctx, types.SearchExportTaskParam{NeedCiReport: needCiReport}, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	ans := make([]ExportTensorTaskView, len(tasks))
	for i := range tasks {
		ans[i] = ModelToView(tasks[i], ctx.GetString(consts.LangKey))
	}
	for i := range ans {
		if ans[i].Status == consts.ExportStatusRunning {
			if sch, err := s.exportSrv.GetTaskSchedule(ctx, tasks[i]); err == nil {
				ans[i].AllImage = sch.All
				ans[i].FinishedImage = sch.Finished
			}
		}
	}

	// 前端需要知道当前有多少个任务未完成
	_, notFinished, err := s.exportSrv.SearchExportTask(ctx, types.SearchExportTaskParam{
		NeedCiReport: needCiReport,
		Finished:     consts.FalseString,
		Failure:      consts.FalseString,
	}, filter)
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

func (s *ExportApiSrv) DownLoad(ctx *gin.Context) {

	param := types.GetExportTaskParam{
		ID: util.GetInt64FromQuery(ctx, "id"),
	}
	ty := strings.ToLower(strings.TrimSpace(ctx.Query("type")))
	if ty == consts.ExportCIType {
		param.UUID = ctx.Query("id")
	}

	task, err := s.exportSrv.GetExportTask(ctx, param)
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

func GenResponseMsg(ctx *gin.Context, taskID int64, filepath string) ResponseMsg {
	msg := ResponseMsg{
		Msg:      "创建导出任务成功",
		TaskID:   taskID,
		FilePath: filepath,
	}

	if util.GetLanguage(ctx) == model.LangEn {
		msg.Msg = "created successfully"
	}
	return msg
}

type ResponseMsg struct {
	Msg      string `json:"msg"`
	TaskID   int64  `json:"taskID"`
	FilePath string `json:"filePath"`
}

type DownloadResponse struct {
	URL string `json:"url"`
}
