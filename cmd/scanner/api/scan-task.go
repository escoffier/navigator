package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanTaskAPI struct {
	scanTaskSrv imagesecSrv.ScanTaskService
}

func NewScanTaskAPI(scanTaskSrv imagesecSrv.ScanTaskService) *ScanTaskAPI {
	return &ScanTaskAPI{scanTaskSrv: scanTaskSrv}
}

func (s *ScanTaskAPI) CreateImageScanTask(ctx *gin.Context) {

	body := imagesecModel.ImageSearchApiParam{}

	if err := ctx.BindJSON(&body); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, err))
		return
	}
	if body.ImageFromType == "" {
		body.ImageFromType = util.GetKeywordFromQuery(ctx, "imageFromType")
	}

	taskInfo := imagesecModel.ImageScanTask{
		ImageFromType: body.ImageFromType,
		ScanType:      imagesecModel.ManualTrigger,
		Updater:       body.Creator,
		Creator:       body.Creator,
		Status:        imagesecModel.TaskStatusPending,
	}

	if err := s.scanTaskSrv.CreateImageScanTask(ctx, body, taskInfo); err != nil {
		response.JSONError(ctx, i18.CreateErr(err))
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{Name: "CreateImageScanTask"}))
}

func (s *ScanTaskAPI) UpdateScanTaskStatus(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "id")

	body := imagesecModel.ImageScanTask{}
	if err := ctx.BindJSON(&body); err != nil {
		response.JSONError(ctx, scani18.ParameterErr(nil))
		return
	}
	body.Status = imagesecModel.ScanStatusStrToInt(body.StatusStr)

	if body.Status < imagesecModel.TaskStatusPending || body.Status > imagesecModel.TaskStatusFailed {
		response.JSONError(ctx, i18.CreateI18BadReqErr("任务状态参数不正确", "task status parameter is incorrect"))
		return
	}

	if err := s.scanTaskSrv.UpdateScanTaskStatus(ctx, taskID, body.StatusStr); err != nil {
		response.JSONError(ctx, scani18.UpdateScanTask(err))
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(taskID)), Name: strconv.Itoa(int(taskID))}))
}

func (s *ScanTaskAPI) RescheduleScanSubtask(ctx *gin.Context) {
	subtaskID := util.GetInt64FromQuery(ctx, "id")
	if err := s.scanTaskSrv.RescheduleScanSubtask(ctx, subtaskID); err != nil {
		response.JSONError(ctx, scani18.UpdateScanSubtask(err))
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(subtaskID)), Name: strconv.Itoa(int(subtaskID))}))
}

func (s *ScanTaskAPI) SearchScanSubtask(ctx *gin.Context) {

	param := imagesecModel.SearchTaskParam{
		TaskID:          util.GetInt64FromQuery(ctx, "taskID"),
		ImageFromType:   util.GetKeywordFromQuery(ctx, "imageFromType"),
		PolicyID:        util.GetInt64FromQuery(ctx, "policyID"),
		Finished:        util.GetKeywordFromQuery(ctx, "finished"),
		Started:         util.GetKeywordFromQuery(ctx, "started"),
		ScanStatusStr:   util.GetStringSliceFromQuery(ctx, "statusStr"),
		NodeNameKeyword: util.GetKeywordFromQuery(ctx, "nodeNameKeyword"),
		Filter:          imagesecModel.GetFilter(ctx).SetMaxLimit(consts.DefaultMaxLimit).SetSortFiled("id").SetSortDesc(),
	}
	param.IsSearchSubtask = true
	subtasks, cnt, err := s.scanTaskSrv.SearchScanSubtask(ctx, param)
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}

	for i := range subtasks {
		subtasks[i].ToApiView()
		subtasks[i].Reason = imagesecModel.GetTaskReason(subtasks[i].Reason, util.GetLanguage(ctx))
	}

	response.JSONOK(ctx, response.WithItems(subtasks),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(param.Filter.Limit),
		response.WithStartIndex(param.Filter.Offset))

}

func (s *ScanTaskAPI) SearchScanTask(ctx *gin.Context) {
	param := imagesecModel.SearchTaskParam{
		ImageFromType:   util.GetKeywordFromQuery(ctx, "imageFromType"),
		PolicyID:        util.GetInt64FromQuery(ctx, "policyID"),
		Finished:        util.GetKeywordFromQuery(ctx, "finished"),
		Started:         util.GetKeywordFromQuery(ctx, "started"),
		ScanStatusStr:   util.GetStringSliceFromQuery(ctx, "statusStr"),
		NodeNameKeyword: util.GetKeywordFromQuery(ctx, "nodeNameKeyword"),
		ScanType:        util.GetStringSliceFromQuery(ctx, "scanType"),
		Filter:          imagesecModel.GetFilter(ctx).SetMaxLimit(consts.DefaultMaxLimit).SetSortDesc().SetSortFiledByID(),
	}
	param.Filter = param.Filter.SetSortDesc().SetSortFiled("id")
	tasks, cnt, err := s.scanTaskSrv.SearchScanTask(ctx, param)
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}

	for i := range tasks {
		tasks[i].ToApiView()
	}

	response.JSONOK(ctx, response.WithItems(tasks),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(param.Filter.Limit),
		response.WithStartIndex(param.Filter.Offset))
}
