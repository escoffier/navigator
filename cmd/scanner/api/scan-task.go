package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
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

	body := imagesecModel.ImageListParam{}

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
		Updater:       body.ImageScanTaskInfo.Operator,
		Creator:       body.ImageScanTaskInfo.Operator,
		Status:        imagesecModel.TaskStatusPending,
	}

	if err := s.scanTaskSrv.CreateImageScanTask(ctx, body, taskInfo); err != nil {
		response.JSONError(ctx, response.CreateErr(err))
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: "CreateImageScanTask",
		Link: "api/v2/containerSec/scanner/tasks/CreateScanImageTask",
	}))
}

func (s *ScanTaskAPI) UpdateScanTaskStatus(ctx *gin.Context) {
	taskID := util.GetInt64FromQuery(ctx, "id")

	body := imagesecModel.ImageScanTask{}
	if err := ctx.BindJSON(&body); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, err))
		return
	}
	body.Status = imagesecModel.ScanStatusStrToInt(body.StatusStr)

	if body.Status < imagesecModel.TaskStatusPending || body.Status > imagesecModel.TaskStatusFailed {
		response.JSONError(ctx, fmt.Errorf("not get scan status"))
		return
	}

	if err := s.scanTaskSrv.UpdateScanTaskStatus(ctx, taskID, body.StatusStr); err != nil {
		response.JSONError(ctx, response.UpdateErr(err))
		return
	}
	response.JSONOK(ctx)
}

func (s *ScanTaskAPI) RescheduleScanSubtask(ctx *gin.Context) {
	subtaskID := util.GetInt64FromQuery(ctx, "id")
	if err := s.scanTaskSrv.RescheduleScanSubtask(ctx, subtaskID); err != nil {
		response.JSONError(ctx, response.UpdateErr(err))
		return
	}
	response.JSONOK(ctx)
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
		Filter:          model.GetFilter(ctx).SetMaxLimit(consts.DefaultLimit).SetSortFiled("status").SetSortDesc(),
	}
	param.SearchSubtask = true
	subtasks, cnt, err := s.scanTaskSrv.SearchScanSubtask(ctx, param)
	if err != nil {
		response.JSONError(ctx, response.SearchErr(err))
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
		Filter:          model.GetFilter(ctx).SetMaxLimit(10).SetSortDesc().SetSortFiledByID(),
	}
	param.Filter = param.Filter.SetSortDesc().SetSortFiled("id")
	tasks, cnt, err := s.scanTaskSrv.SearchScanTask(ctx, param)
	if err != nil {
		response.JSONError(ctx, response.SearchErr(err))
		return
	}

	lang := util.GetLanguage(ctx)
	for i := range tasks {
		tasks[i].ToApiView()
		tasks[i].ChangeCreator(lang)
	}

	response.JSONOK(ctx, response.WithItems(tasks),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(param.Filter.Limit),
		response.WithStartIndex(param.Filter.Offset))
}
