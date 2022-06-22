package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scanreport "gitlab.com/piccolo_su/vegeta/pkg/model/scan-report"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

// ScanReportCrate 新增扫描报告
// @Summary 扫描报告
// @Title 新增扫描报告
// @Author liuyang@tensorsecurity.cn
// @Description 新增扫描报告
// @Tags scan report
// @Param body json	scanreport.TensorScanReportTasks true "JSON数据"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=OnlyFlagRes{}}}
// @Router	/api/v1/scan-report [post]
func (s *Scanner) ScanReportCrate(ctx *gin.Context) {
	var data scanreport.TensorScanReportTasks
	if err := ctx.BindJSON(&data); err != nil {
		response.JSONError(ctx, err)
		return
	}

	id, err := s.Srv.ScanReportCreate(ctx, &data)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx,
		response.WithItem(model.ID{ID: id}),
		response.WithTarget(&response.TargetRef{
			Name: data.Name,
			ID:   strconv.Itoa(int(id)),
			Link: "api/v2/containerSec/scanner/scan-report",
		}))
}

// ScanReportList 扫描报告列表
// @Summary 扫描报告
// @Title 扫描报告列表
// @Author liuyang@tensorsecurity.cn
// @Description 扫描报告列表
// @Tags scan report
// @Param offset query integer true "limit"
// @Param limit query integer true "offset"
// @Param key_word query string true "搜索关键字"
// @Param type query []uint8 true "报告类型：1:周报，2:月报，3:自定义"
// @Success 200 {object} ApiWithItem{}
// @Router	/api/v1/scan-report [get]
func (s *Scanner) ScanReportList(ctx *gin.Context) {
	type query struct {
		KeyWord string  `json:"key_word" form:"key_word" query:"key_word"`
		Type    []uint8 `json:"type" form:"type" query:"type"`
		model.PageParams
	}

	var params query
	if err := ctx.BindQuery(&params); err != nil {
		response.JSONError(ctx, err)
		return
	}

	data, count, err := s.Srv.ScanReportList(ctx, params.KeyWord, params.Limit, params.Offset, params.Type)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(data), response.WithTotalItems(count))
}

// ScanReportDetail 扫描报告详情
// @Summary 扫描报告
// @Title 扫描报告详情
// @Author liuyang@tensorsecurity.cn
// @Description 扫描报告详情
// @Tags scan report
// @Param id path integer true "任务的ID"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=scanreport.TensorScanReportTasks}}
// @Router	/api/v1/scan-report/:id [get]
func (s *Scanner) ScanReportDetail(ctx *gin.Context) {

	var params model.ID
	if err := ctx.BindUri(&params); err != nil {
		response.JSONError(ctx, err)
		return
	}

	data, err := s.Srv.ScanReportDetail(ctx, params.ID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItem(data))
}

// ScanReportDelete 扫描报告删除
// @Summary 扫描报告
// @Title 新增扫描报告
// @Author liuyang@tensorsecurity.cn
// @Description 新增扫描报告
// @Tags scan report
// @Param id path integer true "任务的ID"
// @Success 200 {object}
// @Router	/api/v1/scan-report/:id [delete]
func (s *Scanner) ScanReportDelete(ctx *gin.Context) {
	var data model.ID
	if err := ctx.BindUri(&data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	// 查询
	detail, err := s.Srv.ScanReportDetail(ctx, data.ID)

	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	if err := s.Srv.ScanReportDelete(ctx, data.ID); err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: detail.Name,
		ID:   strconv.Itoa(int(data.ID)),
		Link: "api/v2/containerSec/scanner/scan-report" + strconv.Itoa(int(data.ID)),
	}))
}

// ScanReportFiles 扫描报告文件下载
// @Summary 扫描报告
// @Title 扫描报告文件下载
// @Author liuyang@tensorsecurity.cn
// @Description 扫描报告文件下载
// @Tags scan report
// @Param offset query integer true "limit"
// @Param limit query integer true "offset"
// @Param id path string true "报告ID"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=OnlyFlagRes{}}}
// @Router	/api/v1/scan-report/:id/subtask
func (s *Scanner) ScanReportFiles(ctx *gin.Context) {
	var params model.PageParams
	if err := ctx.BindQuery(&params); err != nil {
		response.JSONError(ctx, err)
		return
	}

	var id model.ID
	if err := ctx.BindUri(&id); err != nil {
		response.JSONError(ctx, err)
		return
	}

	data, count, err := s.Srv.ScanReportFiles(ctx, id.ID, params.Limit, params.Offset)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(data), response.WithTotalItems(count))
}

// ScanReportDownload 下载扫描报告
// @Summary 扫描报告
// @Title 下载扫描报告
// @Author liuyang@tensorsecurity.cn
// @Description 下载扫描报告
// @Tags scan report
// @Param id path integer true "任务的ID"
// @Param file_id path integer true "子任务ID"
// @Success 200 {object} ApiWithItem{data=scanreport.ScanReportResult}
// @Router	/api/v1/scan-report/:id/file/:sub_task_id [get]
func (s *Scanner) ScanReportDownload(ctx *gin.Context) {
	type URI struct {
		model.ID
		SubTaskID uint `uri:"sub_task_id" binding:"required"`
	}

	var uri URI
	if err := ctx.BindUri(&uri); err != nil {
		response.JSONError(ctx, err)
		return
	}

	data, err := s.Srv.ScanReportDownload(ctx, uri.ID.ID, uri.SubTaskID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItem(data))
}

// ScanReportUpdate 扫描报告更新
// @Summary 扫描报告
// @Title 扫描报告更新
// @Author liuyang@tensorsecurity.cn
// @Description 新增扫描报告
// @Tags scan report
// @Param body json	scanreport.TensorScanReportTasks true "JSON数据"
// @Success 200 {object}
// @Router	/api/v1/scan-report/:id [put]
func (s *Scanner) ScanReportUpdate(ctx *gin.Context) {
	var id model.ID
	if err := ctx.BindUri(&id); err != nil {
		response.JSONError(ctx, err)
		return
	}

	var data scanreport.TensorScanReportTasks

	if err := ctx.BindJSON(&data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	data.ID = id.ID
	err := s.Srv.ScanReportUpdate(ctx, &data)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: data.Name,
		ID:   strconv.Itoa(int(id.ID)),
		Link: "api/v2/containerSec/scanner/scan-report" + strconv.Itoa(int(id.ID)),
	}))
}

// ScanReportGenerate 扫描报告立即生成
// @Summary 扫描报告
// @Title 扫描报告立即生成
// @Author liuyang@tensorsecurity.cn
// @Description 扫描报告立即生成
// @Tags scan report
// @Param id path integer true "任务的ID"
// @Success 200 {object}
// @Router	/api/v1/scan-report/:id/subtask [post]
func (s *Scanner) ScanReportGenerate(ctx *gin.Context) {
	var data model.ID
	if err := ctx.BindUri(&data); err != nil {
		response.JSONError(ctx, err)
		return
	}

	id, err := s.Srv.ScanReportGenerate(ctx, data.ID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx,
		response.WithItem(model.ID{ID: id}),
		response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("report: %d", id),
			ID:   strconv.Itoa(int(id)),
			Link: fmt.Sprintf("api/v2/containerSec/scanner/scan-report/%d/subtask", id),
		}))
}
