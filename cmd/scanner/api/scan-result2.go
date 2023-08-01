package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 获取webshell 文件内容
func (s *ScanResultAPI) GetWebshellContent(ctx *gin.Context) {
	uniqueID := util.GetUint64FromQuery(ctx, "uniqueID")
	if uniqueID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get webshell uniqueID"))
		return
	}

	content, err := s.ScanResultSrv.GetWebshellContent(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: []uint64{uniqueID}})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(content),
		response.WithTotalItems(int64(len(content))))
}

// 下载webshell 文件
func (s *ScanResultAPI) GetWebshellFile(ctx *gin.Context) {
	uniqueID := util.GetUint64FromQuery(ctx, "uniqueID")
	if uniqueID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get webshell uniqueID"))
		return
	}

	data, ws, err := s.ScanResultSrv.GetWebshellFile(ctx, imagesecModel.ScanResultSearchParam{
		UniqueIds: []uint64{uniqueID}})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	zipName := fmt.Sprintf("%s.zip", ws.Filename)

	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", zipName))
	ctx.Header("Accept-Length", fmt.Sprintf("%d", len(data)))
	ctx.Data(http.StatusOK, "application/octet-stream", data)
}

func (s *ScanResultAPI) GetWebshellDetail(ctx *gin.Context) {

	webshellUniqueID := util.GetUint64FromQuery(ctx, "uniqueID")
	if webshellUniqueID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get webshell uniqueID"))
		return
	}

	data, _, err := s.ScanResultSrv.SearchWebshell(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: []uint64{webshellUniqueID}})
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}
	if len(data) == 0 {
		response.JSONError(ctx, scani18.NotGetFile(nil))
		return
	}
	wh := data[0]
	wh.AdaptI18(ctx)

	response.JSONOK(ctx, response.WithItem(*wh))
}

func (s *ScanResultAPI) GetMalwareDetail(ctx *gin.Context) {

	uniqueID := util.GetUint64FromQuery(ctx, "uniqueID")
	if uniqueID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get webshell uniqueID"))
		return
	}

	data, err := s.ScanResultSrv.SearchMalware(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: []uint64{uniqueID}})
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}
	if len(data) == 0 {
		response.JSONError(ctx, err)
		return
	}
	wh := data[0]

	response.JSONOK(ctx, response.WithItem(*wh))
}

func (s *ScanResultAPI) GetSensitiveDetail(ctx *gin.Context) {
	uniqueID := util.GetUint64FromQuery(ctx, "uniqueID")
	if uniqueID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get webshell uniqueID"))
		return
	}

	data, err := s.ScanResultSrv.SearchSensitive(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: []uint64{uniqueID}})
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}
	if len(data) == 0 {
		response.JSONError(ctx, err)
		return
	}
	wh := data[0]

	response.JSONOK(ctx, response.WithItem(*wh))
}

func (s *ScanResultAPI) GetSensitiveFile(ctx *gin.Context) {
	uniqueID := util.GetUint64FromQuery(ctx, "uniqueID")
	if uniqueID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get webshell uniqueID"))
		return
	}

	data, ws, err := s.ScanResultSrv.GetSensitiveFile(ctx, imagesecModel.ScanResultSearchParam{
		UniqueIds: []uint64{uniqueID}})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	zipName := fmt.Sprintf("%s.zip", ws.Filename)

	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", zipName))
	ctx.Header("Accept-Length", fmt.Sprintf("%d", len(data)))
	ctx.Data(http.StatusOK, "application/octet-stream", data)
}

func (s *ScanResultAPI) GetMalwareFile(ctx *gin.Context) {
	uniqueID := util.GetUint64FromQuery(ctx, "uniqueID")
	if uniqueID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get webshell uniqueID"))
		return
	}

	data, ws, err := s.ScanResultSrv.GetMalwareFile(ctx, imagesecModel.ScanResultSearchParam{
		UniqueIds: []uint64{uniqueID}})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	zipName := fmt.Sprintf("%s.zip", ws.Name)

	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", zipName))
	ctx.Header("Accept-Length", fmt.Sprintf("%d", len(data)))
	ctx.Data(http.StatusOK, "application/octet-stream", data)
}

func (s *ScanResultAPI) GetLicenseFile(ctx *gin.Context) {
	uniqueID := util.GetUint64FromQuery(ctx, "uniqueID")
	if uniqueID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get webshell uniqueID"))
		return
	}

	data, ws, err := s.ScanResultSrv.GetLicenseFile(ctx, imagesecModel.ScanResultSearchParam{
		UniqueIds: []uint64{uniqueID}})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	zipName := fmt.Sprintf("%s.zip", ws.Name)

	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", zipName))
	ctx.Header("Accept-Length", fmt.Sprintf("%d", len(data)))
	ctx.Data(http.StatusOK, "application/octet-stream", data)
}
