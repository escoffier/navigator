package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-i18"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type WebshellAPIService struct {
	WebshellService imagesecSrv.WebshellService
}

func NewWebshellAPIService(webshellService imagesecSrv.WebshellService) *WebshellAPIService {
	return &WebshellAPIService{WebshellService: webshellService}
}

func (s *WebshellAPIService) GetWebshellContent(ctx *gin.Context) {
	uniqueID := util.GetUint64FromQuery(ctx, "uniqueID")
	if uniqueID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get webshell uniqueID"))
		return
	}

	content, err := s.WebshellService.GetWebshellContent(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: []uint64{uniqueID}})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(content),
		response.WithTotalItems(int64(len(content))))
}

// 获取镜像漏洞-漏洞视角
func (s *WebshellAPIService) GetWebshellFile(ctx *gin.Context) {
	uniqueID := util.GetUint64FromQuery(ctx, "uniqueID")
	if uniqueID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get webshell uniqueID"))
		return
	}
	wss, _, err := s.WebshellService.SearchWebshell(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: []uint64{uniqueID}})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(wss) == 0 {
		response.JSONError(ctx, fmt.Errorf("not find webshell:%d", uniqueID))
		return
	}
	zipName := fmt.Sprintf("%s.zip", wss[0].Filename)
	if wss[0].FileType != "" {
		zipName = strings.Replace(wss[0].Filename, wss[0].FileType, "zip", 1)
	}

	data, err := s.WebshellService.GetWebshellFile(ctx, imagesecModel.ScanResultSearchParam{
		UniqueIds: []uint64{uniqueID}})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", zipName))
	ctx.Header("Accept-Length", fmt.Sprintf("%d", len(data)))
	ctx.Data(http.StatusOK, "application/octet-stream", data)
}

// webshell(只是节点镜像使用)
func (s *WebshellAPIService) GetWebshellDetail(ctx *gin.Context) {

	webshellUniqueID := util.GetUint64FromQuery(ctx, "uniqueID")
	if webshellUniqueID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get webshell uniqueID"))
		return
	}

	data, _, err := s.WebshellService.SearchWebshell(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: []uint64{webshellUniqueID}})
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}
	if len(data) == 0 {
		response.JSONError(ctx, scani18.NotGetWebshell())
		return
	}
	response.JSONOK(ctx, response.WithItem(*(data[0])))
}
