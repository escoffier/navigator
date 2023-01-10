package api

import (
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type ScannerInstanceInfoAPISrv struct {
	ScannerInfoSrv component.ScannerInstanceInfoInterface
}

func NewScannerInstanceInfoSrv(scannerInfoSrv component.ScannerInstanceInfoInterface) *ScannerInstanceInfoAPISrv {
	return &ScannerInstanceInfoAPISrv{ScannerInfoSrv: scannerInfoSrv}
}

func (sc *ScannerInstanceInfoAPISrv) GetScannerInstanceInfo(ctx *gin.Context) {

	type scannerInstanceInfo struct {
		ID                  int64  `json:"id"`
		ClusterName         string `json:"clusterName"`
		ScannerInstance     string `json:"scannerInstance"`     // scanner当前实例，重新启动都会改变
		ScannerInstanceName string `json:"scannerInstanceName"` // 前端展示，scanner+ClusterName的方式
	}

	info, err := sc.ScannerInfoSrv.SearchScannerInfo(ctx)

	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res := make([]scannerInstanceInfo, 0)
	for i := range info {
		logging.Get().Info().Int64("ID", info[i].ID).Msg("GetScannerInstanceInfo")
		ins := scannerInstanceInfo{
			ID:                  info[i].ID,
			ClusterName:         info[i].ClusterName,
			ScannerInstance:     info[i].ScannerInstance,
			ScannerInstanceName: fmt.Sprintf("scanner-%s", info[i].ClusterName),
		}
		if time.Now().Unix()-info[i].HeartBeatAt > 5*60 {
			if GetLanguage(ctx) == consts.LangEN {
				ins.ScannerInstanceName = ins.ScannerInstanceName + "(abnormal)"
			} else {
				ins.ScannerInstanceName = ins.ScannerInstanceName + "(异常)"
			}
		}
		res = append(res, ins)
	}

	response.JSONOK(ctx, response.WithItems(res))
}

func GetLanguage(ctx *gin.Context) string {
	if strings.ToLower(ctx.GetHeader("Accept-Language")) == consts.LangEN ||
		strings.ToLower(ctx.GetHeader("accept-language")) == consts.LangEN {
		return consts.LangEN
	}
	return consts.LangCH
}
