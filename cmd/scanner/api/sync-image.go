package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type SyncImageAPISrv struct {
	syncImageSrv component.SyncImageInterface
}

func NewSyncImageAPISrv(syncImageSrv component.SyncImageInterface) *SyncImageAPISrv {
	return &SyncImageAPISrv{syncImageSrv: syncImageSrv}
}

func (s *SyncImageAPISrv) StartSync(ctx *gin.Context) {
	param := SyncImageParam{}
	if err := ctx.BindJSON(&param); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if param.RegistryID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get RegistryID:%d", param.RegistryID))
		return
	}
	go func(regID int64) {
		defer func() {
			if err := recover(); err != nil {
				logging.GetLogger().Error().Msg("StartSync recover")
			}
		}()

		if err := s.syncImageSrv.StartSyncAllImage(ctx, param.RegistryID); err != nil {
			logging.GetLogger().Err(err).Msg("StartSyncAllImage")
		}
	}(param.RegistryID)
	response.JSONOK(ctx, response.WithItem(ResponseMsg{RegistryID: param.RegistryID, Msg: fmt.Sprintf("开启同步任务:registryID:%d", param.RegistryID)}))
}

func (s *SyncImageAPISrv) GetSyncProgress(ctx *gin.Context) {

}

func (s *SyncImageAPISrv) GetSyncStatus(ctx *gin.Context) {
	status, err := s.syncImageSrv.GetSyncStatus(ctx, consts.ManualSync)

	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(status))
}

type SyncImageParam struct {
	RegistryID int64 `json:"registryID"`
}

type ResponseMsg struct {
	Msg        string `json:"msg"`
	RegistryID int64  `json:"registryID"`
}

type ResponseGetSyncStatus struct {
	Status     bool  `json:"status"`
	RegistryID int64 `json:"registryID"`
}
