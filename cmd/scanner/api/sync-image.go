package api

import (
	"fmt"
	"net/http"
	"strconv"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type SyncImageAPISrv struct {
	syncImageSrv component.SyncImageInterface
	RegistrySrv  component.RegistrySrvInterface
}

func NewSyncImageAPISrv(syncImageSrv component.SyncImageInterface, registrySrv component.RegistrySrvInterface) *SyncImageAPISrv {
	return &SyncImageAPISrv{syncImageSrv: syncImageSrv, RegistrySrv: registrySrv}
}

func (s *SyncImageAPISrv) StartSync(ctx *gin.Context) {
	param := SyncImageParam{}
	if err := ctx.BindJSON(&param); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if param.RegistryID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get RegID:%d", param.RegistryID))
		return
	}

	if err := s.syncImageSrv.CreateSyncTask(ctx, component.CreateSyncTaskParam{
		RegID:    param.RegistryID,
		SyncType: consts.ManualSync,
	}); err != nil {
		logging.GetLogger().Err(err).Msg("StartSyncAllImage")
	}
	response.JSONOK(ctx,
		response.WithItem(ResponseMsg{RegistryID: param.RegistryID, Msg: fmt.Sprintf("开启同步任务:registryID:%d", param.RegistryID)}),
		response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("registry %d", param.RegistryID),
			ID:   strconv.Itoa(int(param.RegistryID)),
			Link: "api/v2/containerSec/scanner/syncImage/startSync",
		}),
	)
}

func (s *SyncImageAPISrv) StartSyncByRegName(ctx *gin.Context) {
	param := SyncImageParam{}
	if err := ctx.BindJSON(&param); err != nil {
		response.JSONError(ctx, err)
		return
	}

	if param.RegistryName == "" {
		response.JSONError(ctx, fmt.Errorf("not get registryName:%s", param.RegistryName))
		return
	}

	regs, _, err := s.RegistrySrv.SearchRegistry(ctx, component.SearchRegistryParam{Name: param.RegistryName, UseType: model.UserRegistry}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(regs) == 0 {
		response.JSONError(ctx, fmt.Errorf("not find registry:%s", param.RegistryName))
		return
	}

	err = s.syncImageSrv.CreateSyncTask(ctx, component.CreateSyncTaskParam{
		RegID:           regs[0].ID,
		SyncType:        consts.ManualSync,
		ScannerInstance: global.ScannerInstance,
	})
	if err != nil {
		logging.GetLogger().Err(err).Msg("StartSyncAllImage")
		response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
		return
	}
	response.JSONOK(ctx,
		response.WithItem(ResponseMsg{RegistryID: regs[0].ID, RegistryName: param.RegistryName, Msg: fmt.Sprintf("开启同步任务:registryName:%s", param.RegistryName)}))
}

func (s *SyncImageAPISrv) GetSyncProgress(ctx *gin.Context) {

}

func (s *SyncImageAPISrv) GetSyncStatus(ctx *gin.Context) {
	status, err := s.syncImageSrv.GetSyncStatus(ctx)

	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(status))
}

type SyncImageParam struct {
	RegistryID   int64  `json:"registryID"`
	RegistryName string `json:"registryName"`
}

type ResponseMsg struct {
	Msg          string `json:"msg"`
	RegistryID   int64  `json:"registryID"`
	RegistryName string `json:"registryName"`
}

type ResponseGetSyncStatus struct {
	Status     bool  `json:"status"`
	RegistryID int64 `json:"registryID"`
}
