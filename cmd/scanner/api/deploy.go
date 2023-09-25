package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	deploySrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/deployment"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type DeploySrv struct {
	deployService deploySrv.DeployService
}

func NewDeploySrv(deployService deploySrv.DeployService) *DeploySrv {
	return &DeploySrv{deployService: deployService}
}

func (s *DeploySrv) DeployReasonTop5(ctx *gin.Context) {
	reasonTop5, err := s.deployService.DeployReasonTop5(ctx)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(reasonTop5))
}

func (s *DeploySrv) DeployOverview(ctx *gin.Context) {
	graph := util.GetKeywordFromQuery(ctx, "graph")

	body := imagesecModel.DeployDeployOverviewParam{
		Graph: graph,
	}
	overview, err := s.deployService.DeployOverview(ctx, body)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(overview))
}

func (s *DeploySrv) DeployOverviewBlockTrend(ctx *gin.Context) {
	overview, err := s.deployService.DeployOverviewBlockTrend(ctx)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(overview))
}

func (s *DeploySrv) SearchDeployRecord(ctx *gin.Context) {
	body := imagesecModel.ImageSearchApiParam{}
	if err := ctx.BindJSON(&body); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, err))
		return
	}
	body.Filter = model.GetFilterWithDefaultValue(ctx)
	body.Filter = body.Filter.SetSortFiled("id").SetSortDesc()

	record, cnt, err := s.deployService.SearchDeployRecord(ctx, body)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(record),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(body.Filter.Limit),
		response.WithStartIndex(body.Filter.Offset))
}

func (s *DeploySrv) CheckDeploy(ctx *gin.Context) {
	type tmpRes struct {
		Flag bool `json:"flag"`
	}
	res := tmpRes{}
	res.Flag = true

	containerInfo := make([]imagesecModel.DeployMonitorImage, 0)

	if err := ctx.BindJSON(&containerInfo); err != nil {
		response.JSONError(ctx, err)
		return
	}

	logging.Get().Info().Interface("body", containerInfo).Msg("CheckDeploy")

	if len(containerInfo) == 0 {
		response.JSONError(ctx, fmt.Errorf("not get container info"))
		return
	}
	safe := true
	for i := range containerInfo {
		sa := s.deployService.CheckDeploy(ctx, containerInfo[i])
		if !sa {
			safe = false
		}
	}
	res.Flag = safe
	logging.Get().Info().Interface("res", res).Msg("CheckDeploy")

	response.JSONOK(ctx, response.WithItem(res))
}

func (s *DeploySrv) SearchDeployWhiteImage(ctx *gin.Context) {
	filter := model.GetFilter(ctx).SetMaxLimit(consts.DefaultMaxLimit)
	filter = filter.SetSortDesc().SetSortFiled("updated_at")

	imageKeyword := util.GetKeywordFromQuery(ctx, "imageName")
	startTime := util.GetInt64FromQuery(ctx, "startTime")
	endTime := util.GetInt64FromQuery(ctx, "endTime")

	record, cnt, err := s.deployService.SearchDeployWhiteImage(ctx,
		imagesecModel.SearchDeployWhiteImageParam{
			ImageKeyword:    imageKeyword,
			ExpirationStart: startTime,
			ExpirationEnd:   endTime,
			Filter:          filter,
		})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(record),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *DeploySrv) CreateDeployWhiteImage(ctx *gin.Context) {

	type DeployWhiteImage struct {
		ImageName    []string `json:"imageName"`
		Creator      string   `json:"creator"` // 创建人
		Updater      string   `json:"updater"`
		ExpirationAt int64    `json:"expirationAt"`
	}

	body := &DeployWhiteImage{}
	if err := ctx.BindJSON(body); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, err))
		return
	}
	if body.ExpirationAt <= time.Now().UnixMilli() {
		response.JSONError(ctx, i18.CreateI18BadReqErr("过期时间设置不正确", "expiration not incorrect"))
		return
	}

	data := make([]*imagesecModel.DeployWhiteImage, 0)
	for i := range body.ImageName {
		data = append(data, &imagesecModel.DeployWhiteImage{
			ImageName:    body.ImageName[i],
			Creator:      body.Creator,
			Updater:      body.Updater,
			ExpirationAt: body.ExpirationAt,
		})
	}

	err := s.deployService.CreateDeployWhiteImage(ctx, data)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

func (s *DeploySrv) UpdateDeployWhiteImage(ctx *gin.Context) {

	type DeployWhiteImage struct {
		ImageName    []string `json:"imageName"`
		Creator      string   `json:"creator"` // 创建人
		Updater      string   `json:"updater"`
		ExpirationAt int64    `json:"expirationAt"`
	}

	body := &DeployWhiteImage{}

	if err := ctx.BindJSON(body); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, err))
		return
	}
	id := util.GetInt64FromQuery(ctx, "id")
	up := &imagesecModel.DeployWhiteImage{
		ExpirationAt: body.ExpirationAt,
	}

	up.ID = id

	err := s.deployService.UpdateDeployWhiteImage(ctx, up)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

func (s *DeploySrv) DeleteDeployWhiteImage(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")

	err := s.deployService.DeleteDeployWhiteImage(ctx, id)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}
