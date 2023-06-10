package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ConfigAPISrv struct {
	sensitiveRuleService   imagesecSrv.SensitiveRuleService
	scanImageConfigService imagesecSrv.ScanImageConfigService
}

func NewConfigAPISrv(
	sensitiveRuleService imagesecSrv.SensitiveRuleService,
	scanImageConfigService imagesecSrv.ScanImageConfigService,
) *ConfigAPISrv {
	return &ConfigAPISrv{
		sensitiveRuleService:   sensitiveRuleService,
		scanImageConfigService: scanImageConfigService,
	}
}

func (s *ConfigAPISrv) CreateSensitiveRule(ctx *gin.Context) {
	data := imagesecModel.SensitiveRule{}
	if err := ctx.BindJSON(&data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	data.IsDefault = false
	if err := s.sensitiveRuleService.CreateSensitiveRule(ctx, &data); err != nil {
		response.JSONError(ctx, i18.CreateErr(err))
		return
	}

	response.JSONOK(ctx)
}

func (s *ConfigAPISrv) SearchSensitiveRule(ctx *gin.Context) {
	filter := model.GetFilter(ctx)
	filter.SortFiled = "created_at"
	filter.SortBy = consts.SortByDesc

	rule, err := s.sensitiveRuleService.SearchSensitiveRule(ctx, filter)
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}
	response.JSONOK(ctx, response.WithItems(rule),
		response.WithTotalItems(int64(len(rule))))
}

func (s *ConfigAPISrv) UpdateSensitiveRule(ctx *gin.Context) {
	data := imagesecModel.SensitiveRule{}
	if err := ctx.BindJSON(&data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if err := data.Check(); err != nil {
		response.JSONError(ctx, err)
		return
	}
	id := util.GetInt64FromQuery(ctx, "id")
	if err := s.sensitiveRuleService.UpdateSensitiveRule(ctx, id, data.ToUpdater()); err != nil {
		response.JSONError(ctx, i18.UpdateErr(err))
		return
	}

	response.JSONOK(ctx)
}

func (s *ConfigAPISrv) DeleteSensitiveRule(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")
	if err := s.sensitiveRuleService.DeleteSensitiveRule(ctx, id); err != nil {
		response.JSONError(ctx, i18.DeleteErr(err))
		return
	}
	response.JSONOK(ctx)
}

func (s *ConfigAPISrv) GetNodeScanImageConfig(ctx *gin.Context) {
	configType := util.GetKeywordFromQuery(ctx, "configType")
	if configType == "" {
		response.JSONError(ctx, fmt.Errorf("not get configType"))
		return
	}

	data, err := s.scanImageConfigService.GetScanImageConfig(ctx, configType)
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}
	if configType == imagesecModel.ConfigTypeNodeScanImage {
		response.JSONOK(ctx, response.WithItem(data.NodeImageConfig))
		return
	}
	response.JSONError(ctx, fmt.Errorf("not find config:%s", configType))
}

func (s *ConfigAPISrv) UpdateScanImageConfig(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")
	nodeImageConfig := imagesecModel.NodeImageConfig{}

	err := ctx.BindJSON(&nodeImageConfig)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	m := &imagesecModel.ScanImageConfig{NodeImageConfig: &nodeImageConfig, ConfigType: imagesecModel.ConfigTypeNodeScanImage}
	if err := s.scanImageConfigService.UpdateScanImageConfig(ctx, id, m); err != nil {
		response.JSONError(ctx, i18.UpdateErr(err))
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(id))}))
}
