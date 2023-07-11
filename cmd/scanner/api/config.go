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
	ruleType := util.GetKeywordFromQuery(ctx, "ruleType")
	isDefault := util.GetKeywordFromQuery(ctx, "isDefault")
	enable := util.GetKeywordFromQuery(ctx, "enable")

	param := imagesecModel.SearchSensitiveRuleParam{
		RuleType:  ruleType,
		IsDefault: isDefault,
		Enable:    enable,
		Filter:    filter,
	}

	rule, cnt, err := s.sensitiveRuleService.SearchSensitiveRule(ctx, param)
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}
	response.JSONOK(ctx, response.WithItems(rule),
		response.WithTotalItems(cnt))
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

func (s *ConfigAPISrv) GetConstView(ctx *gin.Context) {
	constType := util.GetKeywordFromQuery(ctx, "constType")
	view := s.scanImageConfigService.GetConstView(ctx, constType)
	lang := util.GetLanguage(ctx)
	if lang == model.LangEn {
		response.JSONOK(ctx, response.WithItems(view.EN))
		return
	}
	response.JSONOK(ctx, response.WithItems(view.ZH))
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
