package imagesec

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-i18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/utils"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type SensitiveRuleService interface {
	CreateSensitiveRule(ctx context.Context, data *imagesecModel.SensitiveRule) error
	SearchSensitiveRule(ctx context.Context, param imagesecModel.SearchSensitiveRuleParam) ([]*imagesecModel.SensitiveRule, int64, error)
	UpdateSensitiveRule(ctx context.Context, id int64, updater map[string]interface{}) error
	DeleteSensitiveRule(ctx context.Context, id int64) error
}

type ScanImageConfigService interface {
	CreateScanImageConfig(ctx context.Context, data *imagesecModel.ScanImageConfig) error
	GetScanImageConfig(ctx context.Context, configType string) (*imagesecModel.ScanImageConfig, error)
	UpdateScanImageConfig(ctx context.Context, id int64, data *imagesecModel.ScanImageConfig) error
	GetConstView(ctx context.Context, constType string) imagesecModel.ViewConst
}

type SensitiveRuleSrv struct {
	sensitiveRuleDal imagesecStore.SensitiveRuleDal
	scanTaskSrv      imagescan.ScanTaskService
	scannerConfigSrv ScanImageConfigService
	ZhRule           map[string]string
}

func NewSensitiveRuleSrv(
	sensitiveRuleDal imagesecStore.SensitiveRuleDal,
	scanTaskService imagescan.ScanTaskService,
	scannerConfigSrv ScanImageConfigService,
) *SensitiveRuleSrv {
	s := &SensitiveRuleSrv{
		sensitiveRuleDal: sensitiveRuleDal,
		scanTaskSrv:      scanTaskService,
		scannerConfigSrv: scannerConfigSrv,
		ZhRule:           make(map[string]string),
	}

	file, err := utils.GetSensitiveRuleFromFile(consts.DefaultSensitiveRuleZHPath)
	if err == nil {
		for i := range file {
			s.ZhRule[file[i].Value] = file[i].Description
		}
	}
	return s
}

func (s *SensitiveRuleSrv) CreateSensitiveRule(ctx context.Context, data *imagesecModel.SensitiveRule) error {
	if err := data.Check(); err != nil {
		return err
	}
	err := s.sensitiveRuleDal.CreateSensitiveRule(ctx, data)
	if err != nil {
		logging.Get().Err(err).Interface("data", data).Msg("CreateSensitiveRule")
		return scani18.CreateSensitiveRule(err)
	}
	go func() {
		_ = s.AddScanTask(ctx, imagesecModel.ImageListParam{ImageFromType: imagesecModel.ImageFromNode})
	}()

	return nil
}

func (s *SensitiveRuleSrv) SearchSensitiveRule(ctx context.Context, param imagesecModel.SearchSensitiveRuleParam) ([]*imagesecModel.SensitiveRule, int64, error) {
	data, cnt, err := s.sensitiveRuleDal.SearchSensitiveRule(ctx, param)
	if err != nil {
		logging.Get().Err(err).Msg("SearchSensitiveRule")
		return nil, 0, scani18.SearchSensitiveRule(err)
	}
	la, ok := ctx.Value(imagesecModel.AcceptLanguage).(string)
	if ok && la == model.LangZh {
		for i := range data {
			if dis, ok := s.ZhRule[data[i].Value]; ok && dis != "" {
				data[i].Description = dis
			}
		}
	}
	return data, cnt, nil
}

func (s *SensitiveRuleSrv) UpdateSensitiveRule(ctx context.Context, id int64, updater map[string]interface{}) error {
	err := s.sensitiveRuleDal.UpdateSensitiveRule(ctx, id, updater)
	if err != nil {
		logging.Get().Err(err).Int64("id", id).Interface("updater", updater).Msg("UpdateSensitiveRule")
		return scani18.UpdateSensitiveRule(err)
	}

	go func() {
		_ = s.AddScanTask(ctx, imagesecModel.ImageListParam{ImageFromType: imagesecModel.ImageFromNode})
	}()

	return nil
}

func (s *SensitiveRuleSrv) DeleteSensitiveRule(ctx context.Context, id int64) error {
	err := s.sensitiveRuleDal.DeleteSensitiveRule(ctx, id)
	if err != nil {
		logging.Get().Err(err).Int64("id", id).Msg("DeleteSensitiveRule")
		return scani18.DeleteSensitiveRule(err)
	}
	go func() {
		_ = s.AddScanTask(ctx, imagesecModel.ImageListParam{ImageFromType: imagesecModel.ImageFromNode})
	}()

	return nil
}

func (s *SensitiveRuleSrv) AddScanTask(ctx context.Context, param imagesecModel.ImageListParam) error {
	config, err := s.scannerConfigSrv.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
	if err != nil {
		logging.Get().Err(err).Str("configType", imagesecModel.ConfigTypeNodeScanImage).Msg("CreateSensitiveRule GetScanImageConfig")
		return err
	}
	nodeConfig := config.NodeImageConfig
	if !nodeConfig.SensitiveFlush {
		return nil
	}

	taskInfo := imagesecModel.ImageScanTask{
		ImageFromType: imagesecModel.ImageFromNode,
		ScanType:      imagesecModel.SensitiveUpdateTrigger,
		Status:        imagesecModel.TaskStatusPending,
	}
	if err := s.scanTaskSrv.CreateImageScanTask(ctx, param, taskInfo); err != nil {
		logging.Get().Err(err).Str("configType", imagesecModel.ConfigTypeNodeScanImage).Msg("CreateSensitiveRule CreateImageScanTask")
		return err
	}
	return nil
}

type ScanImageConfigSrv struct {
	configDal imagesecStore.ScanImageConfigDal
}

func (s *ScanImageConfigSrv) CreateScanImageConfig(ctx context.Context, data *imagesecModel.ScanImageConfig) error {
	if err := s.configDal.CreateScanImageConfig(ctx, data); err != nil {
		logging.Get().Err(err).Interface("data", data).Msg("CreateScanImageConfig")
		return scani18.CreateScanImageConfig(err)
	}
	return nil
}

func (s *ScanImageConfigSrv) GetScanImageConfig(ctx context.Context, configType string) (*imagesecModel.ScanImageConfig, error) {
	data, err := s.configDal.GetScanImageConfig(ctx, configType)

	if err != nil {
		logging.Get().Err(err).Str("configType", configType).Msg("GetScanImageConfig")
		return nil, scani18.GetScanImageConfig(err)
	}
	return data, nil
}

func (s *ScanImageConfigSrv) UpdateScanImageConfig(ctx context.Context, id int64, data *imagesecModel.ScanImageConfig) error {
	if err := s.configDal.UpdateScanImageConfig(ctx, id, data); err != nil {
		logging.Get().Err(err).Interface("data", data).Msg("UpdateScanImageConfig")
		return scani18.UpdateScanImageConfig(err)
	}
	return nil
}

func (s *ScanImageConfigSrv) GetConstView(ctx context.Context, constType string) imagesecModel.ViewConst {

	ans := imagesecModel.ViewConst{
		ZH: make([]imagesecModel.LabelValue, 0),
		EN: make([]imagesecModel.LabelValue, 0),
	}
	var (
		avEn map[string]string
		avZH map[string]string
	)

	switch constType {
	case consts.ConstViewTypeVulnAttackPath:
		avEn = imagesecModel.GetVulnAVView(model.LangEn)
		avZH = imagesecModel.GetVulnAVView(model.LangZh)

	case consts.ConstViewTypeScanTaskType:
		avEn = imagesecModel.GetTaskTypeView(model.LangEn)
		avZH = imagesecModel.GetTaskTypeView(model.LangZh)

	case consts.ConstViewTypeVulnClass:
		avEn = imagesecModel.GetVulnClassView(model.LangEn)
		avZH = imagesecModel.GetVulnClassView(model.LangZh)

	case consts.ConstViewTypeVulnSeverity:
		avEn = imagesecModel.GetSeverityView(model.LangEn)
		avZH = imagesecModel.GetSeverityView(model.LangZh)
	}

	for k, v := range avEn {
		ans.EN = append(ans.EN, imagesecModel.LabelValue{Label: v, Value: k})
	}

	for k, v := range avZH {
		ans.ZH = append(ans.ZH, imagesecModel.LabelValue{Label: v, Value: k})
	}

	return ans
}

func NewScannerConfigSrv(configDal imagesecStore.ScanImageConfigDal) *ScanImageConfigSrv {
	return &ScanImageConfigSrv{configDal: configDal}
}
