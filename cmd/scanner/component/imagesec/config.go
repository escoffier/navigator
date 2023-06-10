package imagesec

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-i18"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type SensitiveRuleService interface {
	CreateSensitiveRule(ctx context.Context, data *imagesecModel.SensitiveRule) error
	SearchSensitiveRule(ctx context.Context, filter *model.Filter) ([]*imagesecModel.SensitiveRule, error)
	UpdateSensitiveRule(ctx context.Context, id int64, updater map[string]interface{}) error
	DeleteSensitiveRule(ctx context.Context, id int64) error
}

type ScanImageConfigService interface {
	CreateScanImageConfig(ctx context.Context, data *imagesecModel.ScanImageConfig) error
	GetScanImageConfig(ctx context.Context, configType string) (*imagesecModel.ScanImageConfig, error)
	UpdateScanImageConfig(ctx context.Context, id int64, data *imagesecModel.ScanImageConfig) error
}

type SensitiveRuleSrv struct {
	sensitiveRuleDal imagesecStore.SensitiveRuleDal
	scanTaskSrv      imagescan.ScanTaskService
	scannerConfigSrv ScanImageConfigService
}

func NewSensitiveRuleSrv(
	sensitiveRuleDal imagesecStore.SensitiveRuleDal,
	scanTaskService imagescan.ScanTaskService,
	scannerConfigSrv ScanImageConfigService,
) *SensitiveRuleSrv {
	return &SensitiveRuleSrv{sensitiveRuleDal: sensitiveRuleDal, scanTaskSrv: scanTaskService, scannerConfigSrv: scannerConfigSrv}
}

func (s *SensitiveRuleSrv) CreateSensitiveRule(ctx context.Context, data *imagesecModel.SensitiveRule) error {
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

func (s *SensitiveRuleSrv) SearchSensitiveRule(ctx context.Context, filter *model.Filter) ([]*imagesecModel.SensitiveRule, error) {
	data, err := s.sensitiveRuleDal.SearchSensitiveRule(ctx, filter)
	if err != nil {
		logging.Get().Err(err).Msg("SearchSensitiveRule")
		return nil, scani18.SearchSensitiveRule(err)
	}
	return data, nil
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
		Updater:       imagesecModel.ScanTaskSensitiveFlush,
		Creator:       imagesecModel.ScanTaskSensitiveFlush,
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

func NewScannerConfigSrv(configDal imagesecStore.ScanImageConfigDal) *ScanImageConfigSrv {
	return &ScanImageConfigSrv{configDal: configDal}
}
