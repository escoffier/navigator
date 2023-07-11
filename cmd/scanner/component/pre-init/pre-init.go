package preinit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/utils"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type InitScannerInterface interface {
	Init(ctx context.Context, scannerLocalID string) error
}

type InitScanner struct {
	regDal              store.RegistryDal
	imageDal            store.ScannerDalInterface
	vulnDal             store.VulnDalInterface
	scanConfigDal       store.ScanConfigDal
	nodeConfigDal       imagesecStore.ScanImageConfigDal
	nodeDetectPolicyDal imagesecStore.DetectPolicyDal
	sensitiveRuleDal    imagesecStore.SensitiveRuleDal
}

func (s *InitScanner) Init(ctx context.Context, scannerInstance string) error {
	if err := s.createGlobalPolicy(ctx); err != nil {
		return err
	}
	// 默认扫描策略
	if err := s.createDefaultScanStrategy(ctx); err != nil {
		return err
	}
	// 全局扫描配置
	if err := s.createGlobalScanConfig(ctx); err != nil {
		return err
	}
	// 节点镜像默认扫描策略
	if err := s.createNodeScanConfig(ctx); err != nil {
		return err
	}
	// 节点镜像默认安全策略
	if err := s.createNodeDefaultDetectConfig(ctx); err != nil {
		return err
	}
	// 写入默认敏感文件规则
	if err := s.createDefaultSensitiveRule(ctx); err != nil {
		return err
	}
	return nil
}

func (s *InitScanner) createGlobalScanConfig(ctx context.Context) error {
	// 先查询默认策略
	strategies, _, err := s.scanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{IsDefault: consts.TrueString}, nil)
	if err != nil {
		return err
	}
	if len(strategies) == 0 {
		return fmt.Errorf("no default scan strategy")
	}

	// 先查一下
	config, _, err := s.scanConfigDal.SearchScanConfig(ctx, store.SearchScanConfigParam{}, nil)
	if err != nil {
		return err
	}
	if len(config) > 0 {
		return nil
	}

	defaultConfig := model.ScanConfigSinge{
		ScanCycleEnable: false,
		Libraries:       []int64{},
		ScanCycle:       []int64{},
		ScanTime:        "",
		ScanAll:         false,
		StrategyID:      strategies[0].ID,
	}

	bys, err := json.Marshal(defaultConfig)
	if err != nil {
		return err
	}

	data := model.ScanConfig{
		LibraryImageAddTrigEnable: false,
		NodeImageAddTrigEnable:    false,
		VulnFlushTrigEnable:       false,
		MaliciousFlushTrigEnable:  false,
		LibraryImageJson:          string(bys),
		NodeImageJson:             string(bys),
	}
	return s.scanConfigDal.CreateScanConfig(ctx, &data)
}

func (s *InitScanner) createNodeScanConfig(ctx context.Context) error {

	_, err := s.nodeConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
	if err == nil {
		logging.Get().Info().Str("configType", imagesecModel.ConfigTypeNodeScanImage).Msg("GetScanImageConfig")
		return nil
	}

	nodeConfig := imagesecModel.ScanImageConfig{
		ConfigType: imagesecModel.ConfigTypeNodeScanImage,
		NodeImageConfig: &imagesecModel.NodeImageConfig{
			VulnFlush:     false,
			MalwareFlush:  false,
			AutoScanAdded: false,
			DeepScan:      false,
			SyncInterval:  10,
			ScanTimeout:   30,
			ClearInterval: 1,
			ScanCycle: imagesecModel.ScanCycle{
				Enable:     false,
				ClusterKey: make([]string, 0),
				AllCluster: false,
				ScanTime:   "0:01:00",
				Day:        make([]int64, 0),
				Weekday:    make([]int64, 0),
				Mouth:      make([]int64, 0),
				CycleType:  imagesecModel.CycleTypeDay,
			},
			Updater: consts.DefaultAdminUser,
		},
	}

	if err := s.nodeConfigDal.CreateScanImageConfig(ctx, &nodeConfig); err != nil {
		logging.Get().Err(err).Str("configType", imagesecModel.ConfigTypeNodeScanImage).Msg("GetScanImageConfig")
		return err
	}
	return nil
}

func (s *InitScanner) createNodeDefaultDetectConfig(ctx context.Context) error {

	nodeDetectConfig := imagesecModel.SecurityPolicy{
		Name:      imagesecModel.DefaultPolicyNameEN,
		IsDefault: true,
		Scope: imagesecModel.PolicyScope{
			ImageFromType: imagesecModel.ImageFromNode,
			ScopeType:     imagesecModel.DetectScopeTypeCluster,
			AllCluster:    true,
		},
		Creator:  consts.DefaultAdminUser,
		Updater:  consts.DefaultAdminUser,
		Malware:  imagesecModel.MalwareDetectRule{Enable: true},
		Webshell: imagesecModel.WebshellDetectRule{Enable: true, RiskLevel: []string{imagesecModel.WebshellRiskLevelCertain}},
		Vuln: imagesecModel.VulnDetectRule{Enable: true, Severity: imagesecModel.SeverityCritical,
			IgnoreKernelVuln: false, IgnoreLangVuln: true, IgnoreUnfixed: true},
		Sensitive:      imagesecModel.SensitiveDetectRule{Enable: true, AllBlack: true},
		Pkg:            imagesecModel.PkgRule{Enable: false},
		License:        imagesecModel.LicenseDetectRule{Enable: false},
		Env:            imagesecModel.EnvDetectRule{Enable: false, CheckPassword: false},
		RootBootEnable: false,
	}
	nodeDetectConfig.Serialize()

	policies, _, err := s.nodeDetectPolicyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{
		NotCount: true,
		Default:  consts.TrueString,
		Deleted:  consts.FalseString,
	})
	if err != nil {
		logging.Get().Err(err).Msg("SearchDetectPolicy")
		return err
	}
	if len(policies) > 0 {
		logging.Get().Err(err).Msg("SearchDetectPolicy has default detect policy")

		if err := s.nodeDetectPolicyDal.UpdateDetectPolicy(ctx, imagesecModel.UpdateSecurityPolicyParam{
			ID:      policies[0].ID,
			Updater: nodeDetectConfig.ToUpdater(),
		}); err != nil {
			logging.Get().Err(err).Msg("UpdateDetectPolicy")
			return err
		}
		return nil
	}

	if err := s.nodeDetectPolicyDal.CreateDetectPolicy(ctx, &nodeDetectConfig); err != nil {
		logging.Get().Err(err).Msg("CreateDetectPolicy")
		return err
	}

	return nil
}

func (s *InitScanner) createDefaultScanStrategy(ctx context.Context) error {
	// 先查一下
	strategy, _, err := s.scanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{IsDefault: consts.TrueString}, nil)
	if err != nil {
		return err
	}
	if len(strategy) > 0 {
		return nil
	}

	data := model.ScanStrategy{
		Name:              "默认扫描策略",
		Describe:          "系统创建",
		Operator:          "系统创建",
		IsDefault:         true,
		OpenLicenseEnable: true,
		SoftwareEnable:    true,
		EnvsEnable:        true,
		SensitiveEnable:   true,
		VulEnable:         true,
		WebshellEnable:    true, // default disable webshell scan
		MaliciousEnable:   true,
	}
	return s.scanConfigDal.CreateStrategy(ctx, &data)
}

func (s *InitScanner) createGlobalPolicy(ctx context.Context) error {
	policies, err := s.imageDal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.TrueString})
	if err != nil {
		logging.Get().Err(err).Msg("InitScanner.createGlobalPolicy")
		return err
	}

	if len(policies) == 0 {
		policy := model.RejectPolicy{
			CicdEnable:    false,
			K8sEnable:     false,
			Mode:          model.RejectPolicyBaseModel,
			OnlineMonitor: false,
			IsGlobal:      true,
		}

		global := model.GlobalRejectPolicy{
			CICDEnable:    false,
			K8sEnable:     false,
			Mode:          model.RejectPolicyBaseModel,
			OnlineMonitor: false,
		}

		if _, err := s.imageDal.CreateRejectPolicy(ctx, policy); err != nil {
			logging.Get().Err(err).Msg("InitScanner.CreateGlobalPolicy")
			return err
		}

		updater := component.GlobalRejectPolicyToUpdater(global)

		if err := s.imageDal.UpdateGlobalPolicy(ctx, updater); err != nil {
			logging.Get().Err(err).Msg("InitScanner.CreateGlobalPolicy")
			return err
		}
	}
	return nil
}

func (s *InitScanner) createDefaultSensitiveRule(ctx context.Context) error {
	preData, err := utils.GetSensitiveRuleFromFile(consts.DefaultSensitiveRuleENPath)
	if err != nil {
		logging.Get().Err(err).Msg("InitScanner createDefaultSensitiveRule")
		return err
	}
	for i := range preData {
		data := &imagesecModel.SensitiveRule{
			Description: preData[i].Description,
			Value:       preData[i].Value,
			RuleType:    preData[i].SecretType,
			IsDefault:   true,
			Enable:      true,
			Updater:     consts.DefaultAdminUser,
			Creator:     consts.DefaultAdminUser,
		}

		if err := s.sensitiveRuleDal.CreateSensitiveRule(ctx, data); err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			}
			logging.Get().Err(err).Interface("data", data).Msg("InitScanner createDefaultSensitiveRule")
		}
	}

	return nil
}

func NewInitScanner(regDal store.RegistryDal,
	imageDal store.ScannerDalInterface,
	scanConfigDAl store.ScanConfigDal,
	vulnDal store.VulnDalInterface,
	nodeConfigDal imagesecStore.ScanImageConfigDal,
	nodeDetectPolicyDal imagesecStore.DetectPolicyDal,
	sensitiveRuleDal imagesecStore.SensitiveRuleDal,
) *InitScanner {
	return &InitScanner{regDal: regDal,
		imageDal:            imageDal,
		scanConfigDal:       scanConfigDAl,
		vulnDal:             vulnDal,
		nodeConfigDal:       nodeConfigDal,
		nodeDetectPolicyDal: nodeDetectPolicyDal,
		sensitiveRuleDal:    sensitiveRuleDal,
	}
}
