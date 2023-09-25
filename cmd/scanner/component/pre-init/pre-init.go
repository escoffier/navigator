package preinit

import (
	"context"
	"os"
	"strings"

	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type InitScannerInterface interface {
	Init(ctx context.Context, scannerLocalID string) error
}

type InitScanner struct {
	imageConfigDal   imagesecStore.ScanImageConfigDal
	detectPolicyDal  imagesecStore.DetectPolicyDal
	sensitiveRuleDal imagesecStore.SensitiveRuleDal
	dataMigrateDal   imagesecStore.DataMigrateDal
	scanResultDal    imagesecStore.ScanResultDal
}

func (s *InitScanner) Init(ctx context.Context) error {
	if !scannerUtils.MainCluster() {
		logging.Get().Info().Msg("not in main cluster")
		return nil
	}
	// 节点镜像默认扫描配置
	if err := s.createNodeImageScanConfig(ctx); err != nil {
		return err
	}
	// 仓库镜像认扫描配置
	if err := s.createRegImageScanConfig(ctx); err != nil {
		return err
	}
	// 节点镜像默认安全策略
	if err := s.createNodeDefaultDetectPolicy(ctx); err != nil {
		return err
	}
	// 仓库镜像的默认安全策略
	if err := s.createRegDefaultDetectPolicy(ctx); err != nil {
		return err
	}
	// 写入默认敏感文件规则
	if err := s.createDefaultSensitiveRule(ctx); err != nil {
		return err
	}
	// 2.10版本数据迁移
	if err := s.createLicenseVer210DataMigrate(ctx); err != nil {
		return err
	}
	// 已存在的策略快照
	_ = s.createDetectPolicySnapshot(ctx)
	return nil
}

func (s *InitScanner) createNodeImageScanConfig(ctx context.Context) error {

	_, err := s.imageConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
	if err == nil {
		logging.Get().Info().Str("configType", imagesecModel.ConfigTypeNodeScanImage).Msg("GetScanImageConfig")
		return nil
	}

	nodeConfig := imagesecModel.ScanImageConfig{
		ConfigType: imagesecModel.ConfigTypeNodeScanImage,
		ImageScanConfig: &imagesecModel.ImageScanConfig{
			VulnFlush:     false,
			MalwareFlush:  false,
			AutoScanAdded: false,
			DeepScan:      false,
			SyncInterval:  30,
			ScanTimeout:   30,
			ClearInterval: 30,
			ScanCycle: imagesecModel.ScanCycle{
				Enable:     false,
				ClusterKey: make([]string, 0),
				AllCluster: true,
				ScanTime:   "00:00:00",
				Day:        make([]int64, 0),
				Weekday:    make([]int64, 0),
				Mouth:      make([]int64, 0),
				CycleType:  imagesecModel.CycleTypeDay,
			},
			Updater: consts.DefaultAdminUser,
		},
	}

	if err := s.imageConfigDal.CreateScanImageConfig(ctx, &nodeConfig); err != nil {
		logging.Get().Err(err).Str("configType", imagesecModel.ConfigTypeNodeScanImage).Msg("GetScanImageConfig")
		return err
	}
	return nil
}

func (s *InitScanner) createRegImageScanConfig(ctx context.Context) error {

	_, err := s.imageConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeRegScanImage)
	if err == nil {
		logging.Get().Info().Str("configType", imagesecModel.ConfigTypeRegScanImage).Msg("GetScanImageConfig")
		return nil
	}

	nodeConfig := imagesecModel.ScanImageConfig{
		ConfigType: imagesecModel.ConfigTypeRegScanImage,
		ImageScanConfig: &imagesecModel.ImageScanConfig{
			VulnFlush:     false,
			MalwareFlush:  false,
			AutoScanAdded: true,
			DeepScan:      false,
			SyncInterval:  10,
			ScanTimeout:   30,
			ClearInterval: 30,
			OldImage:      30,
			ScanCycle: imagesecModel.ScanCycle{
				Enable:     false,
				ClusterKey: make([]string, 0),
				AllReg:     true,
				ScanTime:   "00:00:00",
				Day:        make([]int64, 0),
				Weekday:    make([]int64, 0),
				Mouth:      make([]int64, 0),
				CycleType:  imagesecModel.CycleTypeDay,
			},
			Updater: consts.DefaultAdminUser,
		},
	}

	if err := s.imageConfigDal.CreateScanImageConfig(ctx, &nodeConfig); err != nil {
		logging.Get().Err(err).Str("configType", imagesecModel.ConfigTypeRegScanImage).Msg("GetScanImageConfig")
		return err
	}
	return nil
}

func (s *InitScanner) createNodeDefaultDetectPolicy(ctx context.Context) error {

	detectConfig := &imagesecModel.SecurityPolicy{
		UniqueID:   0,
		Enable:     true,
		PolicyType: imagesecModel.ConfigTypeNodeScanImage,
		Name:       imagesecModel.DefaultPolicyNameEN,
		IsDefault:  true,
		Scope: imagesecModel.PolicyScope{
			ImageFromType: imagesecModel.ImageFromNode,
			ScopeType:     imagesecModel.DetectScopeTypeCluster,
			AllCluster:    true,
		},
		Creator:  consts.DefaultAdminUser,
		Updater:  consts.DefaultAdminUser,
		Malware:  imagesecModel.MalwareDetectRule{Enable: true},
		Webshell: imagesecModel.WebshellDetectRule{Enable: true, RiskLevel: []string{imagesecModel.WebshellRiskLevelCertain}},
		Vuln: imagesecModel.VulnDetectRuleView{
			Enable:           true,
			Severity:         imagesecModel.SeverityCritical,
			IgnoreUnfixed:    true,
			IgnoreKernelVuln: true,
			IgnoreLangVuln:   true,
			HasFixedVuln:     true,
		},
		Sensitive:  imagesecModel.SensitiveDetectRule{Enable: true, AllBlack: true},
		Pkg:        imagesecModel.PkgRule{Enable: false},
		License:    imagesecModel.LicenseDetectRule{Enable: false},
		Env:        imagesecModel.EnvDetectRule{Enable: false, CheckPassword: false},
		RootBoot:   imagesecModel.EnableActionRule{Enable: false},
		TrustImage: imagesecModel.EnableActionRule{Enable: false},
		PkgLicense: imagesecModel.LicenseDetectRule{Enable: false},
		ExistInReg: imagesecModel.EnableActionRule{Enable: false},
	}
	detectConfig.Serialize()

	policies, _, err := s.detectPolicyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{
		PolicyType: imagesecModel.ConfigTypeNodeScanImage,
		NotCount:   true,
		Default:    consts.TrueString,
		Deleted:    consts.FalseString,
	})
	if err != nil {
		logging.Get().Err(err).Msg("SearchDetectPolicy")
		return err
	}

	if len(policies) > 0 {

		logging.Get().Err(err).Msg("SearchDetectPolicy has default detect policy")
		return nil
	}

	if err := s.detectPolicyDal.CreateDetectPolicy(ctx, detectConfig); err != nil {
		logging.Get().Err(err).Msg("CreateDetectPolicy")
		return err
	}

	return nil
}

func (s *InitScanner) createRegDefaultDetectPolicy(ctx context.Context) error {

	detectConfig := &imagesecModel.SecurityPolicy{
		UniqueID:   0,
		PolicyType: imagesecModel.ConfigTypeRegScanImage,
		Name:       imagesecModel.DefaultPolicyNameEN,
		Enable:     true,
		IsDefault:  true,
		Scope: imagesecModel.PolicyScope{
			ImageFromType: imagesecModel.ImageFromRegistry,
			ScopeType:     imagesecModel.DetectScopeTypeReg,
			AllCluster:    false,
			AllReg:        true,
		},
		Creator:  consts.DefaultAdminUser,
		Updater:  consts.DefaultAdminUser,
		Malware:  imagesecModel.MalwareDetectRule{Enable: true},
		Webshell: imagesecModel.WebshellDetectRule{Enable: true, RiskLevel: []string{imagesecModel.WebshellRiskLevelCertain}},
		Vuln: imagesecModel.VulnDetectRuleView{
			Enable:           true,
			Severity:         imagesecModel.SeverityCritical,
			IgnoreUnfixed:    true,
			IgnoreKernelVuln: true,
			IgnoreLangVuln:   true,
			HasFixedVuln:     true,
		},
		Sensitive:  imagesecModel.SensitiveDetectRule{Enable: true, AllBlack: true},
		Pkg:        imagesecModel.PkgRule{Enable: false},
		License:    imagesecModel.LicenseDetectRule{Enable: false},
		Env:        imagesecModel.EnvDetectRule{Enable: false, CheckPassword: false},
		RootBoot:   imagesecModel.EnableActionRule{Enable: false},
		TrustImage: imagesecModel.EnableActionRule{Enable: false},
		PkgLicense: imagesecModel.LicenseDetectRule{Enable: false},
	}
	detectConfig.Serialize()

	policies, _, err := s.detectPolicyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{
		PolicyType: imagesecModel.ConfigTypeRegScanImage,
		NotCount:   true,
		Default:    consts.TrueString,
		Deleted:    consts.FalseString,
	})
	if err != nil {
		logging.Get().Err(err).Msg("SearchDetectPolicy")
		return err
	}
	if len(policies) > 0 {
		logging.Get().Err(err).Msg("SearchDetectPolicy has default detect policy")
		return nil
	}

	if err := s.detectPolicyDal.CreateDetectPolicy(ctx, detectConfig); err != nil {
		logging.Get().Err(err).Msg("CreateDetectPolicy")
		return err
	}

	return nil
}

func (s *InitScanner) createDefaultSensitiveRule(ctx context.Context) error {

	preData, err := scannerUtils.GetSensitiveRuleFromFile(consts.DefaultSensitiveRuleENPath)
	if err != nil {
		logging.Get().Err(err).Msg("InitScanner createDefaultSensitiveRule")
		return err
	}

	rule, _, err := s.sensitiveRuleDal.SearchSensitiveRule(ctx, imagesecModel.SearchSensitiveRuleParam{})
	if err != nil {
		return err
	}
	exit := make(map[string]bool)

	for i := range rule {
		exit[rule[i].Value] = true
	}

	for i := range preData {
		if exit[preData[i].Value] {
			continue
		}

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

// 2.10版本数据迁移
func (s *InitScanner) createLicenseVer210DataMigrate(ctx context.Context) error {

	ver := os.Getenv("SOFT_VERSION")
	if !strings.HasPrefix(ver, "2.10") {
		return nil
	}
	data := &imagesecModel.DataMigrate{
		SoftVersion: ver,
		Model:       consts.DataMigrateModelImage,
	}
	if err := s.dataMigrateDal.CreateDataMigrate(ctx, data); err != nil {
		logging.Get().Err(err).Str("SOFT_VERSION", ver).Msg("CreateDataMigrate")
		return err
	}
	return nil
}

func (s *InitScanner) createDetectPolicySnapshot(ctx context.Context) error {
	policy1, _, err := s.detectPolicyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{
		Filed: []string{"id", "unique_id"},
	})
	if err != nil {
		logging.Get().Err(err).Msg("MigratePolicy SearchDetectPolicy")
		return err
	}

	policy2, err := s.detectPolicyDal.SearchDetectPolicySnapshot(ctx, imagesecModel.SearchSecurityPolicyParam{
		Filed: []string{"id", "unique_id"},
	})
	if err != nil {
		logging.Get().Err(err).Msg("MigratePolicy SearchDetectPolicy")
		return err
	}
	exit := make(map[uint64]bool)
	for i := range policy2 {
		exit[policy2[i].UniqueID] = true
	}

	for i := range policy1 {
		if exit[policy1[i].UniqueID] {
			continue
		}
		pol, _, err := s.detectPolicyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{
			UniqueID: policy1[i].UniqueID,
		})
		if err != nil {
			logging.Get().Err(err).Msg("MigratePolicy SearchDetectPolicy")
			return err
		}
		if len(pol) == 0 {
			continue
		}

		po := pol[i]

		if err := s.detectPolicyDal.CreateDetectPolicySnapshot(ctx, po); err != nil {
			if !strings.Contains(err.Error(), consts.DuplicateKey) {
				logging.Get().Err(err).Msg("MigratePolicy CreateDetectPolicySnapshot")
				continue
			}
		}
	}
	return nil
}

func NewInitScanner(db *databases.RDBInstance) *InitScanner {
	imageConfigDal := imagesecStore.NewScanImageConfigDao(db)
	detectPolicyDal := imagesecStore.NewDetectPolicyDao(db)
	sensitiveRuleDal := imagesecStore.NewSensitiveRuleDao(db)
	dataMigrateDal := imagesecStore.NewDataMigrateDao(db)
	scanResultDal := imagesecStore.NewScanResultDao(db)

	return &InitScanner{
		imageConfigDal:   imageConfigDal,
		detectPolicyDal:  detectPolicyDal,
		sensitiveRuleDal: sensitiveRuleDal,
		dataMigrateDal:   dataMigrateDal,
		scanResultDal:    scanResultDal,
	}
}
