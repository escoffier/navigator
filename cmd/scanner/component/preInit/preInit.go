package preinit

import (
	"context"
	"fmt"
	"os"
	"strings"

	"gitlab.com/security-rd/go-pkg/databases"

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
	dbMetaDal        imagesecStore.ScanDbMetaDal
	Log              *scannerUtils.LogEvent
}

func (s *InitScanner) Init(ctx context.Context) error {
	if !scannerUtils.MainCluster() {
		s.Log.Info().Msg("not in main cluster")
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
	// 2.20版本数据迁移
	// 中移发版，不做数据迁移，其他环境可以直接同步然后扫描
	// _ = s.createVer210DataMigrate(ctx)

	// 已存在的策略快照
	_ = s.createDetectPolicySnapshot(ctx)

	// scanner 启动时清理镜像扫描过程中的临时文件
	_ = s.removeImagescanDir(ctx)
	_ = s.createSensitiveDBVersion(ctx)
	return nil
}

func (s *InitScanner) createNodeImageScanConfig(ctx context.Context) error {

	_, err := s.imageConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
	if err == nil {
		s.Log.Info().Str("configType", imagesecModel.ConfigTypeNodeScanImage).Msg("GetScanImageConfig")
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
		s.Log.Err(err).Str("configType", imagesecModel.ConfigTypeNodeScanImage).Msg("GetScanImageConfig")
		return err
	}
	return nil
}

func (s *InitScanner) createRegImageScanConfig(ctx context.Context) error {

	_, err := s.imageConfigDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeRegScanImage)
	if err == nil {
		s.Log.Info().Str("configType", imagesecModel.ConfigTypeRegScanImage).Msg("GetScanImageConfig")
		return nil
	}

	nodeConfig := imagesecModel.ScanImageConfig{
		ConfigType: imagesecModel.ConfigTypeRegScanImage,
		ImageScanConfig: &imagesecModel.ImageScanConfig{
			VulnFlush:     false,
			MalwareFlush:  false,
			AutoScanAdded: false,
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
		s.Log.Err(err).Str("configType", imagesecModel.ConfigTypeRegScanImage).Msg("GetScanImageConfig")
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
		s.Log.Err(err).Msg("SearchDetectPolicy")
		return err
	}

	if len(policies) > 0 {

		s.Log.Err(err).Msg("SearchDetectPolicy has default detect policy")
		return nil
	}

	if err := s.detectPolicyDal.CreateDetectPolicy(ctx, detectConfig); err != nil {
		s.Log.Err(err).Msg("CreateDetectPolicy")
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
		s.Log.Err(err).Msg("SearchDetectPolicy")
		return err
	}
	if len(policies) > 0 {
		s.Log.Err(err).Msg("SearchDetectPolicy has default detect policy")
		return nil
	}

	if err := s.detectPolicyDal.CreateDetectPolicy(ctx, detectConfig); err != nil {
		s.Log.Err(err).Msg("CreateDetectPolicy")
		return err
	}

	return nil
}

func (s *InitScanner) createDefaultSensitiveRule(ctx context.Context) error {

	preData, err := scannerUtils.GetSensitiveRuleFromFile(consts.DefaultSensitiveRuleENPath)
	if err != nil {
		s.Log.Err(err).Msg("InitScanner createDefaultSensitiveRule")
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
			s.Log.Err(err).Interface("data", data).Msg("InitScanner createDefaultSensitiveRule")
		}
	}

	return nil
}

func (s *InitScanner) createSensitiveDBVersion(ctx context.Context) error {
	filter := imagesecModel.EmptyFilter().SetSortDesc().SetSortFiled("updated_at").SetLimit(1)
	rule, _, err := s.sensitiveRuleDal.SearchSensitiveRule(ctx, imagesecModel.SearchSensitiveRuleParam{Filter: filter})
	if err != nil {
		return err
	}
	if len(rule) == 0 {
		return fmt.Errorf("not find sensitive rule")
	}
	data := &imagesecModel.ScanConfigDB{
		DBVersion: fmt.Sprintf("%d", rule[0].UpdatedAt),
		DBType:    imagesecModel.SensitiveCacheData,
		Updater:   consts.DefaultAdminUser,
	}
	data.Serialize()
	meta, _, err := s.dbMetaDal.SearchScanDbMeta(ctx, imagesecModel.SearchScanDbParam{DBType: imagesecModel.SensitiveCacheData})
	if err != nil {
		return err
	}
	if len(meta) > 0 {
		update := map[string]interface{}{
			"db_version": fmt.Sprintf("%d", rule[0].UpdatedAt),
			"unique_id":  data.UniqueID,
		}
		return s.dbMetaDal.UpdateScanDbMeta(ctx, meta[0].ID, update)
	}

	return s.dbMetaDal.CreateScanDbMeta(ctx, data)
}

// 2.10版本数据迁移
func (s *InitScanner) createVer210DataMigrate(ctx context.Context) error {

	ver := os.Getenv("SOFT_VERSION")
	if !strings.HasPrefix(ver, consts.ScannerVersion220) {
		return nil
	}
	data := &imagesecModel.DataMigrate{
		SoftVersion: ver,
		Model:       consts.DataMigrateModelImage,
	}
	if err := s.dataMigrateDal.CreateDataMigrate(ctx, data); err != nil {
		s.Log.Err(err).Str("SOFT_VERSION", ver).Msg("CreateDataMigrate")
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return nil
		}
		return err
	}
	return nil
}

func (s *InitScanner) createDetectPolicySnapshot(ctx context.Context) error {
	policy1, _, err := s.detectPolicyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{
		Filed: []string{"id", "unique_id"},
	})
	if err != nil {
		s.Log.Err(err).Msg("MigratePolicy SearchDetectPolicy")
		return err
	}

	policy2, err := s.detectPolicyDal.SearchDetectPolicySnapshot(ctx, imagesecModel.SearchSecurityPolicyParam{
		Filed: []string{"id", "unique_id"},
	})
	if err != nil {
		s.Log.Err(err).Msg("MigratePolicy SearchDetectPolicy")
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
			s.Log.Err(err).Msg("MigratePolicy SearchDetectPolicy")
			return err
		}
		if len(pol) == 0 {
			continue
		}

		po := pol[i]

		if err := s.detectPolicyDal.CreateDetectPolicySnapshot(ctx, po); err != nil {
			if !strings.Contains(err.Error(), consts.DuplicateKey) {
				s.Log.Err(err).Msg("MigratePolicy CreateDetectPolicySnapshot")
				continue
			}
		}
	}
	return nil
}

// FIXME 2.21版本进行优化，使用临时目录进行管理
func (s *InitScanner) removeImagescanDir(ctx context.Context) error {
	_, err := os.Stat("/Imagescan")
	if err != nil {
		return nil
	}
	if err := os.RemoveAll("/Imagescan"); err != nil {
		s.Log.Err(err).Msg("RemoveAll Imagescan")
		return err
	}
	return nil
}

func NewInitScanner(db *databases.RDBInstance) *InitScanner {
	imageConfigDal := imagesecStore.NewScanImageConfigDao(db)
	detectPolicyDal := imagesecStore.NewDetectPolicyDao(db)
	sensitiveRuleDal := imagesecStore.NewSensitiveRuleDao(db)
	dataMigrateDal := imagesecStore.NewDataMigrateDao(db)
	scanResultDal := imagesecStore.NewScanResultDao(db)
	dbMetaDal := imagesecStore.NewScanDbMetaDao(db)

	return &InitScanner{
		imageConfigDal:   imageConfigDal,
		detectPolicyDal:  detectPolicyDal,
		sensitiveRuleDal: sensitiveRuleDal,
		dataMigrateDal:   dataMigrateDal,
		scanResultDal:    scanResultDal,
		dbMetaDal:        dbMetaDal,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithModule(consts.ModulePreInit)),
	}
}
