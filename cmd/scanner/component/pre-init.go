package component

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type InitScannerInterface interface {
	Init(ctx context.Context, scannerLocalID string) error
}

type InitScanner struct {
	regDal        store.RegistryDal
	imageDal      store.ScannerDalInterface
	vulnDal       store.VulnDalInterface
	scanConfigDal store.ScanConfigDal
}

func (s *InitScanner) Init(ctx context.Context, scannerInstance string) error {
	if err := s.createGlobalPolicy(ctx); err != nil {
		return err
	}
	safeNodeEnbale := os.Getenv("SAFENODE_ENABLE")
	if strings.Trim(safeNodeEnbale, " ") == consts.TrueString {
		if err := s.createSafeNodeBufRegistry(ctx, scannerInstance); err != nil {
			return err
		}
	}
	// 一次要在写入默认策略前写入全局配置
	if err := s.createDefaultScanStrategy(ctx); err != nil {
		return err
	}
	if err := s.createGlobalScanConfig(ctx); err != nil {
		return err
	}

	// 写入当前集群中的scanner信息
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
		Name:      "默认扫描策略",
		Describe:  "系统创建",
		Operator:  "系统创建",
		IsDefault: true,

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

func (s *InitScanner) createCicdBufRegistry(ctx context.Context) error {
	url := os.Getenv("BUF_REGISTRY_URL")
	username := os.Getenv("BUF_REGISTRY_USER")
	passwd := os.Getenv("BUF_REGISTRY_PASSWORD")
	if url == "" || username == "" || passwd == "" {
		return errors.New("cicd buf registry not setting")
	}
	data := model.Registry{
		Name:           "cicd-buf-registry",
		RegType:        "registry-v2",
		Url:            url,
		Username:       username,
		PasswordString: passwd,
		Description:    "cicd中转仓库",
		UseType:        model.CICDImageRegistry,
		SyncInterval:   consts.RegistryDefaultSyncInterval,
	}
	// 先查一下,可能已经存在
	registries, _, err := s.regDal.SearchRegistry(ctx, store.SearchRegistryParam{
		UseType: model.CICDImageRegistry,
		Deleted: consts.FalseString,
	}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("when initializing the buff registry, query error occurred")
		return err
	}
	if len(registries) == 0 {
		if _, err = s.regDal.CreateRegistry(ctx, data); err != nil {
			logging.GetLogger().Err(err).Msg("when initializing the buff registry,create data error")
			return err
		}
	} else {
		encryPass, err := util.DesEncrypt([]byte(passwd), []byte(consts.EncryptPasswordKey))
		if err != nil {
			logging.GetLogger().Err(err).Msg("when initializing the buff registry, the encryption password error occurred")
			return err
		}

		updater := map[string]interface{}{
			"reg_type": "registry-v2",
			"url":      url,
			"username": username,
			"password": encryPass,
			"use_type": model.CICDImageRegistry,
		}
		if err := s.regDal.UpdateRegistry(ctx, store.SearchRegistryParam{ID: registries[0].ID}, updater); err != nil {
			logging.GetLogger().Err(err).Msg("when initializing the buff registry, the encryption password error occurred")
			return err
		}
	}
	return nil
}

func (s *InitScanner) createSafeNodeBufRegistry(ctx context.Context, scannerInstance string) error {
	url := os.Getenv("BUF_REGISTRY_URL")
	username := os.Getenv("BUF_REGISTRY_USER")
	passwd := os.Getenv("BUF_REGISTRY_PASSWORD")
	inter := os.Getenv("BUF_INTERNA")
	inter1, err := strconv.ParseInt(inter, 10, 64)
	if err != nil {
		inter1 = consts.RegistryDefaultSyncInterval
	}

	if url == "" || username == "" || passwd == "" {
		return errors.New("safe node buf registry not setting")
	}
	data := model.Registry{
		Name:            "safe-node-buf-registry",
		RegType:         "registry-v2",
		Url:             url,
		Username:        username,
		PasswordString:  passwd,
		Description:     "节点镜像中转仓库",
		UseType:         model.NodeBuffRegistry,
		SyncInterval:    inter1,
		ScannerInstance: scannerInstance,
	}
	// 先查一下,可能已经存在
	registries, _, err := s.regDal.SearchRegistry(ctx, store.SearchRegistryParam{
		UseType: model.NodeBuffRegistry,
		Deleted: consts.FalseString,
	}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("when initializing the buff registry, query error occurred")
		return err
	}
	if len(registries) == 0 {
		if _, err = s.regDal.CreateRegistry(ctx, data); err != nil {
			logging.GetLogger().Err(err).Msg("when initializing the buff registry,create data error")
			return err
		}
	} else {
		encryPass, err := util.DesEncrypt([]byte(passwd), []byte(consts.EncryptPasswordKey))
		if err != nil {
			logging.GetLogger().Err(err).Msg("when initializing the buff registry, the encryption password error occurred")
			return err
		}

		updater := map[string]interface{}{
			"reg_type": "registry-v2",
			"url":      url,
			"username": username,
			"password": encryPass,
			"use_type": model.NodeBuffRegistry,
		}
		if err := s.regDal.UpdateRegistry(ctx, store.SearchRegistryParam{ID: registries[0].ID}, updater); err != nil {
			logging.GetLogger().Err(err).Msg("when initializing the buff registry, the encryption password error occurred")
			return err
		}
	}
	return nil
}

func (s *InitScanner) createGlobalPolicy(ctx context.Context) error {
	policies, err := s.imageDal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.TrueString})
	if err != nil {
		logging.GetLogger().Err(err).Msg("InitScanner.createGlobalPolicy")
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
			logging.GetLogger().Err(err).Msg("InitScanner.CreateGlobalPolicy")
			return err
		}

		updater := GlobalRejectPolicyToUpdater(global)

		if err := s.imageDal.UpdateGlobalPolicy(ctx, updater); err != nil {
			logging.GetLogger().Err(err).Msg("InitScanner.CreateGlobalPolicy")
			return err
		}
	}
	return nil
}

func NewInitScanner(regDal store.RegistryDal,
	imageDal store.ScannerDalInterface,
	scanConfigDAl store.ScanConfigDal,
	vulnDal store.VulnDalInterface,
) *InitScanner {
	return &InitScanner{regDal: regDal, imageDal: imageDal, scanConfigDal: scanConfigDAl, vulnDal: vulnDal}
}
