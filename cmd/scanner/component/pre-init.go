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
	Init(ctx context.Context) error
}

type InitScanner struct {
	regDal        store.RegistryDalInterface
	imageDal      store.ScannerDalInterface
	ScanConfigDAl store.ScanConfigDalInterface
}

func (s *InitScanner) Init(ctx context.Context) error {
	if err := s.createCicdBufRegistry(ctx); err != nil {
		return err
	}
	if err := s.createGlobalPolicy(ctx); err != nil {
		return err
	}
	if err := s.createSafeNodeBufRegistry(ctx); err != nil {
		return err
	}
	// 一次要在写入默认策略前写入全局配置
	if err := s.createDefaultScanStrategy(ctx); err != nil {
		return err
	}
	if err := s.createGlobalScanConfig(ctx); err != nil {
		return err
	}

	// if err := s.checkUniqueImage(ctx); err != nil {
	// 	return err
	// }
	// if err := s.checkUniqueVuln(ctx); err != nil {
	// 	return err
	// }
	return nil
}

func (s *InitScanner) createGlobalScanConfig(ctx context.Context) error {
	// 先查询默认策略
	strategies, _, err := s.ScanConfigDAl.SearchStrategy(ctx, store.SearchStrategyParam{IsDefault: consts.TrueString}, nil)
	if err != nil {
		return err
	}
	if len(strategies) == 0 {
		return fmt.Errorf("no default scan strategy")
	}

	// 先查一下
	config, _, err := s.ScanConfigDAl.SearchScanConfig(ctx, store.SearchScanConfigParam{}, nil)
	if err != nil {
		return err
	}
	if len(config) > 0 {
		return nil
	}

	defaultConfig := model.ScanConfigSinge{
		ImageAddTrigEnable: false,
		Libraries:          []int64{},
		ScanCycle:          []int64{},
		ScanTime:           "",
		ScanAll:            false,
		StrategyID:         strategies[0].ID,
	}

	bys, err := json.Marshal(defaultConfig)
	if err != nil {
		return err
	}

	data := model.ScanConfig{
		VulnFlushTrigEnable:      false,
		MaliciousFlushTrigEnable: false,
		LibraryImageJson:         string(bys),
		NodeImageJson:            string(bys),
	}
	return s.ScanConfigDAl.CreateScanConfig(ctx, &data)
}

func (s *InitScanner) createDefaultScanStrategy(ctx context.Context) error {
	// 先查一下
	strategy, _, err := s.ScanConfigDAl.SearchStrategy(ctx, store.SearchStrategyParam{IsDefault: consts.TrueString}, nil)
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

		SensitiveEnable: true,
		VulEnable:       true,
		WebshellEnable:  false, // default disable webshell scan
		MaliciousEnable: true,
	}
	return s.ScanConfigDAl.CreateStrategy(ctx, &data)
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
		UseType:        model.RegistryUseTypeCICDBuff,
		SyncInterval:   consts.RegistryDefaultSyncInterval,
	}
	// 先查一下,可能已经存在
	registries, _, err := s.regDal.SearchRegistry(ctx, store.SearchRegistryParam{
		UseType:  model.RegistryUseTypeCICDBuff,
		NoDelete: true,
	}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("when initializing the buff registry, query error occurred")
		return err
	}
	if len(registries) == 0 {
		if _, err = s.regDal.CreateRegistry(ctx, data); err != nil {
			logging.GetLogger().Error().Err(err).Msg("when initializing the buff registry,create data error")
			return err
		}
	} else {
		encryPass, err := util.DesEncrypt([]byte(passwd), []byte(consts.EncryptPasswordKey))
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("when initializing the buff registry, the encryption password error occurred")
			return err
		}

		updater := map[string]interface{}{
			"reg_type": "registry-v2",
			"url":      url,
			"username": username,
			"password": encryPass,
			"use_type": model.RegistryUseTypeCICDBuff,
		}
		if err := s.regDal.UpdateRegistry(ctx, store.SearchRegistryParam{ID: registries[0].ID}, updater); err != nil {
			logging.GetLogger().Error().Err(err).Msg("when initializing the buff registry, the encryption password error occurred")
			return err
		}
	}
	return nil
}

func (s *InitScanner) createSafeNodeBufRegistry(ctx context.Context) error {
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
		Name:           "safe-node-buf-registry",
		RegType:        "registry-v2",
		Url:            url,
		Username:       username,
		PasswordString: passwd,
		Description:    "节点镜像中转仓库",
		UseType:        model.RegistryUseSafeNode,
		SyncInterval:   inter1,
	}
	// 先查一下,可能已经存在
	registries, _, err := s.regDal.SearchRegistry(ctx, store.SearchRegistryParam{
		UseType:  model.RegistryUseSafeNode,
		NoDelete: true,
	}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("when initializing the buff registry, query error occurred")
		return err
	}
	if len(registries) == 0 {
		if _, err = s.regDal.CreateRegistry(ctx, data); err != nil {
			logging.GetLogger().Error().Err(err).Msg("when initializing the buff registry,create data error")
			return err
		}
	} else {
		encryPass, err := util.DesEncrypt([]byte(passwd), []byte(consts.EncryptPasswordKey))
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("when initializing the buff registry, the encryption password error occurred")
			return err
		}

		updater := map[string]interface{}{
			"reg_type": "registry-v2",
			"url":      url,
			"username": username,
			"password": encryPass,
			"use_type": model.RegistryUseSafeNode,
		}
		if err := s.regDal.UpdateRegistry(ctx, store.SearchRegistryParam{ID: registries[0].ID}, updater); err != nil {
			logging.GetLogger().Error().Err(err).Msg("when initializing the buff registry, the encryption password error occurred")
			return err
		}
	}
	return nil
}

func (s *InitScanner) createGlobalPolicy(ctx context.Context) error {
	policies, err := s.imageDal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.TrueString})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("InitScanner.createGlobalPolicy")
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
			logging.GetLogger().Error().Err(err).Msg("InitScanner.CreateGlobalPolicy")
			return err
		}

		updater := GlobalRejectPolicyToUpdater(global)

		if err := s.imageDal.UpdateGlobalPolicy(ctx, updater); err != nil {
			logging.GetLogger().Error().Err(err).Msg("InitScanner.CreateGlobalPolicy")
			return err
		}
	}
	return nil
}

func (s *InitScanner) checkUniqueImage(ctx context.Context) error {
	var lastID int64
	for {
		param := store.SearchImageParam{Where: fmt.Sprintf("(unique_image is null OR unique_image = 0 ) AND id > %d", lastID)}
		param.OmitFields = param.GetDefaultOmitFields()
		images, _, err := s.imageDal.SearchImage(ctx, param, &model.Filter{Limit: consts.DefaultBathSize, SortBy: consts.SortByAsc, SortFiled: "id"})
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("InitScanner.checkUniqueImage")
			return err
		}
		logging.GetLogger().Info().Int("vuln", len(images)).Msg("初始化时写入uniqueImage")
		if len(images) == 0 {
			break
		}
		lastID = images[len(images)-1].ID
		for _, image := range images {
			uniqueImage := image.GenUniqueImage()
			updater := map[string]interface{}{"unique_image": uniqueImage}
			where := fmt.Sprintf("id = %d", image.ID)
			if err := s.imageDal.UpdateImage(ctx, where, updater, nil); err != nil {
				logging.GetLogger().Error().Err(err).Int64("ImageID", image.ID).Msg("InitScanner.checkUniqueImage")
				return err
			}
		}
	}
	return nil
}

func (s *InitScanner) checkUniqueVuln(ctx context.Context) error {
	var lastID int64
	for {
		param := store.SearchVulnParm{Where: fmt.Sprintf("(unique_vuln is null OR unique_vuln = 0 ) AND id > %d", lastID)}
		vulus, _, err := s.imageDal.SearchVuln(ctx, param, &model.Filter{Limit: consts.DefaultBathSize, SortBy: consts.SortByAsc, SortFiled: "id"})
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("InitScanner.checkUniqueImage")
			return err
		}

		logging.GetLogger().Info().Int("vuln", len(vulus)).Msg("初始化时写入uniqueVuln")
		if len(vulus) == 0 {
			break
		}
		lastID = vulus[len(vulus)-1].ID
		for _, vu := range vulus {
			uniqueVuln := vu.GenUniqueVuln()
			updater := map[string]interface{}{"unique_vuln": uniqueVuln}
			where := fmt.Sprintf("id = %d", vu.ID)
			if err := s.imageDal.UpdateVuln(ctx, where, updater, nil); err != nil {
				if strings.Contains(err.Error(), consts.DuplicateKey) {
					logging.GetLogger().Error().Err(err).Int64("vulnID", vu.ID).Str("vuln", fmt.Sprintf("%s-%s-%s", vu.Name, vu.PkgName, vu.PkgVersion)).Uint64("UniqueVuln", uniqueVuln).Msg("InitScanner.checkUniqueVuln")
					continue
				}
				logging.GetLogger().Error().Err(err).Int64("vulnID", vu.ID).Msg("InitScanner.checkUniqueVuln")
				return err
			}
		}
	}
	return nil
}

func NewInitScanner(regDal store.RegistryDalInterface, imageDal store.ScannerDalInterface, scanConfigDAl store.ScanConfigDalInterface) *InitScanner {
	return &InitScanner{regDal: regDal, imageDal: imageDal, ScanConfigDAl: scanConfigDAl}
}
