package component

import (
	"context"
	"errors"
	"os"
	"strconv"

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
	regDal   store.RegistryDaoInterface
	imageDal store.ScannerDalInterface
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
	return nil
}

func (s *InitScanner) createCicdBufRegistry(ctx context.Context) error {
	url := os.Getenv("CICD-BUF-REGISTRY-URL")
	username := os.Getenv("CICD-BUF-REGISTRY-USER")
	passwd := os.Getenv("CICD-BUF-REGISTRY-PASSWORD")
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
		if err := s.regDal.UpdateRegistry(ctx, store.SearchRegistryParam{Id: registries[0].ID}, updater); err != nil {
			logging.GetLogger().Error().Err(err).Msg("when initializing the buff registry, the encryption password error occurred")
			return err
		}
	}
	return nil
}

func (s *InitScanner) createSafeNodeBufRegistry(ctx context.Context) error {
	url := os.Getenv("SAFENODE-BUF-REGISTRY-URL")
	username := os.Getenv("SAFENODE-BUF-REGISTRY-USER")
	passwd := os.Getenv("SAFENODE-BUF-REGISTRY-PASSWORD")
	inter := os.Getenv("SAFENODE-BUF-INTERNA")
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
		if err := s.regDal.UpdateRegistry(ctx, store.SearchRegistryParam{Id: registries[0].ID}, updater); err != nil {
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

func NewInitScanner(regDal store.RegistryDaoInterface, imageDal store.ScannerDalInterface) *InitScanner {
	return &InitScanner{regDal: regDal, imageDal: imageDal}
}
