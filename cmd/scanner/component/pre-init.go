package component

import (
	"context"
	"errors"
	"os"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type InitScannerInterface interface {
	CreateCicdBufRegistry(ctx context.Context) error
}

type InitScanner struct {
	regDal store.RegistryDaoInterface
}

func (s *InitScanner) CreateCicdBufRegistry(ctx context.Context) error {
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
		UseType:        model.RegistryUseTypeBuff,
	}
	// 先查一下,可能已经存在
	registries, _, err := s.regDal.SearchRegistry(ctx, store.SearchRegistryParam{
		UseType:  model.RegistryUseTypeBuff,
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
			"use_type": model.RegistryUseTypeBuff,
		}
		if err := s.regDal.UpdateRegistry(ctx, store.SearchRegistryParam{Id: registries[0].ID}, updater); err != nil {
			logging.GetLogger().Error().Err(err).Msg("when initializing the buff registry, the encryption password error occurred")
			return err
		}
	}
	return nil
}

func NewInitScanner(regDal store.RegistryDaoInterface) *InitScanner {
	return &InitScanner{regDal: regDal}
}
