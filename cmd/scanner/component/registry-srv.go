package component

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/docker"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/harborv1"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/harborv2"
	hwswr "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/hw-swr"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type RegistrySrvInterface interface {
	CreateRegistry(ctx context.Context, reg model.Registry) (int64, error)
	UpdateRegistry(ctx context.Context, id int64, reg model.Registry) error
	DeleteRegistry(ctx context.Context, id int64) error
	SearchRegistry(ctx context.Context, param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error)
	GetRegistry(ctx context.Context, id int64) (*model.Registry, error)
	GetRegistryType(ctx context.Context) ([]string, error)
}
type RegistrySrv struct {
	RegistryDal store.RegistryDaoInterface
}

type SearchRegistryParam struct {
	UseType   int64
	Search    string
	RegType   []string
	HasDelete bool
}

func (s *RegistrySrv) GetRegistryType(ctx context.Context) ([]string, error) {
	res := make([]string, 0)
	res = append(res, docker.Version, harborv2.HarborVersion, harborv1.HarborVersion, hwswr.Version)
	return res, nil
}

func (s *RegistrySrv) GetRegistry(ctx context.Context, id int64) (*model.Registry, error) {
	registries, _, err := s.RegistryDal.SearchRegistry(ctx, store.SearchRegistryParam{Id: id, NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("ListRegistry SearchRegistry error %s", err.Error())
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("获取仓库信息出错"))
	}
	if len(registries) == 0 {
		return nil, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not fond the registry id :%d", id))
	}
	return &registries[0], nil
}

func (s *RegistrySrv) SearchRegistry(ctx context.Context, param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error) {
	registries, cnt, err := s.RegistryDal.SearchRegistry(ctx, store.SearchRegistryParam{UseType: param.UseType, Search: param.Search, RegType: param.RegType, NoDelete: true}, filter)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchRegistry")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("获取仓库列表出错"))
	}
	return registries, cnt, nil
}

func (s *RegistrySrv) DeleteRegistry(ctx context.Context, id int64) error {
	if id <= 0 {
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("请传入要删除仓库的ID"))
	}
	update := make(map[string]interface{})
	update["deleted_at"] = time.Now().Unix()
	err := s.RegistryDal.UpdateRegistry(ctx, store.SearchRegistryParam{Id: id}, update)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("DeleteRegistry")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("删除仓库出错"))
	}
	return nil
}

func (s *RegistrySrv) CreateRegistry(ctx context.Context, reg model.Registry) (int64, error) {
	if err := validateRegistry(reg, consts.ValidateCreate); err != nil {
		return 0, response.NewHttpError(http.StatusExpectationFailed, err)
	}
	if err := PingRegistry(reg); err != nil {
		logging.GetLogger().Error().Err(err).Msg("尝试连接到仓库出错")
		return 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("尝试连接到仓库出错,请核对信息后重新提交"))
	}

	id, err := s.RegistryDal.CreateRegistry(ctx, reg)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("CreateRegistry")
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return 0, response.NewHttpError(http.StatusFailedDependency, fmt.Errorf("仓库名已存在"))
		}
		return 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	return id, nil
}

func (s *RegistrySrv) UpdateRegistry(ctx context.Context, id int64, reg model.Registry) error {
	if id <= 0 {
		return response.NewHttpError(http.StatusExpectationFailed, fmt.Errorf("请传入要更新仓库的ID"))
	}
	registries, _, err := s.RegistryDal.SearchRegistry(ctx, store.SearchRegistryParam{Id: id, NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("UpdateRegistry.SearchRegistry")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	if len(registries) == 0 {
		return response.NewHttpError(http.StatusExpectationFailed, fmt.Errorf("not find the registry:%d", id))
	}

	reg.RegType = registries[0].RegType
	reg.Url = registries[0].Url

	if err := validateRegistry(reg, consts.ValidateUpdate); err != nil {
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}

	if err := PingRegistry(reg); err != nil {
		logging.GetLogger().Error().Err(err).Msg("尝试连接到仓库出错")
		return response.NewHttpError(http.StatusBadGateway, fmt.Errorf("尝试连接到仓库出错,请核对信息后重新提交"))
	}
	updater := registryToUpdater(reg)
	if reg.PasswordString != "" {
		encryPass, err := util.DesEncrypt([]byte(reg.PasswordString), []byte(consts.EncryptPasswordKey))
		if err != nil {
			return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("加密密码出错：%s", err.Error()))
		}
		updater["password"] = encryPass
	}

	err = s.RegistryDal.UpdateRegistry(ctx, store.SearchRegistryParam{Id: id}, updater)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("CreateRegistry")
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return response.NewHttpError(http.StatusFailedDependency, fmt.Errorf("仓库名已存在"))
		}
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	return nil
}

func NewRegistrySrv(dal store.RegistryDaoInterface) *RegistrySrv {
	return &RegistrySrv{RegistryDal: dal}
}
