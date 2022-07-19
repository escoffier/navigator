package component

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
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
	GetRegistryType(ctx context.Context) ([]model.LabelValue, error)
}
type RegistrySrv struct {
	registryDal   store.RegistryDal
	scanConfigDal store.ScanConfigDal
}

type SearchRegistryParam struct {
	UseType int64
	Search  string
	RegType []string
	Name    string
	Ids     []int64
}

func (s *RegistrySrv) GetRegistryType(ctx context.Context) ([]model.LabelValue, error) {
	ans := make([]model.LabelValue, 0)
	reg := model.GetRegType()
	for k := range reg {
		ans = append(ans, reg[k])
	}
	return ans, nil
}

func (s *RegistrySrv) SearchRegistry(ctx context.Context, param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error) {

	daoParam := store.SearchRegistryParam{RegistryIds: param.Ids, Name: param.Name, UseType: param.UseType, Search: param.Search, RegType: param.RegType, NoDelete: true}
	daoParam.Compatible()
	registries, cnt, err := s.registryDal.SearchRegistry(ctx, daoParam, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchRegistry")
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
	err := s.registryDal.UpdateRegistry(ctx, store.SearchRegistryParam{ID: id}, update)
	if err != nil {
		logging.GetLogger().Err(err).Msg("DeleteRegistry")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("删除仓库出错"))
	}
	// 删除了仓库，仓库所对应的扫描配置也要删除
	configs, _, err := s.scanConfigDal.SearchScanConfig(ctx, store.SearchScanConfigParam{}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchScanConfig")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("删除仓库出错后，同步更新扫描配置出错"))
	}
	for i := range configs {
		config := configs[i]
		libConfig := config.LibraryImageConfig
		if libConfig != nil {
			libs := make([]int64, 0)
			for j := range libConfig.Libraries {
				if libConfig.Libraries[j] != id {
					libs = append(libs, libConfig.Libraries[j])
				}
			}

			config.LibraryImageConfig.Libraries = libs
			config.Serialize()
			updater := config.ToUpdater()

			if err := s.scanConfigDal.UpdateScanConfig(ctx, config.ID, updater); err != nil {
				logging.GetLogger().Err(err).Int64("configId", config.ID).Msg("UpdateScanConfig")
			}
		}
	}

	return nil
}

func (s *RegistrySrv) createRegistry(ctx context.Context, reg model.Registry) (int64, error) {
	if err := reg.Validate(consts.ValidateCreate); err != nil {
		return 0, response.NewHttpError(http.StatusExpectationFailed, err)
	}

	if err := validateRegistryType(reg.RegType); err != nil {
		return 0, response.NewHttpError(http.StatusExpectationFailed, err)
	}

	drive, err := registry.Open(RegToRegistryConf(reg))
	if err != nil {
		logging.GetLogger().Err(err).Msg("尝试连接到仓库出错")
		switch err {
		case consts.ErrAccessKeyOrAccessSecret, consts.ErrNotConnectOrWrongUsernameOrPasswd:
			return 0, response.NewHttpError(http.StatusBadRequest, err)
		default:
			return 0, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("尝试连接到仓库出错,请核对信息后重新提交,错误信息:%s", err.Error()))
		}
	}
	if err := drive.Ping(); err != nil {
		logging.GetLogger().Err(err).Msg("尝试连接到仓库出错")
		switch err {
		case consts.ErrAccessKeyOrAccessSecret, consts.ErrNotConnectOrWrongUsernameOrPasswd:
			return 0, response.NewHttpError(http.StatusBadRequest, err)
		default:
			return 0, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("尝试连接到仓库出错,请核对信息后重新提交,错误信息:%s", err.Error()))
		}
	}

	id, err := s.registryDal.CreateRegistry(ctx, reg)
	if err != nil {
		logging.GetLogger().Err(err).Msg("CreateRegistry")
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return 0, response.NewHttpError(http.StatusFailedDependency, fmt.Errorf("仓库名已存在"))
		}
		return 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	return id, nil

}

func (s *RegistrySrv) CreateRegistry(ctx context.Context, reg model.Registry) (int64, error) {
	if !InStringSlice(reg.RegType, []string{consts.HarborVersion, consts.HarborV1Version, consts.HarborV2Version}) {
		return s.createRegistry(ctx, reg)
	}
	// 对于harbor做一下兼容
	// 先试v2
	reg.RegType = consts.HarborV2Version
	id, err := s.createRegistry(ctx, reg)
	if err != nil {
		// 再试v1
		reg.RegType = consts.HarborV1Version
		return s.createRegistry(ctx, reg)
	}
	return id, nil
}

func (s *RegistrySrv) UpdateRegistry(ctx context.Context, id int64, reg model.Registry) error {
	if id <= 0 {
		return response.NewHttpError(http.StatusExpectationFailed, fmt.Errorf("请传入要更新仓库的ID"))
	}
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{ID: id, NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("UpdateRegistry.SearchRegistry")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	if len(registries) == 0 {
		return response.NewHttpError(http.StatusExpectationFailed, fmt.Errorf("not find the registry:%d", id))
	}

	reg.RegType = registries[0].RegType
	reg.Url = registries[0].Url

	if err := reg.Validate(consts.ValidateUpdate); err != nil {
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}

	drive, err := registry.Open(RegToRegistryConf(reg))

	if err != nil {
		logging.GetLogger().Err(err).Msg("尝试连接到仓库出错")
		switch err {
		case consts.ErrAccessKeyOrAccessSecret, consts.ErrNotConnectOrWrongUsernameOrPasswd:
			return response.NewHttpError(http.StatusBadRequest, err)
		default:
			return response.NewHttpError(http.StatusBadRequest, fmt.Errorf("尝试连接到仓库出错,请核对信息后重新提交,错误信息:%s", err.Error()))
		}
	}
	if err := drive.Ping(); err != nil {
		logging.GetLogger().Err(err).Msg("尝试连接到仓库出错")
		switch err {
		case consts.ErrAccessKeyOrAccessSecret, consts.ErrNotConnectOrWrongUsernameOrPasswd:
			return response.NewHttpError(http.StatusBadRequest, err)
		default:
			return response.NewHttpError(http.StatusBadRequest, fmt.Errorf("尝试连接到仓库出错,请核对信息后重新提交,错误信息:%s", err.Error()))
		}
	}

	updater := registryToUpdater(reg)
	if reg.PasswordString != "" {
		encryPass, err := util.DesEncrypt([]byte(reg.PasswordString), []byte(consts.EncryptPasswordKey))
		if err != nil {
			return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("加密密码出错：%s", err.Error()))
		}
		updater["password"] = encryPass
	}

	err = s.registryDal.UpdateRegistry(ctx, store.SearchRegistryParam{ID: id}, updater)
	if err != nil {
		logging.GetLogger().Err(err).Msg("CreateRegistry")
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return response.NewHttpError(http.StatusFailedDependency, fmt.Errorf("仓库名已存在"))
		}
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	return nil
}

func NewRegistrySrv(registryDal store.RegistryDal, scanConfigDal store.ScanConfigDal) *RegistrySrv {
	return &RegistrySrv{registryDal: registryDal, scanConfigDal: scanConfigDal}
}

func validateRegistryType(regType string) error {
	if !InStringSlice(regType, registry.DriverTypes) {
		return errors.New("registry type is illegal")
	}
	return nil
}
