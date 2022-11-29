package component

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"

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
	CheckHealth(ctx context.Context, scannerInstance string) error
}

type RegistrySrv struct {
	registryDal   store.RegistryDal
	syncTaskDal   store.SyncTaskDal
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

func (s *RegistrySrv) CreateRegistry(ctx context.Context, reg model.Registry) (int64, error) {
	if reg.ScannerInstance == "" {
		// 设置默认:当前集群（openapi接口还不支持多集群）
		reg.ScannerInstance = global.ScannerInstance
	}
	// 新建时不能验证仓库配置是否正确,所以直接新建
	if err := reg.Validate(consts.ValidateCreate); err != nil {
		return 0, response.NewHttpError(http.StatusExpectationFailed, err)
	}

	if err := validateRegistryType(reg.RegType); err != nil {
		return 0, response.NewHttpError(http.StatusExpectationFailed, err)
	}

	id, err := s.registryDal.CreateRegistry(ctx, reg)
	if err != nil {
		logging.GetLogger().Err(err).Msg("CreateRegistry")
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return 0, response.NewHttpError(http.StatusFailedDependency, fmt.Errorf("仓库名已存在"))
		}
		return 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	// 新增加的仓库需要自动同步,但是对于harbor的仓库，需要在等一次健康检查之后才能确定版本类型,
	// 这里使用一种取巧的方式，直接休眠3分钟，后期镜像同步重构之后再优化
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.GetLogger().Error().Msg("CreateRegistry recover")
			}
		}()
		ticker := time.NewTicker(time.Minute * 3)
		defer ticker.Stop()
		<-ticker.C

		syncTask := &model.SyncTask{RegistryID: id, SyncType: consts.CycleFullSync.String()}
		if err := s.syncTaskDal.CreateSyncTask(ctx, syncTask); err != nil {
			logging.GetLogger().Err(err).Int64("regID", id).Msg("createRegistry CreateSyncTask")
		}
	}()

	return id, nil
}

func (s *RegistrySrv) checkHealth(ctx context.Context, reg model.Registry) (string, error) {
	drive, err := registry.Open(RegToRegistryConf(reg))
	if err != nil {
		logging.GetLogger().Err(err).Msg("CheckHealth Open 尝试连接到仓库出错")
		return consts.RegAbnormal, err
	}
	if err := drive.Ping(); err != nil {
		logging.GetLogger().Err(err).Msg("CheckHealth 尝试连接到仓库出错")
		return consts.RegAbnormal, err
	}
	return consts.RegNormal, nil
}

func (s *RegistrySrv) CheckHealth(ctx context.Context, scannerInstance string) error {
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{ScannerInstance: scannerInstance, NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("RegistrySrv CheckHealth")
		return err
	}

	for i := range registries {
		reg := registries[i]

		var health string
		var err error
		regType := reg.RegType

		if reg.RegType == consts.HarborVersion {
			// 先试V2
			reg.RegType = consts.HarborV2Version
			regType = consts.HarborV2Version
			health, err = s.checkHealth(ctx, reg)
			if health == consts.RegAbnormal {
				regType = consts.HarborV1Version
				reg.RegType = consts.HarborV1Version
				health, err = s.checkHealth(ctx, reg)
			}
		} else {
			health, err = s.checkHealth(ctx, reg)
		}

		if health == consts.RegNormal {
			reg.RegType = regType
		}

		update := map[string]interface{}{"status": health, "reg_type": reg.RegType, "heat_beat": time.Now().UnixMilli()}
		if err != nil {
			logging.GetLogger().Err(err).Msg("RegistrySrv CheckHealth")
			update["health_msg"] = err.Error()
		}

		if reg.Status != health || reg.RegType != regType {
			if err := s.registryDal.UpdateRegistry(ctx, store.SearchRegistryParam{ID: reg.ID}, update); err != nil {
				logging.GetLogger().Err(err).Msg("RegistrySrv CheckHealth")
				continue
			}
		}
	}

	return nil
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
	// reg.ScannerInstance = registries[0].ScannerInstance

	if err := reg.Validate(consts.ValidateUpdate); err != nil {
		return response.NewHttpError(http.StatusExpectationFailed, err)
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

func NewRegistrySrv(registryDal store.RegistryDal, scanConfigDal store.ScanConfigDal, syncTaskDal store.SyncTaskDal) *RegistrySrv {
	return &RegistrySrv{registryDal: registryDal, scanConfigDal: scanConfigDal, syncTaskDal: syncTaskDal}
}

func validateRegistryType(regType string) error {
	regTypes := append([]string{consts.HarborVersion}, registry.DriverTypes...)
	if !InStringSlice(regType, regTypes) {
		return errors.New("registry type is illegal")
	}
	return nil
}
