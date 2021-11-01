package component

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type SearchStrategyParam struct {
	IsDefault  string
	StrategyID int64
}
type SearchScanConfigParam struct {
	ScanConfigID int64
}

type SearchSoftWareParam struct {
	StrategyID int64
}

type ScanConfigSrvInterface interface {
	CreateStrategy(ctx context.Context, data *model.ScanStrategy) error
	SearchStrategy(ctx context.Context, parm SearchStrategyParam, filter *model.Filter) ([]model.ScanStrategy, int64, error)
	UpdateStrategy(ctx context.Context, strategyId int64, data *model.ScanStrategy) error
	DeleteStrategy(ctx context.Context, strategyId int64) error
	UpdateScanConfig(ctx context.Context, configID int64, data *model.ScanConfig) error
	SearchScanConfig(ctx context.Context, parm SearchScanConfigParam, filter *model.Filter) ([]model.ScanConfig, int64, error)

	GetAllNodes(ctx context.Context) ([]string, error)
	AddTaskByStrategy(ctx context.Context) error
	GetAllProject(ctx context.Context) ([]string, error)
	GetAllRepoName(ctx context.Context) ([]string, error)
}

type ScanConfigSrv struct {
	ScanConfigDal store.ScanConfigDalInterface
	RegistryDal   store.RegistryDalInterface
	ImageDal      store.ScannerDalInterface
	ScanTaskDal   store.ScanTaskInterface
}

func NewScanConfigSrv(scanConfigDAl store.ScanConfigDalInterface, registryDal store.RegistryDalInterface, imageDal store.ScannerDalInterface, scanTaskDal store.ScanTaskInterface) *ScanConfigSrv {
	return &ScanConfigSrv{ScanConfigDal: scanConfigDAl, RegistryDal: registryDal, ImageDal: imageDal, ScanTaskDal: scanTaskDal}
}

func (s *ScanConfigSrv) GetAllRepoName(ctx context.Context) ([]string, error) {
	nodes, err := s.ScanConfigDal.GetAllRepoName(ctx)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("GetAllRepoName")
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}
	return nodes, nil
}
func (s *ScanConfigSrv) GetAllProject(ctx context.Context) ([]string, error) {
	nodes, err := s.ScanConfigDal.GetAllProject(ctx)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("GetAllProject")
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}
	return nodes, nil
}
func (s *ScanConfigSrv) GetAllNodes(ctx context.Context) ([]string, error) {
	nodes, err := s.ScanConfigDal.GetAllNodes(ctx)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("GetAllNodes")
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}
	return nodes, nil
}

func (s *ScanConfigSrv) AddTaskByStrategy(ctx context.Context) error {

	ticker := time.NewTicker(time.Second * consts.CheckTaskInterval)

	for {
		<-ticker.C
		logging.GetLogger().Info().Msg("AddTaskByStrategy,check")

		configs, _, err := s.SearchScanConfig(ctx, SearchScanConfigParam{}, nil)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("AddTaskByStrategy")
			continue
		}
		if len(configs) == 0 {
			logging.GetLogger().Info().Msg("AddTaskByStrategy,not fond scan config")
			continue
		}
		config := configs[0]
		// 先加仓库镜像
		if err := s.addLibraryScanTask(ctx, config); err != nil {
			logging.GetLogger().Error().Err(err).Msg("AddTaskByStrategy,addLibraryScanTask failure")
			continue
		}

		// 再加节点镜像
		if err := s.addNodeScanTask(ctx, config); err != nil {
			logging.GetLogger().Error().Err(err).Msg("AddTaskByStrategy,addNodeScanTask failure")
			continue
		}
		ticker.Reset(time.Second * consts.CheckTaskInterval)
	}
}

func (s *ScanConfigSrv) SearchScanConfig(ctx context.Context, param SearchScanConfigParam, filter *model.Filter) ([]model.ScanConfig, int64, error) {
	config, cnt, err := s.ScanConfigDal.SearchScanConfig(ctx, store.SearchScanConfigParam{ScanConfigID: param.ScanConfigID}, filter)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchScanConfig")
		return nil, 0, err
	}
	return config, cnt, nil
}

func (s *ScanConfigSrv) SearchStrategy(ctx context.Context, param SearchStrategyParam, filter *model.Filter) ([]model.ScanStrategy, int64, error) {
	strategies, cnt, err := s.ScanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{StrategyID: param.StrategyID, IsDefault: param.IsDefault}, filter)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchStrategy")
		return nil, 0, err
	}
	return strategies, cnt, nil
}

func (s *ScanConfigSrv) CreateStrategy(ctx context.Context, data *model.ScanStrategy) error {
	if err := data.Check(); err != nil {
		logging.GetLogger().Error().Err(err).Msg("CreateStrategy")
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}
	data = data.Serialize()
	err := s.ScanConfigDal.CreateStrategy(ctx, data)
	if err != nil {
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("该策略已存在，请重新设置策略名"))
		}
		logging.GetLogger().Error().Err(err).Msg("CreateStrategy")
		return response.NewHttpError(http.StatusInternalServerError, err)
	}
	return nil
}

func (s *ScanConfigSrv) UpdateStrategy(ctx context.Context, strategyId int64, data *model.ScanStrategy) error {
	if err := data.Check(); err != nil {
		logging.GetLogger().Error().Err(err).Msg("CreateStrategy")
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}

	data = data.Serialize()

	updater := data.ToUpdater()

	err := s.ScanConfigDal.UpdateStrategy(ctx, store.SearchStrategyParam{StrategyID: strategyId, IsDefault: consts.FalseString}, updater)
	if err != nil {
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("该策略已存在，请重新设置策略名"))
		}
		logging.GetLogger().Error().Err(err).Msg("CreateStrategy")
		return response.NewHttpError(http.StatusInternalServerError, err)
	}
	return nil
}

func (s *ScanConfigSrv) DeleteStrategy(ctx context.Context, strategyId int64) error {
	// 删除之前先做检查，
	// 没有配置
	config, _, err := s.SearchScanConfig(ctx, SearchScanConfigParam{}, nil)
	if err != nil {
		return response.NewHttpError(http.StatusInternalServerError, err)
	}
	for i := range config {
		if config[i].LibraryImageConfig.StrategyId == strategyId {
			return fmt.Errorf("该策略已配置在扫描配置中，不能删除")
		}
		if config[i].NodeImageConfig.StrategyId == strategyId {
			return fmt.Errorf("该策略已配置在扫描配置中，不能删除")
		}
	}
	// 默认策略不能删除
	strategy, _, err := s.ScanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{IsDefault: consts.TrueString}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("search strategy err")
		return err
	}
	for i := range strategy {
		if strategy[i].ID == strategyId {
			return fmt.Errorf("该策略属于默认策略，不能删除")
		}
	}
	// 再看是否有该策略的扫描任务
	tasks, _, err := s.ScanTaskDal.GetTasks(ctx, store.SearchTaskParam{
		Statuses:   []int8{consts.Pending, consts.InProgress, consts.Pause},
		StrategyID: strategyId,
	}, nil)
	if err != nil {
		return response.NewHttpError(http.StatusInternalServerError, err)
	}
	if len(tasks) > 0 {
		return fmt.Errorf("该策略下还有未完成的扫描任务，不能删除")
	}
	if err := s.ScanConfigDal.DeleteStrategy(ctx, strategyId); err != nil {
		logging.GetLogger().Error().Err(err).Msgf("DeleteStrategy:%d", strategyId)
		return response.NewHttpError(http.StatusInternalServerError, err)
	}
	return nil
}

func (s *ScanConfigSrv) UpdateScanConfig(ctx context.Context, configID int64, data *model.ScanConfig) error {
	if err := data.Check(); err != nil {
		logging.GetLogger().Error().Err(err).Msg("UpdateScanConfig")
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}
	// 验证所传仓库是不是公司支持的仓库,验证所传策略ID是不是存在于数据库中(低频接口，直接循环了)
	if err := s.verifyLibrary(ctx, data.LibraryImageConfig.Libraries); err != nil {
		return err
	}
	if err := s.verifyLibrary(ctx, data.NodeImageConfig.Libraries); err != nil {
		return err
	}
	if err := s.verifyStrategyID(ctx, []int64{data.LibraryImageConfig.StrategyId}); err != nil {
		return err
	}
	if err := s.verifyStrategyID(ctx, []int64{data.NodeImageConfig.StrategyId}); err != nil {
		return err
	}

	data = data.Serialize()
	updater := data.ToUpdater()

	if err := s.ScanConfigDal.UpdateScanConfig(ctx, configID, updater); err != nil {
		logging.GetLogger().Error().Err(err).Msg("UpdateScanConfig")
		return response.NewHttpError(http.StatusInternalServerError, err)
	}
	return nil
}

func (s *ScanConfigSrv) verifyLibrary(ctx context.Context, libs []int64) error {
	for i := range libs {
		registry, _, err := s.RegistryDal.SearchRegistry(ctx, store.SearchRegistryParam{
			Id:       libs[i],
			NoDelete: true,
		}, nil)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("verifyLibrary")
			return response.NewHttpError(http.StatusInternalServerError, err)
		}
		if len(registry) == 0 {
			return response.NewHttpError(http.StatusExpectationFailed, fmt.Errorf("library:%d is not allowed", libs[i]))
		}
	}
	return nil
}

func (s *ScanConfigSrv) verifyStrategyID(ctx context.Context, ids []int64) error {
	for i := range ids {
		registry, _, err := s.ScanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{
			StrategyID: ids[i],
		}, nil)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("verifyStrategyID")
			return response.NewHttpError(http.StatusInternalServerError, err)
		}
		if len(registry) == 0 {
			return response.NewHttpError(http.StatusExpectationFailed, fmt.Errorf("StrategyID:%d is not allowed", ids[i]))
		}
	}
	return nil
}

func (s *ScanConfigSrv) getAllImageIds(ctx context.Context, daoParm store.SearchImageParam) ([]int64, error) {
	imgIds := make([]int64, 0)

	imgs, _, err := s.ImageDal.SearchImage(ctx, daoParm, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("ScanAllNow.SearchImage error:%s", err.Error())
		return imgIds, err
	}

	for i := range imgs {
		imgIds = append(imgIds, imgs[i].ID)
	}

	return imgIds, nil
}

func (s *ScanConfigSrv) addLibraryScanTask(ctx context.Context, config model.ScanConfig) error {

	add, err := config.IsTimeToAddTask(model.ImageFromTypeNormal, consts.CheckTaskInterval)
	if err != nil {
		logging.GetLogger().Info().Msg("AddTaskByStrategy,not fond scan config")
		return err
	}

	logging.GetLogger().Info().Msgf("AddTaskByStrategy,addLibraryScanTask add: %t", add)

	if add {
		libs := config.LibraryImageConfig.Libraries
		if config.LibraryImageConfig.ScanAll {
			registry, _, err := s.RegistryDal.SearchRegistry(ctx, store.SearchRegistryParam{
				UseType:  model.RegistryUseTypeNormal,
				NoDelete: true,
			}, nil)

			if err != nil {
				return err
			}
			lbs := make([]int64, 0)
			for i := range registry {
				lbs = append(lbs, registry[i].ID)
			}
			libs = lbs
		}
		// 查找所有的镜像增加任务
		daoParm := store.SearchImageParam{FromType: model.ImageFromTypeNormal, RegistryIds: libs}
		imgIds, err := s.getAllImageIds(ctx, daoParm)
		if err != nil {
			return err
		}
		// 增加扫描任务
		ts := task.NewTaskSrv()
		if err := ts.GenerateScanTask(ctx, imgIds, task.UpdateTaskInfo{
			Scope:       consts.FullScan,
			TriggerType: consts.ScheduleTrigger,
			StrategyId:  config.LibraryImageConfig.StrategyId,
			Operator:    consts.SyncTriggerOperator,
		}); err != nil {
			logging.GetLogger().Error().Err(err).Msg("AddTaskByStrategy add scan task failed")
			return err
		}
		logging.GetLogger().Info().Msgf("AddTaskByStrategy addLibraryScanTask add scan task success:%d", len(imgIds))
	}
	return nil
}

func (s *ScanConfigSrv) addNodeScanTask(ctx context.Context, config model.ScanConfig) error {
	add, err := config.IsTimeToAddTask(model.ImageFromSafeNode, consts.CheckTaskInterval)
	if err != nil {
		logging.GetLogger().Info().Msg("AddTaskByStrategy,not fond scan config")
		return err
	}
	if add {
		daoParm := store.SearchImageParam{FromType: model.ImageFromSafeNode}
		if !config.NodeImageConfig.ScanAll {
			daoParm.NodeHostnames = config.NodeImageConfig.NodeHostnames
		}

		// 查找所有的镜像增加任务
		imgIds, err := s.getAllImageIds(ctx, daoParm)
		if err != nil {
			return err
		}
		// 增加扫描任务
		ts := task.NewTaskSrv()
		if err := ts.GenerateScanTask(ctx, imgIds, task.UpdateTaskInfo{
			Scope:       consts.SingleScan,
			TriggerType: consts.ScheduleTrigger,
			StrategyId:  config.NodeImageConfig.StrategyId,
			Operator:    consts.SyncTriggerOperator,
		}); err != nil {
			logging.GetLogger().Error().Err(err).Msg("AddTaskByStrategy add  scan task failed")
			return err
		}
		logging.GetLogger().Info().Msgf("AddTaskByStrategy addNodeScanTask add scan task success:%d", len(imgIds))
	}
	return nil
}
