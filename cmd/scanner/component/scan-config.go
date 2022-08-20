package component

import (
	"context"
	"fmt"
	"math"
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
	All        string
	Name       string
}
type SearchScanConfigParam struct {
	ScanConfigID int64
}

type SearchSoftWareParam struct {
	StrategyID int64
}

type ScanConfigSrvInterface interface {
	CreateStrategy(ctx context.Context, data *model.ScanStrategy) error
	SearchStrategy(ctx context.Context, param SearchStrategyParam, filter *model.Filter) ([]model.ScanStrategy, int64, error)
	UpdateStrategy(ctx context.Context, strategyID int64, data *model.ScanStrategy) error
	DeleteStrategy(ctx context.Context, strategyID int64) error
	UpdateScanConfig(ctx context.Context, configID int64, data *model.ScanConfig) (*model.ScanConfig, error)
	SearchScanConfig(ctx context.Context, param SearchScanConfigParam, filter *model.Filter) ([]model.ScanConfig, int64, error)

	SearchNodes(ctx context.Context) ([]string, error)
	AddTaskByStrategy(ctx context.Context) error
	SearchProjects(ctx context.Context, registryID int64) ([]string, error)
	SearchRepoNames(ctx context.Context) ([]string, error)
}

type ScanConfigSrv struct {
	ScanConfigDal store.ScanConfigDal
	RegistryDal   store.RegistryDal
	ImageDal      store.ScannerDalInterface
	ScanTaskDal   store.ScanTaskInterface
}

func NewScanConfigSrv(scanConfigDAl store.ScanConfigDal, registryDal store.RegistryDal, imageDal store.ScannerDalInterface, scanTaskDal store.ScanTaskInterface) *ScanConfigSrv {
	return &ScanConfigSrv{ScanConfigDal: scanConfigDAl, RegistryDal: registryDal, ImageDal: imageDal, ScanTaskDal: scanTaskDal}
}

func (s *ScanConfigSrv) SearchRepoNames(ctx context.Context) ([]string, error) {
	nodes, err := s.ScanConfigDal.SearchRepoNames(ctx)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchRepoNames")
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}
	return nodes, nil
}
func (s *ScanConfigSrv) SearchProjects(ctx context.Context, registryID int64) ([]string, error) {
	nodes, err := s.ScanConfigDal.SearchProjects(ctx, store.GetProjectParam{RegistryID: registryID})
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchProjects")
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}
	return nodes, nil
}
func (s *ScanConfigSrv) SearchNodes(ctx context.Context) ([]string, error) {
	nodes, err := s.ScanConfigDal.SearchNodes(ctx)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchNodes")
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}
	return nodes, nil
}

func (s *ScanConfigSrv) AddTaskByStrategy(ctx context.Context) error {

	ticker := time.NewTicker(time.Second * consts.CheckTaskInterval)
	defer ticker.Stop()

	for {
		<-ticker.C
		logging.GetLogger().Info().Msg("AddTaskByStrategy,check")

		configs, _, err := s.SearchScanConfig(ctx, SearchScanConfigParam{}, nil)
		if err != nil {
			logging.GetLogger().Err(err).Msg("AddTaskByStrategy")
			continue
		}
		if len(configs) == 0 {
			logging.GetLogger().Info().Msg("AddTaskByStrategy,not fond scan config")
			continue
		}
		config := configs[0]
		// 先加仓库镜像
		if config.LibraryImageConfig != nil && config.LibraryImageConfig.ScanCycleEnable {
			if err := s.addLibraryScanTask(ctx, config); err != nil {
				logging.GetLogger().Err(err).Msg("AddTaskByStrategy,addLibraryScanTask failure")
				continue
			}
		}

		// 再加节点镜像
		if config.NodeImageConfig != nil && config.NodeImageConfig.ScanCycleEnable {
			if err := s.addNodeScanTask(ctx, config); err != nil {
				logging.GetLogger().Err(err).Msg("AddTaskByStrategy,addNodeScanTask failure")
				continue
			}
		}
		ticker.Reset(time.Second * consts.CheckTaskInterval)
	}
}

func (s *ScanConfigSrv) SearchScanConfig(ctx context.Context, param SearchScanConfigParam, filter *model.Filter) ([]model.ScanConfig, int64, error) {
	configs, cnt, err := s.ScanConfigDal.SearchScanConfig(ctx, store.SearchScanConfigParam{ScanConfigID: param.ScanConfigID}, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchScanConfig")
		return nil, 0, err
	}
	// 去除掉已删除的仓库，兼容直接清理数据的情况
	registry, _, err := s.RegistryDal.SearchRegistry(ctx, store.SearchRegistryParam{NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchRegistry")
		return nil, 0, err
	}
	registryMap := make(map[int64]bool)
	for i := range registry {
		registryMap[registry[i].ID] = true
	}

	for i := range configs {
		// 数据不大，使用双层循环
		if configs[i].LibraryImageConfig != nil {
			lib := make([]int64, 0)
			for j := range configs[i].LibraryImageConfig.Libraries {
				regId := configs[i].LibraryImageConfig.Libraries[j]
				if registryMap[regId] {
					lib = append(lib, regId)
				}
			}
			configs[i].LibraryImageConfig.Libraries = lib
		}
	}

	return configs, cnt, nil
}

func (s *ScanConfigSrv) SearchStrategy(ctx context.Context, param SearchStrategyParam, filter *model.Filter) ([]model.ScanStrategy, int64, error) {
	if param.All == consts.TrueString {
		// 默认策略永远在最前面,所以查出全部，在程序中分页
		if filter == nil {
			filter = model.EmptyFilterForTotalQuery()
		}
		allFilter := filter.DeepCopy()

		allFilter.Offset = 0
		allFilter.Limit = math.MaxInt64
		strategies, cnt, err := s.ScanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{IsDefault: consts.FalseString}, allFilter)
		if err != nil {
			logging.GetLogger().Err(err).Msg("SearchStrategy")
			return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
		}
		defaults, _, err := s.ScanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{IsDefault: consts.TrueString}, allFilter)
		if err != nil {
			logging.GetLogger().Err(err).Msg("SearchStrategy")
			return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
		}
		all := append(defaults, strategies...)

		// 应付前端分页
		if filter != nil && len(all) > 0 {
			start := int(filter.Offset)
			end := int(filter.Offset + filter.Limit)
			if len(all) <= start {
				return make([]model.ScanStrategy, 0), cnt + 1, nil
			}
			if end > len(all) {
				end = len(all)
			}
			return all[start:end], int64(len(all)), nil
		}
		return all, cnt + int64(len(defaults)), nil
	}
	strategies, cnt, err := s.ScanConfigDal.SearchStrategy(ctx, store.SearchStrategyParam{StrategyID: param.StrategyID, Name: param.Name, IsDefault: param.IsDefault}, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchStrategy")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	return strategies, cnt, nil
}

func (s *ScanConfigSrv) CreateStrategy(ctx context.Context, data *model.ScanStrategy) error {
	data.Serialize()
	data.SetDefault()
	if err := data.Check(); err != nil {
		logging.GetLogger().Err(err).Msg("CreateStrategy")
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}
	err := s.ScanConfigDal.CreateStrategy(ctx, data)
	if err != nil {
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("该策略已存在，请重新设置策略名"))
		}
		logging.GetLogger().Err(err).Msg("CreateStrategy")
		return response.NewHttpError(http.StatusInternalServerError, err)
	}
	return nil
}

func (s *ScanConfigSrv) UpdateStrategy(ctx context.Context, strategyID int64, data *model.ScanStrategy) error {
	data.Serialize()
	data.SetDefault()

	if err := data.Check(); err != nil {
		logging.GetLogger().Err(err).Msg("CreateStrategy")
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}

	updater := data.ToUpdater()

	err := s.ScanConfigDal.UpdateStrategy(ctx, store.SearchStrategyParam{StrategyID: strategyID, IsDefault: consts.FalseString}, updater)
	if err != nil {
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("该策略已存在，请重新设置策略名"))
		}
		logging.GetLogger().Err(err).Msg("CreateStrategy")
		return response.NewHttpError(http.StatusInternalServerError, err)
	}
	return nil
}

func (s *ScanConfigSrv) DeleteStrategy(ctx context.Context, strategyID int64) error {
	// 删除之前先做检查，
	// 没有配置
	config, _, err := s.SearchScanConfig(ctx, SearchScanConfigParam{}, nil)
	if err != nil {
		return response.NewHttpError(http.StatusInternalServerError, err)
	}
	for i := range config {
		if config[i].LibraryImageConfig.StrategyID == strategyID {
			return fmt.Errorf("该策略已配置在扫描配置中，不能删除")
		}
		if config[i].NodeImageConfig.StrategyID == strategyID {
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
		if strategy[i].ID == strategyID {
			return fmt.Errorf("该策略属于默认策略，不能删除")
		}
	}
	// 再看是否有该策略的扫描任务
	tasks, _, err := s.ScanTaskDal.GetTasks(ctx, store.SearchTaskParam{
		Statuses:   []int8{consts.Pending, consts.InProgress, consts.Pause},
		StrategyID: strategyID,
	}, nil)
	if err != nil {
		return response.NewHttpError(http.StatusInternalServerError, err)
	}
	if len(tasks) > 0 {
		return fmt.Errorf("该策略下还有未完成的扫描任务，不能删除")
	}
	updater := map[string]interface{}{"deleted_at": time.Now().Unix()}

	if err := s.ScanConfigDal.UpdateStrategy(ctx, store.SearchStrategyParam{StrategyID: strategyID}, updater); err != nil {
		logging.GetLogger().Err(err).Msgf("UpdateStrategy:%d", strategyID)
		return response.NewHttpError(http.StatusInternalServerError, err)
	}
	return nil
}

func (s *ScanConfigSrv) UpdateScanConfig(ctx context.Context, configID int64, data *model.ScanConfig) (*model.ScanConfig, error) {
	if err := data.Check(); err != nil {
		logging.GetLogger().Err(err).Msg("UpdateScanConfig")
		return nil, response.NewHttpError(http.StatusExpectationFailed, err)
	}
	// 验证所传仓库是不是公司支持的仓库,验证所传策略ID是不是存在于数据库中(低频接口，直接循环了)
	if err := s.verifyLibrary(ctx, data.LibraryImageConfig.Libraries); err != nil {
		return nil, err
	}
	if err := s.verifyLibrary(ctx, data.NodeImageConfig.Libraries); err != nil {
		return nil, err
	}
	if err := s.verifyStrategyID(ctx, []int64{data.LibraryImageConfig.StrategyID}); err != nil {
		return nil, err
	}
	if err := s.verifyStrategyID(ctx, []int64{data.NodeImageConfig.StrategyID}); err != nil {
		return nil, err
	}

	data.Serialize()
	updater := data.ToUpdater()

	if err := s.ScanConfigDal.UpdateScanConfig(ctx, configID, updater); err != nil {
		logging.GetLogger().Err(err).Msg("UpdateScanConfig")
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}
	return data, nil
}

func (s *ScanConfigSrv) verifyLibrary(ctx context.Context, libs []int64) error {
	for i := range libs {
		registry, _, err := s.RegistryDal.SearchRegistry(ctx, store.SearchRegistryParam{
			ID:       libs[i],
			NoDelete: true,
		}, nil)
		if err != nil {
			logging.GetLogger().Err(err).Msg("verifyLibrary")
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
			logging.GetLogger().Err(err).Msg("verifyStrategyID")
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

	add, err := config.IsTimeToAddTask(model.UserRegistry, consts.CheckTaskInterval)
	if err != nil {
		logging.GetLogger().Info().Msg("AddTaskByStrategy,not fond scan config")
		return err
	}

	logging.GetLogger().Info().Msgf("AddTaskByStrategy,addLibraryScanTask add: %t", add)

	if add {
		libs := config.LibraryImageConfig.Libraries
		if config.LibraryImageConfig.ScanAll {
			registry, _, err := s.RegistryDal.SearchRegistry(ctx, store.SearchRegistryParam{
				UseType:  model.UserRegistry,
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
		if len(libs) == 0 {
			logging.GetLogger().Info().Msg("not configured scan library")
		}
		// 查找所有的镜像增加任务
		daoParm := store.SearchImageParam{FromType: model.UserRegistry, RegistryIds: libs}
		imgIds, err := s.getAllImageIds(ctx, daoParm)
		if err != nil {
			return err
		}
		// 增加扫描任务
		ts := task.NewTaskSrv()
		if err := ts.GenerateScanTask(ctx, imgIds, task.UpdateTaskInfo{
			Scope:       consts.FullScan,
			TriggerType: consts.ScheduleTrigger,
			StrategyID:  config.LibraryImageConfig.StrategyID,
			Operator:    consts.CycleTriggerOperator,
		}); err != nil {
			logging.GetLogger().Err(err).Msg("AddTaskByStrategy add scan task failed")
			return err
		}
		logging.GetLogger().Info().Msgf("AddTaskByStrategy addLibraryScanTask add scan task success:%d", len(imgIds))
	}
	return nil
}

func (s *ScanConfigSrv) addNodeScanTask(ctx context.Context, config model.ScanConfig) error {
	add, err := config.IsTimeToAddTask(model.NodeBuffRegistry, consts.CheckTaskInterval)
	if err != nil {
		logging.GetLogger().Info().Msg("AddTaskByStrategy,not fond scan config")
		return err
	}
	if add {
		daoParm := store.SearchImageParam{FromType: model.NodeBuffRegistry}
		if !config.NodeImageConfig.ScanAll {
			daoParm.NodeHostnames = config.NodeImageConfig.NodeHostnames
		}
		if len(daoParm.NodeHostnames) == 0 {
			logging.GetLogger().Info().Msg("not configured scan node")
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
			StrategyID:  config.NodeImageConfig.StrategyID,
			Operator:    consts.CycleTriggerOperator,
		}); err != nil {
			logging.GetLogger().Err(err).Msg("AddTaskByStrategy add  scan task failed")
			return err
		}
		logging.GetLogger().Info().Msgf("AddTaskByStrategy addNodeScanTask add scan task success:%d", len(imgIds))
	}
	return nil
}
