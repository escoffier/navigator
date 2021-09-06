package data

import (
	"context"
	"runtime/debug"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (s *Service) expireGCTaskLoop() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when expire gc tasks: %v. stack: %s", r, debug.Stack())
		}
	}()

	// wait for server to be ready
	time.Sleep(time.Second * 5)

	s.expireGCTask(time.Now())
	ticker := time.NewTicker(time.Minute * 5)
	for {
		t := <-ticker.C
		s.expireGCTask(t)
	}
}

const (
	expireGCTaskTimeout = time.Second * 5
)

func (s *Service) expireGCTask(t time.Time) {
	logging.GetLogger().Info().Msgf("expire GCTask run")
	ctx, cancel := context.WithTimeout(context.Background(), expireGCTaskTimeout)
	defer cancel()
	retryFunc := func() error {
		return s.taskManager.DealExpireTasks(ctx, t)
	}
	if err := util.WithRetry(retryFunc, util.DefaultRetryConf); err != nil {
		logging.GetLogger().Error().Msgf("DealExpireTasks fail, err:%s", err.Error())
	}
}

func (s *Service) checkStorageLoop() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when checking storage: %v. stack: %s", r, debug.Stack())
		}
	}()

	// wait for k8s client to be ready
	time.Sleep(time.Minute * 5)
	s.checkStorage()
	ticker := time.NewTicker(time.Hour * 24)
	for {
		<-ticker.C
		s.checkStorage()
	}
}

const (
	checkStorageTimeout = time.Minute
)

type getStorageFunc func(ctx context.Context) (*model.StorageView, error)

func (s *Service) checkStorage() {
	logging.GetLogger().Info().Msgf("checkStorage")
	ctx, cancel := context.WithTimeout(context.Background(), checkStorageTimeout)
	defer cancel()

	percentage, err := s.getWaterlineWithRetry(ctx)
	if err != nil {
		logging.GetLogger().Error().Msgf("GetWaterline fail, err:%s", err.Error())
		return
	}

	var pods = map[string]getStorageFunc{
		model.DataTypeHotLogic:   s.GetLogicHotStorageView,
		model.DataTypeHotOffline: s.GetOfflineHotStorageView,
		model.DataTypeCold:       s.GetColdStorageView,
	}

	for dataType, fn := range pods {
		storageView, err := s.getStorageViewWithRetry(ctx, fn)
		if err != nil {
			logging.GetLogger().Error().Msgf("getStorageView fail, dataType:%s, err:%s", dataType, err.Error())
			continue
		}

		if storageView.Used*100/storageView.Total >= int64(percentage) {
			err = s.notifyInsufficientStorage(ctx, dataType, storageView)
			if err != nil {
				logging.GetLogger().Error().Msgf("notifyAdminStorage fail, err:%s", err.Error())
			}
		}
	}
}

func (s *Service) getWaterlineWithRetry(ctx context.Context) (int, error) {
	var percentage int
	getPercentageFunc := func() error {
		var _err error
		percentage, _err = s.waterlineManager.GetWaterline(ctx)
		return _err
	}

	err := util.WithRetry(getPercentageFunc, util.DefaultRetryConf)
	return percentage, err
}

func (s *Service) getStorageViewWithRetry(ctx context.Context, fn getStorageFunc) (*model.StorageView, error) {
	var storageView *model.StorageView
	getStorageViewFunc := func() error {
		var _err error
		storageView, _err = fn(ctx)
		return _err
	}

	err := util.WithRetry(getStorageViewFunc, util.DefaultRetryConf)
	return storageView, err
}

func (s *Service) notifyInsufficientStorage(ctx context.Context, dataType string, storage *model.StorageView) error {
	notifyFunc := func() error {
		return s.notifyHandler.Notify(ctx, dataType, storage)
	}

	return util.WithRetry(notifyFunc, util.DefaultRetryConf)
}
