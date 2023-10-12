package sync

import (
	"context"
	"runtime/debug"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

func (s *RegSyncSrv) getRegistryDriver(ctx context.Context, reg imagesecModel.Registry) (warehouse.Registry, error) {

	drive, err := warehouse.Open(warehouse.RegToRegistryConf(reg))
	if err != nil {
		s.Log.Err(err).Str("name", reg.Name).Msg("sync image open registry")
		return nil, err
	}
	if err := drive.Ping(); err != nil {
		s.Log.Err(err).Str("regName", reg.Name).Msg("connect registry")
		return nil, err
	}
	s.Log.Debug().Interface("reg", reg).Msg("getRegistryDriver")

	return drive, nil
}

func (s *RegSyncSrv) AddSyncTask(ctx context.Context) error {
	// 仓库配置的周期全量同步任务
	s.createFullSyncTask(ctx)
	// 每开开启动同步任务
	s.createCronSyncTask(ctx)
	return nil
}

// 周期全量任务
func (s *RegSyncSrv) createFullSyncTask(ctx context.Context) {

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("panic recover")
			}
		}()

		ticker := time.NewTicker(time.Minute * 5) // 最小同步间隔是5分钟
		defer ticker.Stop()
		for {
			<-ticker.C

			s.Log.Info().Msg("createFullSyncTask start")
			// 每次都去数据库查询，因为数据增加了用户之后要能感知到
			registries, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString})
			if err != nil {
				s.Log.Err(err).Msg("createFullSyncTask")
				continue
			}

			for i := range registries {
				driver, err := s.getRegistryDriver(ctx, registries[i])
				if err != nil {
					s.Log.Err(err).Str("regName", registries[i].Name).Str("regUrl", registries[i].Url).
						Msg("AddSyncTask getRegistryDriver")
					continue
				}
				if !registries[i].WhetherToStartSync() || driver.SupportIncrementalSync(ctx) {
					continue
				}
				tas := imagesecModel.ImageSyncTask{
					RegistryID: registries[i].ID,
					SyncType:   imagesecModel.CycleFullSync.String(),
				}

				if err := s.syncTaskDal.CreateSyncTask(ctx, &tas); err != nil {
					s.Log.Err(err).Str("regName", registries[i].Name).Str("syncType", imagesecModel.CycleFullSync.String()).
						Msg("AddSyncTask CreateSyncTask failure")
					continue
				}
				s.Log.Info().Str("syncType", imagesecModel.CycleFullSync.String()).Msg("AddSyncTask end")
			}
		}

	}()
}

func (s *RegSyncSrv) createCronSyncTask(ctx context.Context) {

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("createCronSyncTask panic recover")
			}
		}()

		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()

		for {
			<-ticker.C

			if time.Now().Hour() != consts.DetectAtHour {
				continue
			}

			s.Log.Info().Msg("createFullSyncTask start")
			// 每次都去数据库查询，因为数据增加了用户之后要能感知到
			registries, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString})
			if err != nil {
				s.Log.Err(err).Msg("createCronSyncTask")
				continue
			}

			for i := range registries {
				tas := imagesecModel.ImageSyncTask{
					RegistryID: registries[i].ID,
					SyncType:   imagesecModel.TimingFullSync.String(),
				}

				if err := s.syncTaskDal.CreateSyncTask(ctx, &tas); err != nil {
					s.Log.Err(err).Str("regName", registries[i].Name).Str("syncType", imagesecModel.TimingFullSync.String()).
						Msg("CreateSyncTask failure")
					continue
				}
			}

			s.Log.Info().Str("syncType", imagesecModel.TimingFullSync.String()).Msg("createCronSyncTask")
		}
	}()

	return
}
