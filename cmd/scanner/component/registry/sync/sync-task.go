package sync

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

func getRegistryDriver(ctx context.Context, reg imagesecModel.Registry) (warehouse.Registry, error) {

	drive, err := warehouse.Open(warehouse.RegToRegistryConf(reg))
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Str("name", reg.Name).Msg("sync image open registry")
		return nil, err
	}
	if err := drive.Ping(); err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Str("regName", reg.Name).Msg("connect registry")
		return nil, err
	}
	logging.Get().Debug().Str("module", "RegistryImage").Interface("reg", reg).Msg("getRegistryDriver")

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
				logging.Get().Error().Msg(" panic recover")
			}
		}()

		ticker := time.NewTicker(time.Minute * 5)
		defer ticker.Stop()
		for {
			<-ticker.C

			logging.Get().Info().Str("module", "RegistryImage").Msg("createFullSyncTask start")
			// 每次都去数据库查询，因为数据增加了用户之后要能感知到
			registries, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString})
			if err != nil {
				logging.Get().Err(err).Str("module", "RegistryImage").Msg("createFullSyncTask")
				continue
			}

			for i := range registries {
				driver, err := getRegistryDriver(ctx, registries[i])
				if err != nil {
					logging.Get().Err(err).Str("module", "RegistryImage").Str("regName", registries[i].Name).Str("regUrl", registries[i].Url).
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
					logging.Get().Err(err).Str("module", "RegistryImage").Str("regName", registries[i].Name).Str("syncType", imagesecModel.CycleFullSync.String()).
						Msg("AddSyncTask CreateSyncTask failure")
					continue
				}
				logging.Get().Info().Str("module", "RegistryImage").Str("syncType", imagesecModel.CycleFullSync.String()).Msg("AddSyncTask end")
			}
		}

	}()
}

func (s *RegSyncSrv) createCronSyncTask(ctx context.Context) {

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("createCronSyncTask panic recover")
			}
		}()

		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()

		for {
			<-ticker.C

			if time.Now().Hour() != consts.DetectAtHour {
				continue
			}

			logging.Get().Info().Str("module", "RegistryImage").Msg("createFullSyncTask start")
			// 每次都去数据库查询，因为数据增加了用户之后要能感知到
			registries, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString})
			if err != nil {
				logging.Get().Err(err).Str("module", "RegistryImage").Msg("createCronSyncTask")
				continue
			}

			for i := range registries {
				tas := imagesecModel.ImageSyncTask{
					RegistryID: registries[i].ID,
					SyncType:   imagesecModel.TimingFullSync.String(),
				}

				if err := s.syncTaskDal.CreateSyncTask(ctx, &tas); err != nil {
					logging.Get().Err(err).Str("module", "RegistryImage").Str("regName", registries[i].Name).Str("syncType", imagesecModel.TimingFullSync.String()).
						Msg("CreateSyncTask failure")
					continue
				}
			}

			logging.Get().Info().Str("module", "RegistryImage").Str("syncType", imagesecModel.TimingFullSync.String()).Msg("createCronSyncTask")
		}
	}()

	return
}
