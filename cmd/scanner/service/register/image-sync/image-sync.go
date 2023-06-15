package imagesync

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "image-sync"
)

type Config struct {
}

type ImageSync struct {
	syncImage component.SyncImageInterface
	imageSrv  imagemeta.ImageService
}

func (i *ImageSync) Start(ctx context.Context) error {
	// 开启全量同步
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.GetLogger().Error().Msg("SyncAllImage recover")
			}
		}()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			<-ticker.C
			err := i.syncImage.SyncAllImage(ctx)
			if err != nil {
				logging.GetLogger().Err(err).Msg("SyncAllImage service end")
				continue
			}
			logging.GetLogger().Info().Msg("SyncAllImage start success")
		}
	}()

	// 定期增加同布任务
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.GetLogger().Error().Msg("AddSyncTask recover")
			}
		}()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			<-ticker.C
			err := i.syncImage.AddSyncTask(ctx)
			if err != nil {
				logging.GetLogger().Err(err).Msg("AddSyncTask service end")
				continue
			}
			logging.GetLogger().Info().Msg("AddSyncTask start success")
		}
	}()
	// 开启增量同步
	go func() {

		defer func() {
			if err := recover(); err != nil {
				logging.GetLogger().Error().Msg("SyncAddImage recover")
			}
		}()

		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			err := i.syncImage.SyncAddImage(ctx, consts.CycleIncSync)
			if err != nil {
				logging.GetLogger().Err(err).Msg("SyncAddImage service end")
				continue
			}
			logging.GetLogger().Info().Msg("SyncAddImage start success")
		}
	}()

	// 镜像更新
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.GetLogger().Error().Msg("DeleteMoreRetryCount recover")
			}
		}()
		_ = i.imageSrv.ContinueUpdateDeleteImage(ctx)
	}()

	return nil
}

func (i *ImageSync) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
	logging.GetLogger().Info().Msg("image-sync register success")
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	scannerWrapperDb := store.GetScannerWrapperDb()

	registryDal := store.NewRegistryDao(scannerWrapperDb)
	scanConfigDal := store.NewScanConfigDao(scannerWrapperDb)
	vulnDal := store.NewVulnDao(scannerWrapperDb)
	scanResultDal := store.NewImageScanResultDao(scannerWrapperDb)
	webshellDal := store.NewWebsehllDao(scannerWrapperDb)
	scanTaskDal := store.NewScannerOrm(scannerWrapperDb)
	imageDal := store.NewScannerOrm(scannerWrapperDb)
	resourceDal := store.NewResourceDao(scannerWrapperDb)
	trustedImageDal := store.NewScannerOrm(scannerWrapperDb)
	syncTaskDal := store.NewSyncTaskDao(scannerWrapperDb)
	syncRetryImageDal := store.NewSyncRetryImageDao(scannerWrapperDb)

	scannerInstanceInfoDal := store.NewScannerInstanceDao(scannerWrapperDb)

	imageSrv := component.NewLibImageSrv(imageDal, registryDal, scanTaskDal, vulnDal, scanResultDal, webshellDal, trustedImageDal, resourceDal, scannerInstanceInfoDal)
	syncSrv := component.NewSyncRepoImage(registryDal, imageDal, syncRetryImageDal, scanConfigDal, vulnDal, syncTaskDal)

	p := &ImageSync{
		syncImage: syncSrv,
		imageSrv:  imageSrv,
	}

	return p, nil
}
