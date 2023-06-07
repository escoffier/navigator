package imagesync

import (
	"context"
	"os"
	"strconv"
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

	// 定期删除重试超限
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.GetLogger().Error().Msg("DeleteMoreRetryCount recover")
			}
		}()

		maxRetryCountStr := os.Getenv("SYNC_IMAGE_RETRY_MAX_COUNT")
		maxRetryCount, err := strconv.ParseInt(maxRetryCountStr, 10, 64)
		if err != nil || maxRetryCount <= 0 {
			maxRetryCount = consts.SyncImageMaxCountDefault
		}

		ticker := time.NewTicker(time.Minute * 5)
		defer ticker.Stop()
		for {
			<-ticker.C
			logging.GetLogger().Info().Msg("start DeleteMoreRetryCount")

			err := i.syncImage.DeleteMoreRetryCount(context.Background(), maxRetryCount)
			if err != nil {
				logging.GetLogger().Err(err).Msg("DeleteMoreRetryCount service end")
			} else {
				logging.GetLogger().Info().Msg("DeleteMoreRetryCount start success")
			}
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

	scannerInstanceInfoDal := store.NewScannerInstanceDao(scannerWrapperDb)

	imageSrv := component.NewLibImageSrv(imageDal, registryDal, scanTaskDal, vulnDal, scanResultDal, webshellDal, trustedImageDal, resourceDal, scannerInstanceInfoDal)
	syncSrv := component.NewSyncRepoImage(registryDal, imageDal, scanConfigDal, vulnDal, syncTaskDal)

	p := &ImageSync{
		syncImage: syncSrv,
		imageSrv:  imageSrv,
	}

	return p, nil
}
