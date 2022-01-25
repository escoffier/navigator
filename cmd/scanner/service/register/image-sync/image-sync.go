package imagesync

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
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
	// config    Config
	syncImage *component.SyncRepoImage
}

func (i *ImageSync) Start(ctx context.Context) error {

	err := i.syncImage.SyncImage(context.Background()) // nolint errcheck
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("sync image service end")
		return nil
	}
	logging.GetLogger().Info().Msg("image-sync start success")
	return nil
}

func (i *ImageSync) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
	logging.GetLogger().Info().Msg("image-sync register success")
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	scannerWrapperDb := store.GetScannerWrapperDb()
	p := &ImageSync{}
	s := component.NewSyncRepoImage(store.NewRegistryDao(scannerWrapperDb),
		store.NewScannerOrm(scannerWrapperDb),
		store.NewPodResourceRelationDao(scannerWrapperDb),
		store.NewScanConfigDao(scannerWrapperDb),
	)

	p.syncImage = s
	return p, nil
}
