package service

import (
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/config"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"

	// Register registry driver.
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/docker"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/harborv1"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/harborv2"
)

// SyncRepoImage sync registry repos and tags to db
type SyncRepoImage struct {
	config       *config.Config
	psql         *component.ScannerDB
	syncInterval uint
}

func NewSyncRepoImage(configPath string, syncInterval uint, psql *component.ScannerDB) (*SyncRepoImage, error) {
	// Load configuration
	config, err := config.LoadConfigFromDb(psql)
	if err != nil {
		logging.GetLogger().Fatal().Msg("failed to load configuration")
		return nil, err
	}

	s := &SyncRepoImage{
		config:       config,
		psql:         psql,
		syncInterval: syncInterval,
	}
	return s, nil
}

func (s *SyncRepoImage) Run(extender registry.ImageListExtender) error {

	// Open registry
	r, err := registry.Open(s.config.Registry)
	if err != nil {
		logging.GetLogger().Fatal().Str("err", err.Error()).Msg("open config err")
		return err
	}

	for {
		images, err := r.ListImages(extender)
		if err != nil {
			logging.GetLogger().Error().Msgf("get images err.%v", err)
		} else {
			logging.GetLogger().Info().Msgf("get images count %d", len(images))
		}

		time.Sleep(time.Duration(s.syncInterval) * time.Second)
	}
	return nil
}

func TransImageToImagelist(r *SyncRepoImage, image registry.Image) model.ImageList {
	TransImagelist := model.ImageList{}
	TransImagelist.Library = r.config.Registry.Options["url"].(string)
	TransImagelist.RegistryId = uint(r.config.RegistryID)
	TransImagelist.Digest = image.ImageDigest
	TransImagelist.FullRepoName = image.Repository
	TransImagelist.Tags = image.Tag
	TransImagelist.Size = int(image.Size)
	TransImagelist.FirstPushTime = image.Created
	TransImagelist.LastPullTime = image.LastPullTime
	TransImagelist.LastPushTime = image.LastPushTime
	TransImagelist.ManifestV1JSON = []byte(image.ManifestV1)
	TransImagelist.ManifestV2JSON = []byte(image.ManifestV2)
	TransImagelist.ConfigJson = []byte(image.ConfigJson)
	return TransImagelist
}
