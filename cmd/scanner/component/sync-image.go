package component

import (
	"context"
	"fmt"
	"sync"
	"time"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/docker"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/harborv1"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/harborv2"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

// SyncRepoImage sync registry repos and tags to db
type SyncRepoImage struct {
	config       Config
	psql         *store.ScannerDB
	syncInterval uint
}

func NewSyncRepoImage(ctx context.Context, configPath string, syncInterval uint, psql *store.ScannerDB) ([]SyncRepoImage, error) {
	// Load configuration
	config, err := LoadConfig(configPath)

	if err != nil {
		logging.GetLogger().Fatal().Msg("failed to load configuration")
		return nil, err
	}
	var res []SyncRepoImage
	for i := range config {
		var tls int
		if config[i].Registry.Options["skiptlsverify"].(bool) == true {
			tls = 1
		} else {
			tls = 0
		}
		tmpRgistry := model.Registry{Url: config[i].Registry.Options["url"].(string), Username: config[i].Registry.Options["username"].(string), Password: []byte(config[i].Registry.Options["password"].(string)), TLS: tls, ApiVersion: config[i].Registry.Type}
		psql.InsertToRegistry(ctx, &tmpRgistry)
		config[i].RegistryID = int64(tmpRgistry.ID)
		s := SyncRepoImage{
			config:       config[i],
			psql:         psql,
			syncInterval: syncInterval,
		}
		res = append(res, s)
	}
	return res, nil
}

/*func NewSyncRepoImageByConfig(configPath string, syncInterval uint) (*SyncRepoImage, error) {
	// Load configuration
	config, err := LoadConfig(configPath)
	if err != nil {
		logging.GetLogger().Fatal().Msg("failed to load configuration")
		return nil, err
	}

	s := &SyncRepoImage{
		config:       config,
		syncInterval: syncInterval,
	}
	return s, nil
}*/

/*func (s *SyncRepoImage) MockRun(extender registry.ImageListExtender) error {
	// Open registry
	r, err := registry.Open(s.config.Registry)
	if err != nil {
		logging.GetLogger().Fatal().Str("err", err.Error()).Msg("open config err")
		return err
	}
	images, err := r.ListImages(extender)
	if err != nil {
		logging.GetLogger().Error().Msgf("get images err.%v", err)
	} else {
		logging.GetLogger().Info().Msgf("get images count %d,%+v", len(images), images)
	}
	return nil
}*/

func (s *SyncRepoImage) Run(extender registry.ImageListExtender, wg *sync.WaitGroup) error {
	defer wg.Done()
	// Open registry
	fmt.Printf("\n调用了%v仓库", s.config.Registry.Type)
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

func TransImageToImagelist(r SyncRepoImage, image registry.Image) model.ImageList {
	// fmt.Printf("\nType为:%v 内部ID为:%v\n", r.config.Registry.Type, uint(r.config.RegistryID))
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
