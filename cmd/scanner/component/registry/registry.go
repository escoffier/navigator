// Package registry defines the  models and a common interface for
// registry implementations.
package registry

import (
	"errors"
	"fmt"
)

// RegistrableComponentConfig is a configuration block that can be used to
// determine which registrable component should be initialized and pass custom
// configuration to it.
type RegistrableComponentConfig struct {
	Type    string
	Options map[string]interface{}
}

var drivers = make(map[string]Driver)

// Driver is a function that connects a registry specified by its client driver type and specific
// configuration.
type Driver func(RegistrableComponentConfig) (Registry, error)

// ImageListExtender is a function that can do some stuff when sync one image
type ImageListExtender func(image Image) error

// Register makes a Constructor available by the provided name.
//
// If this function is called twice with the same name or if the Constructor is
// nil, it panics.
func Register(name string, driver Driver) error {
	if driver == nil {
		return errors.New("could not register nil Driver")
	}
	if _, dup := drivers[name]; dup {
		return errors.New("could not register duplicate Driver: " + name)
	}
	drivers[name] = driver
	return nil
}

// Open opens a registry specified by a configuration.
func Open(cfg RegistrableComponentConfig) (Registry, error) {
	driver, ok := drivers[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown Driver %q (forgotten configuration or import?)", cfg.Type)
	}
	return driver(cfg)
}

// Registry represents the required operations on a registry
type Registry interface {
	// // ListRepos returns the entire list of repository.
	// ListRepos() ([]string, error)
	//
	// // ListRepoTags returns the repo tags
	// ListRepoTags(string) ([]string, error)

	CheckProject(projectName string) error

	CreateProject(projectName string, public bool) error

	GetImage(projectName, fullRepoName, tag string) (*Image, error)
	// 删除Image
	DeleteImages(projectName, repoName, digest string) error

	// ListImages return all images
	ListImages(extender ImageListExtender) ([]Image, error)
}

// // SyncRepoImage sync registry repos and tags to db
// type SyncRepoImage struct {
// 	config       component.Config
// 	psql         *component.ScannerDB
// 	syncInterval uint
// }
//
// func NewSyncRepoImage(ctx context.Context, configPath string, syncInterval uint, psql *component.ScannerDB) ([]SyncRepoImage, error) {
// 	// Load configuration
// 	config, err := component.LoadConfig(configPath)
//
// 	if err != nil {
// 		logging.GetLogger().Fatal().Msg("failed to load configuration")
// 		return nil, err
// 	}
// 	var res []SyncRepoImage
// 	for i := range config {
// 		var tls int
// 		if config[i].Registry.Options["skiptlsverify"].(bool) == true {
// 			tls = 1
// 		} else {
// 			tls = 0
// 		}
// 		tmpRgistry := model.Registry{Url: config[i].Registry.Options["url"].(string), Username: config[i].Registry.Options["username"].(string), Password: []byte(config[i].Registry.Options["password"].(string)), TLS: tls, ApiVersion: config[i].Registry.Type}
// 		psql.InsertToRegistry(ctx, &tmpRgistry)
// 		config[i].RegistryID = int64(tmpRgistry.ID)
// 		s := SyncRepoImage{
// 			config:       config[i],
// 			psql:         psql,
// 			syncInterval: syncInterval,
// 		}
// 		res = append(res, s)
// 	}
// 	return res, nil
// }
//
// func (s *SyncRepoImage) Run(extender ImageListExtender, wg *sync.WaitGroup) error {
// 	defer wg.Done()
// 	// Open registry
// 	// fmt.Printf("\n调用了%v仓库", s.config.Registry.Type)
// 	r, err := Open(s.config.Registry)
// 	if err != nil {
// 		logging.GetLogger().Fatal().Str("err", err.Error()).Msg("open config err")
// 		return err
// 	}
//
// 	for {
// 		images, err := r.ListImages(extender)
// 		if err != nil {
// 			logging.GetLogger().Error().Msgf("get images err.%v", err)
// 		} else {
// 			logging.GetLogger().Info().Msgf("get images count %d", len(images))
// 		}
//
// 		time.Sleep(time.Duration(s.syncInterval) * time.Second)
// 	}
//
// 	return nil
// }
//
// func TransImageToImagelist(r SyncRepoImage, image Image) model.ImageList {
// 	// fmt.Printf("\nType为:%v 内部ID为:%v\n", r.config.Registry.Type, uint(r.config.RegistryID))
// 	TransImagelist := model.ImageList{}
// 	TransImagelist.Library = r.config.Registry.Options["url"].(string)
// 	TransImagelist.RegistryId = uint(r.config.RegistryID)
// 	TransImagelist.Digest = image.ImageDigest
// 	TransImagelist.FullRepoName = image.Repository
// 	TransImagelist.Tags = image.Tag
// 	TransImagelist.Size = int(image.Size)
// 	TransImagelist.FirstPushTime = image.Created
// 	TransImagelist.LastPullTime = image.LastPullTime
// 	TransImagelist.LastPushTime = image.LastPushTime
// 	TransImagelist.ManifestV1JSON = []byte(image.ManifestV1)
// 	TransImagelist.ManifestV2JSON = []byte(image.ManifestV2)
// 	TransImagelist.ConfigJson = []byte(image.ConfigJson)
// 	return TransImagelist
// }
