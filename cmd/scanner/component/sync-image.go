package component

import (
	"context"
	"sync"
	"time"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/alauda"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/docker"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/harborv1"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/harborv2"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/hw-swr"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type SyncImageInterface interface {
	SyncImage(wg *sync.WaitGroup) error
}

// SyncRepoImage sync registry repos and tags to db
type SyncRepoImage struct {
	registryDao store.RegistryDaoInterface
	scannerDB   *store.ScannerDB
}

func (s *SyncRepoImage) GetSyncRegistry(ctx context.Context) ([]registry.Registry, error) {
	registries, _, err := s.registryDao.SearchRegistry(context.Background(), store.SearchRegistryParam{UseType: model.ImageFromTypeNormal, NoDelete: true}, nil)
	if err != nil {
		return nil, err
	}
	res := make([]registry.Registry, 0)
	for i := range registries {
		// 检查是否达到同步时间
		if time.Now().Unix()-registries[i].LastSyncAt < registries[i].SyncInterval*60 {
			continue
		}
		if err := s.registryDao.UpdateRegistry(ctx, store.SearchRegistryParam{Id: registries[i].ID}, map[string]interface{}{"last_sync_at": time.Now().Unix()}); err != nil {
			logging.GetLogger().Error().Err(err).Msg("UpdateRegistry last_sync_at error")
		}

		reg, err := GetRegistryFromConfig(registries[i])
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("GetRegistryFromConfig ")
			continue
		}
		res = append(res, reg)
	}
	return res, err
}

func NewSyncRepoImage(registryDao store.RegistryDaoInterface, scannerDB *store.ScannerDB) *SyncRepoImage {
	return &SyncRepoImage{
		registryDao: registryDao,
		scannerDB:   scannerDB,
	}
}

func (s *SyncRepoImage) SyncImage(wg *sync.WaitGroup) error {
	defer wg.Done()

	worker := func(reg registry.Registry, extender registry.ImageListExtender) {
		images, err := reg.ListImages(extender)
		if err != nil {
			logging.GetLogger().Error().Msgf("get images err.%v", err)
		} else {
			logging.GetLogger().Info().Msgf("get images count %d", len(images))
		}
	}
	extender := func(conf registry.RegisterConfig, image registry.Image) error {
		img := TransImageToImagelist(conf, image)

		_, err := s.scannerDB.InsertImageList(context.Background(), img)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("SyncImage.InsertImageList")
			return err
		} else {
			logging.GetLogger().Info().Msgf("SyncImage.InsertImageList:%s/%s:%s", img.Library, img.FullRepoName, img.Tags)
		}
		return nil
	}

	for {
		// 每次都去数据库查询，因为数据增加了用户之后要能感知到
		// logging.GetLogger().Info().Msg("开始同步镜像")
		registries, err := s.GetSyncRegistry(context.Background())
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("查询仓库信息出错")
			continue
		}
		for i := range registries {
			go worker(registries[i], extender)
		}
		time.Sleep(time.Duration(1) * time.Minute) // 每分钟去查一次数据库
	}
}

func TransImageToImagelist(conf registry.RegisterConfig, image registry.Image) model.ImageList {

	transImagelist := model.ImageList{
		FullRepoName:   image.Repository,
		Tags:           image.Tag,
		Digest:         image.ImageDigest,
		Size:           int(image.Size),
		Library:        conf.URL,
		ImageScanVuln:  model.ImageScanSummaryResult{},
		RegistryId:     conf.RegistryId,
		FirstPushTime:  image.Created,
		LastPushTime:   image.LastPushTime,
		LastPullTime:   image.LastPullTime,
		ManifestV1JSON: []byte(image.ManifestV1),
		ManifestV2JSON: []byte(image.ManifestV2),
		ConfigJson:     []byte(image.ConfigJson),
		FromType:       model.ImageFromTypeNormal,
	}
	transImagelist.Layers = getLayerString(transImagelist)
	return transImagelist
}
