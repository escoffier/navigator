package component

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/hwswr"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

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

type RegistryWithConf struct {
	Registry registry.Registry
	Config   model.Registry
}

func (s *SyncRepoImage) GetSyncRegistry(ctx context.Context) ([]RegistryWithConf, error) {
	registries, _, err := s.registryDao.SearchRegistry(context.Background(), store.SearchRegistryParam{NoDelete: true,
		UseTypes: []int64{model.RegistryUseTypeNormal, model.RegistryUseSafeNode}}, nil)
	if err != nil {
		return nil, err
	}
	res := make([]RegistryWithConf, 0)
	for i := range registries {
		// 检查是否达到同步时间
		if time.Now().Unix()-registries[i].LastSyncAt < registries[i].SyncInterval*60 {
			continue
		}
		if err := s.registryDao.UpdateRegistry(ctx, store.SearchRegistryParam{Id: registries[i].ID}, map[string]interface{}{"last_sync_at": time.Now().Unix()}); err != nil {
			logging.GetLogger().Error().Err(err).Msg("UpdateRegistry last_sync_at error")
		}

		drive, err := registry.Open(RegToRegistryConf(registries[i]))
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get no drive")
			return nil, response.NewHttpError(http.StatusInternalServerError, err)
		}
		if err := drive.Ping(); err != nil {
			logging.GetLogger().Error().Err(err).Msgf("尝试连接到仓库出错:%s", registries[i].Name)
			continue
		}

		res = append(res, RegistryWithConf{
			Registry: drive,
			Config:   registries[i],
		})
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
	var exitMap sync.Map

	worker := func(reg RegistryWithConf, extender registry.ImageListExtender) {
		_, err := reg.Registry.ListImages(extender, false)
		if err != nil {
			logging.GetLogger().Error().Msgf("get images err.%v", err)
		}
		exitMap.Store(reg.Config.Name, true)
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
			if ex, ok := exitMap.Load(registries[i].Config.Name); ok {
				if ex1, ok := ex.(bool); ok && !ex1 {
					logging.GetLogger().Info().Msg("SyncImage.InsertImageList last synchronization has not been completed")
					continue
				}
			}
			exitMap.Store(registries[i].Config.Name, false)

			go worker(registries[i], func(image registry.Image) error {
				img, err := TransImageToImagelist(registries[i].Config, image)
				if err != nil {
					logging.GetLogger().Info().Msgf("SyncImage.InsertImageList:%s", err.Error())
					return err
				}

				_, err = s.scannerDB.InsertImageList(context.Background(), img)
				if err != nil {
					logging.GetLogger().Error().Err(err).Msg("SyncImage.InsertImageList")
					return err
				} else {
					logging.GetLogger().Info().Msgf("SyncImage.InsertImageList:%s/%s:%s", img.Library, img.FullRepoName, img.Tags)
				}
				return nil
			})
		}
		time.Sleep(time.Duration(1) * time.Minute) // 每分钟去查一次数据库
	}
}

func TransImageToImagelist(reg model.Registry, image registry.Image) (model.ImageList, error) {
	tmpLib := reg.Url
	tmpLib = strings.TrimPrefix(tmpLib, "http://") // trimPrefix http or https
	tmpLib = strings.TrimPrefix(tmpLib, "https://")

	imageID := fmt.Sprintf("%s/%s:%s", tmpLib, image.Repository, image.Tag)
	img := model.ImageList{
		FullRepoName:   image.Repository,
		Tags:           image.Tag,
		Digest:         image.ImageDigest,
		Size:           int(image.Size),
		Library:        tmpLib,
		ImageScanVuln:  model.ImageScanSummaryResult{},
		RegistryId:     reg.ID,
		FirstPushTime:  image.Created,
		LastPushTime:   image.LastPushTime,
		LastPullTime:   image.LastPullTime,
		ManifestV1JSON: []byte(image.ManifestV1),
		ManifestV2JSON: []byte(image.ManifestV2),
		ConfigJson:     []byte(image.ConfigJson),
		FromType:       model.ImageFromTypeNormal,
		ImageUUID:      util.GenerateUUID(imageID),
	}
	img.Layers = getLayerString(img)
	if reg.UseType == model.RegistryUseSafeNode {
		logging.GetLogger().Info().Msgf("TransImageToImagelist Url:%s,UseType:%d", reg.Url, reg.UseType)
		newImage, err := parseImageFromNodeSafe(image.Repository)
		if err != nil {
			return img, err
		}
		img.NodeIp = newImage.NodeIp
		img.NodeHostname = newImage.NodeHostname
		img.OS = newImage.OS
		img.Library = newImage.Library

		img.FromType = model.ImageFromSafeNode
	}

	return img, nil
}

// RegToRegistryConf 把model.Registry转为registry.RegistrableComponentConfig
func RegToRegistryConf(reg model.Registry) registry.RegistrableComponentConfig {
	opt := make(map[string]interface{})
	opt["type"] = reg.RegType
	opt["registry_id"] = reg.ID
	opt["url"] = reg.Url
	opt["username"] = reg.Username
	opt["password"] = reg.PasswordString
	opt["skip_tls_verify"] = true
	opt["insecure"] = true

	if reg.RegType == hwswr.Version {
		opt["access_key"] = reg.Username
		opt["secret_key"] = reg.PasswordString
		opt["username"] = ""
		opt["password"] = ""
	}
	conf := registry.RegistrableComponentConfig{
		Type:    reg.RegType,
		Options: opt,
	}
	return conf
}

func parseImageFromNodeSafe(fullRepoName string) (*model.ImageList, error) {
	// tensorsecurity/tensorsec-safe-node-image-gjj92/10.65.72.63/linux/index.docker.io/calico/cni"
	// tensorsecurity/tensorsec-safe-node-image-v2x54/10.65.72.54/linux/registry.t-appagile.com/google_containers/coredns

	fullRepoName = strings.Trim(fullRepoName, " ")
	// fullRepoName = strings.Replace(fullRepoName, "_", ".", -1)
	split := strings.Split(fullRepoName, "/")
	if len(split) < 7 {
		return nil, fmt.Errorf("parse error  %s split is %d", fullRepoName, len(split))
	}
	if split[0] != consts.NodeSafeSalt {
		return nil, fmt.Errorf("parse error not fond NodeSafeSalt %s", fullRepoName)
	}
	// NodeSafeTage = NodeSafeSalt + "/%s/%s%s/%s" // tensorsec/hostname/ip/os/镜像名
	im := &model.ImageList{
		NodeIp:       split[2],
		OS:           split[3],
		NodeHostname: split[1],
		Library:      split[4],
	}
	return im, nil
}
