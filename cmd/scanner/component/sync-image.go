package component

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/suport/hwswr"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type SyncImageInterface interface {
	SyncImage(ctx context.Context) error
}

// SyncRepoImage sync registry repos and tags to db
type SyncRepoImage struct {
	registryDao            store.RegistryDalInterface
	ImageDal               store.ScannerDalInterface
	podResourceRelationDAl store.PodResourceRelationInterface
	ScanConfigDal          store.ScanConfigDalInterface
}

type RegistryWithConf struct {
	Registry registry.Registry
	Config   model.Registry
}

func (s *SyncRepoImage) GetSyncRegistry(ctx context.Context) ([]RegistryWithConf, error) {
	registries, _, err := s.registryDao.SearchRegistry(context.Background(),
		store.SearchRegistryParam{NoDelete: true, UseTypes: []int64{model.RegistryUseTypeNormal, model.RegistryUseSafeNode}}, nil)
	if err != nil {
		return nil, err
	}
	res := make([]RegistryWithConf, 0)
	for i := range registries {
		// 检查是否达到同步时间
		if time.Now().Unix()-registries[i].LastSyncAt < registries[i].SyncInterval*60 {
			continue
		}
		if err := s.registryDao.UpdateRegistry(ctx, store.SearchRegistryParam{ID: registries[i].ID}, map[string]interface{}{"last_sync_at": time.Now().Unix()}); err != nil {
			logging.GetLogger().Error().Err(err).Msg("UpdateRegistry last_sync_at error")
			continue
		}

		drive, err := registry.Open(RegToRegistryConf(registries[i]))
		if err != nil {
			logging.GetLogger().Err(err).Str("name", registries[i].Name).Msg("open registry driver err")
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

func NewSyncRepoImage(registryDao store.RegistryDalInterface, imageDal store.ScannerDalInterface, podResourceRelationDAl store.PodResourceRelationInterface, scanConfigDal store.ScanConfigDalInterface) *SyncRepoImage {
	return &SyncRepoImage{
		registryDao:            registryDao,
		ImageDal:               imageDal,
		podResourceRelationDAl: podResourceRelationDAl,
		ScanConfigDal:          scanConfigDal,
	}
}

func (s *SyncRepoImage) SyncImage(ctx context.Context) error {
	// defer wg.Done()
	var exitMap sync.Map

	worker := func(reg RegistryWithConf, extender registry.ImageListExtender) {
		start := time.Now().Unix()
		logging.GetLogger().Info().Msgf("start sync image,library name is :%s,url is:%s", reg.Config.Name, reg.Config.Url)

		res, err := reg.Registry.ListImages(extender, registry.ListImagesRequest{NeedToReturnAdded: true})
		if err != nil {
			logging.GetLogger().Error().Msgf("get images err.%v", err)
			exitMap.Store(reg.Config.Name, true)
			return
		}
		logging.GetLogger().Info().Msgf("SyncImage complete, start to generate scan tasks:%d", len(res.Added))

		configs, _, err := s.ScanConfigDal.SearchScanConfig(ctx, store.SearchScanConfigParam{}, nil)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("SearchScanConfig")
			exitMap.Store(reg.Config.Name, true)
			return
		}
		if len(configs) == 0 {
			logging.GetLogger().Info().Msg("SyncImage not fond scan config")
		}

		// 下发扫描任务
		if len(configs) > 0 {
			logging.GetLogger().Info().Interface("scan config", configs[0]).Msg("SyncImage")
			if configs[0].NodeImageConfig.ImageAddTrigEnable {
				imgIds := make([]int64, 0)
				for i := range res.Added {
					if configs[0].NodeImageConfig.ScanAll || InStringSlice(res.Added[i].NodeHostname, configs[0].NodeImageConfig.NodeHostnames) {
						if res.Added[i].FromType == model.ImageFromSafeNode {
							imgIds = append(imgIds, res.Added[i].ID)
						}
					}
				}

				if len(imgIds) > 0 {
					imgIds = DeDuplicationInt64Slice(imgIds)
					logging.GetLogger().Info().Int("ImageIds", len(imgIds)).Msg("SyncImage send library image scan tasks")
					ts := task.NewTaskSrv()
					if err := ts.GenerateScanTask(ctx, imgIds, task.UpdateTaskInfo{Scope: consts.SingleScan,
						TriggerType: consts.ImageSyncTrigger,
						StrategyID:  configs[0].NodeImageConfig.StrategyId}); err != nil {
						logging.GetLogger().Error().Err(err).Msg("SyncImage add scan task failed")
					}
				}
			}
			if configs[0].LibraryImageConfig.ImageAddTrigEnable {
				imgIds := make([]int64, 0)
				for i := range res.Added {
					if configs[0].LibraryImageConfig.ScanAll || InInt64Slice(res.Added[i].RegistryID, configs[0].LibraryImageConfig.Libraries) {
						if res.Added[i].FromType == model.ImageFromTypeNormal {
							imgIds = append(imgIds, res.Added[i].ID)
						}
					}
				}
				if len(imgIds) > 0 {
					imgIds = DeDuplicationInt64Slice(imgIds)

					logging.GetLogger().Info().Int("ImageIds", len(imgIds)).Msg("SyncImage send node image scan tasks")
					ts := task.NewTaskSrv()
					if err := ts.GenerateScanTask(ctx, imgIds, task.UpdateTaskInfo{
						Scope:       consts.SingleScan,
						TriggerType: consts.ImageSyncTrigger,
						StrategyID:  configs[0].LibraryImageConfig.StrategyId,
					}); err != nil {
						logging.GetLogger().Error().Err(err).Msg("SyncImage add scan task failed")
					}
				}
			}
		}
		exitMap.Store(reg.Config.Name, true)
		logging.GetLogger().Info().Msgf("end sync image,library name is :%s,url is:%s,cost:%d second", reg.Config.Name, reg.Config.Url, time.Now().Unix()-start)
	}

	for {
		// 每次都去数据库查询，因为数据增加了用户之后要能感知到
		logging.GetLogger().Info().Msg("start sync image")
		registries, err := s.GetSyncRegistry(context.Background())
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("查询仓库信息出错")
			time.Sleep(time.Duration(1) * time.Minute)
			continue
		}

		for i := range registries {
			if ex, ok := exitMap.Load(registries[i].Config.Name); ok {
				if ex1, ok := ex.(bool); ok && !ex1 {
					logging.GetLogger().Info().Msg("SyncImage.InsertImageList last synchronization has not been completed")
					continue
				}
			}

			reg := registries[i]
			exitMap.Store(reg.Config.Name, false)

			go worker(reg, func(image registry.Image) (*registry.ListImagesRes, error) {
				res := new(registry.ListImagesRes)
				img, err := s.TransImageToImagelist(ctx, reg.Config, image)

				if err != nil {
					if err != consts.ErrNotNodeImage {
						logging.GetLogger().Error().Err(err).Msgf("SyncImage.InsertImageList,error:%s", err.Error())
					}
					return nil, err
				}
				// 先查一下
				where := fmt.Sprintf("full_repo_name ='%s'  AND tags = '%s' AND from_type = %d AND registry_id = %d", img.FullRepoName, img.Tags, img.FromType, img.RegistryID)
				searchImage, _, err := s.ImageDal.SearchImage(ctx, store.SearchImageParam{Where: where}, nil)
				if err != nil {
					logging.GetLogger().Error().Err(err).Msg("SyncImage.InsertImageList")
					return nil, err
				}

				im, err := s.ImageDal.CreateImage(context.Background(), &img)
				if err != nil {
					logging.GetLogger().Error().Err(err).Msg("SyncImage.InsertImageList")
					return nil, err
				}
				if len(searchImage) == 0 {
					res.Added = append(res.Added, im)
					logging.GetLogger().Info().Msgf("sync new image:%d %s/%s:%s", im.ID, img.Library, img.FullRepoName, img.Tags)
				}
				res.All = append(res.All, im)
				return res, nil
			})
		}
		time.Sleep(time.Duration(1) * time.Minute) // 每分钟去查一次数据库
	}
}

func (s *SyncRepoImage) TransImageToImagelist(ctx context.Context, reg model.Registry, image registry.Image) (model.ImageList, error) {
	tmpLib := reg.Url
	tmpLib = strings.TrimPrefix(tmpLib, "http://") // trimPrefix http or https
	tmpLib = strings.TrimPrefix(tmpLib, "https://")
	tmpLib = strings.TrimRight(tmpLib, "/")

	imageID := fmt.Sprintf("%s/%s:%s", tmpLib, image.Repository, image.Tag)
	img := model.ImageList{
		FullRepoName:   image.Repository,
		Tags:           image.Tag,
		Digest:         image.ImageDigest,
		Size:           int(image.Size),
		Library:        reg.Url,
		RegistryID:     reg.ID,
		FirstPushTime:  image.Created,
		LastPushTime:   image.LastPushTime,
		LastPullTime:   image.LastPullTime,
		ManifestV1JSON: []byte(image.ManifestV1),
		ManifestV2JSON: []byte(image.ManifestV2),
		ConfigJSON:     []byte(image.ConfigJSON),
		FromType:       model.ImageFromTypeNormal,
		ImageUUID:      util.GenerateUUID(imageID),
	}
	if img.FirstPushTime.Unix() <= 0 {
		img.FirstPushTime = time.Now().UTC()
	}
	if img.LastPushTime.Unix() <= 0 {
		img.LastPushTime = time.Now().UTC()
	}
	if img.LastPullTime.Unix() <= 0 {
		img.LastPullTime = time.Now().UTC()
	}

	img.Layers = getLayerString(img)
	if reg.UseType == model.RegistryUseSafeNode {
		// logging.GetLogger().Info().Msgf("TransImageToImagelist Url:%s,UseType:%d", reg.Url, reg.UseType)
		newImage, err := s.parseImageFromNodeSafe(ctx, image.Repository)
		if err != nil {
			if err != consts.ErrNotNodeImage {
				logging.GetLogger().Error().Err(err).Msgf("reg.UseType:%d,reg.url:%s,error:%s", reg.UseType, reg.Url, err.Error())
			}
			return img, err
		}
		img.NodeIP = newImage.NodeIP
		img.NodeHostname = newImage.NodeHostname
		img.OS = newImage.OS
		img.Project = newImage.Project
		img.RepoName = newImage.RepoName

		img.FromType = model.ImageFromSafeNode
	} else if reg.UseType == model.RegistryUseTypeNormal {
		split := strings.Split(img.FullRepoName, "/")
		if len(split) >= 2 {
			img.Project = split[0]
			img.RepoName = strings.Join(split[1:], "/")
		}
	}
	var config model.ConfigFile
	err := json.Unmarshal(img.ConfigJSON, &config)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("unmarshal config json error")
	} else {
		if config.Config.User == "" || strings.Contains(config.Config.User, "root") {
			img.PrivilegedBoot = consts.PrivilegedBootImage
		}
		for _, v := range config.History {
			if strings.Contains(v.CreatedBy, "/tmp/file-checker") {
				img.IsReinforce = consts.IsReinforceImage
			}
		}
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
	opt["access_key"] = reg.AccessKey
	opt["access_secret"] = reg.AccessSecret

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

func (s *SyncRepoImage) parseImageFromNodeSafe(ctx context.Context, fullRepoName string) (*model.ImageList, error) {
	// tensorsecurity/clusterKey/namespace/podName/tensorsec-safe-node-image-v2x54/linux/registry.t-appagile.com/google_containers/coredns

	// 仓库地址/tensorsec/clusterKey/namespace/podName/os/镜像名
	fullRepoName = strings.Trim(fullRepoName, " ")
	// fullRepoName = strings.Replace(fullRepoName, "_", ".", -1)
	split := strings.Split(fullRepoName, "/")
	if len(split) < 7 {
		logging.GetLogger().Debug().Msgf("not node image:%s", fullRepoName)
		return nil, consts.ErrNotNodeImage
	}
	if split[0] != consts.NodeSafeSalt {
		logging.GetLogger().Debug().Msgf("parse error not fond NodeSafeSalt %s", fullRepoName)
		return nil, consts.ErrNotNodeImage
	}
	// NodeSafeTage = NodeSafeSalt + "/%s/%s%s/%s" // tensorsec/hostname/ip/os/镜像名
	clusterKey := split[1]
	namespace := split[2]
	namespace = strings.Replace(namespace, consts.ColonSalt, ":", -1)

	podName := split[3]
	info, err := s.podResourceRelationDAl.Search(ctx, namespace, clusterKey, podName)
	if err != nil {
		return nil, err
	}
	if len(info) == 0 {
		return nil, consts.ErrNotNodeImage
	}
	// logging.GetLogger().Info().Msgf("cluster info:%+v", info[0])

	im := &model.ImageList{
		NodeIP:       info[0].HostIP,
		OS:           split[4],
		NodeHostname: info[0].NodeName,
		Library:      split[5],
		Project:      split[6],
	}
	im.Library = strings.Replace(im.Library, consts.ColonSalt, ":", -1)

	if len(split) >= 8 {
		im.RepoName = strings.Join(split[7:], "/")
	}
	// NodeSafeTage     = NodeSafeSalt + "/%s/%s/%s/%s/%s" // tensorsec/clusterKey/namespace/podName/podIp/os/镜像名
	if !strings.Contains(im.Library, "http://") && !strings.Contains(im.Library, "https://") {
		im.Library = "https://" + im.Library
	}
	return im, nil
}
