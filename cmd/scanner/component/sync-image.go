package component

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/atomic"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type SyncImageInterface interface {
	SyncAllImage(ctx context.Context, param SyncAllImageParam) error      // 全部仓库全量同步
	SyncAddImage(ctx context.Context, syncType consts.SyncType) error     // 全部仓库增量同步
	RetryFailedSyncImage(ctx context.Context, lessRetryCount int64) error // 重试
	DeleteMoreRetryCount(ctx context.Context, moreRetryCount int64) error // 删除超过重试次数
	GetSyncStatus(ctx context.Context, syncType consts.SyncType) ([]ResponseGetSyncStatus, error)
}

// SyncRepoImage sync registry repos and tags to db
type SyncRepoImage struct {
	registryDal            store.RegistryDal
	imageDal               store.ScannerDalInterface
	podResourceRelationDAl store.PodResourceRelationDal
	vulnDal                store.VulnDalInterface
	scannerDB              *store.ScannerDB
	syncRetryImageDal      store.SyncRetryImageDal

	scanConfigDal   store.ScanConfigDal
	syncAllImageMap sync.Map // 不重复执行全量扫描
	syncAddImageMap sync.Map // 不重复执行增量扫描

	mutex *atomic.Int32 // 互斥锁
}

type ResponseGetSyncStatus struct {
	Status     bool  `json:"status"`
	RegistryID int64 `json:"registryID"`
}

func (s *SyncRepoImage) GetSyncStatus(ctx context.Context, syncType consts.SyncType) ([]ResponseGetSyncStatus, error) {
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{NoDelete: true, UseTypes: []int64{model.UserRegistry, model.NodeBuffRegistry}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("GetSyncStatus")
		return nil, err
	}
	ans := make([]ResponseGetSyncStatus, 0)

	for i := range registries {
		status := ResponseGetSyncStatus{RegistryID: registries[i].ID}
		switch syncType {
		case consts.ManualSync, consts.TimingFullSync, consts.CycleFullSync:
			if ex, ok := s.syncAllImageMap.Load(registries[i].ID); ok {
				if ex1, ok := ex.(bool); ok {
					status.Status = ex1
				}
			}

		case consts.CycleIncSync:
			if ex, ok := s.syncAddImageMap.Load(registries[i].ID); ok {
				if ex1, ok := ex.(bool); ok {
					status.Status = ex1
				}
			}
		}
		ans = append(ans, status)

	}
	return ans, nil
}

func NewSyncRepoImage(
	registryDal store.RegistryDal,
	imageDal store.ScannerDalInterface,
	podResourceRelationDAl store.PodResourceRelationDal,
	scanConfigDal store.ScanConfigDal,
	syncRetryImageDal store.SyncRetryImageDal,
	vulnDal store.VulnDalInterface,
	scannerDB *store.ScannerDB,
) *SyncRepoImage {
	return &SyncRepoImage{
		registryDal:            registryDal,
		imageDal:               imageDal,
		podResourceRelationDAl: podResourceRelationDAl,
		vulnDal:                vulnDal,
		scannerDB:              scannerDB,
		syncRetryImageDal:      syncRetryImageDal,
		scanConfigDal:          scanConfigDal,
		syncAllImageMap:        sync.Map{},
		syncAddImageMap:        sync.Map{},
		mutex:                  atomic.NewInt32(NoRunning),
	}
}

// 定期重试
func (s *SyncRepoImage) RetryFailedSyncImage(ctx context.Context, lessRetryCount int64) error {
	if err := s.preSync(ctx, consts.RetryIncSync); err != nil {
		return err
	}

	defer s.mutex.Store(NoRunning)

	logging.GetLogger().Info().Msg("start RetryFailedSyncImage")

	needRetry, err := s.syncRetryImageDal.SearchImageRetry(ctx, store.SearchImageRetryParam{LessRetryCount: lessRetryCount})
	if err != nil {
		logging.GetLogger().Err(err).Msg("RetryFailedSync.ImageSearchImageRetry")
		return err
	}
	mm := make(map[int64][]model.SyncRetryImage)
	for i := range needRetry {
		if mm[needRetry[i].RegistryID] == nil {
			mm[needRetry[i].RegistryID] = make([]model.SyncRetryImage, 0)
		}
		mm[needRetry[i].RegistryID] = append(mm[needRetry[i].RegistryID], needRetry[i])
	}

	for regId, images := range mm {
		diver, err := s.getSyncRegistryByRegID(ctx, regId)
		if err != nil {
			logging.GetLogger().Err(err).Msg("RetryFailedSync.getSyncRegistryByRegID")
			return err
		}

		res, err := diver.Registry.ImageRetry(context.Background(), s.getExtender(), registry.ImageRetryRequest{RetryImages: images})
		if err != nil {
			logging.GetLogger().Err(err).Msg("RetryFailedSync.ImageRetry")
			return err
		}
		if err := s.addScanTask(ctx, res); err != nil {
			logging.GetLogger().Err(err).Msg("addScanTask")
			return err
		}
	}
	return err
}

// 定期删除超过重试次数
func (s *SyncRepoImage) DeleteMoreRetryCount(ctx context.Context, moreRetryCount int64) error {
	err := s.syncRetryImageDal.DeleteImageRetry(ctx, store.SearchImageRetryParam{MoreRetryCount: moreRetryCount})
	if err != nil {
		logging.GetLogger().Err(err).Msg("DeleteImageRetry")
		return err
	}
	return nil
}

func (s *SyncRepoImage) SyncAllImage(ctx context.Context, param SyncAllImageParam) error {
	if err := s.preSync(ctx, param.SyncType); err != nil {
		return err
	}

	defer s.mutex.Store(NoRunning)

	logging.GetLogger().Info().Str("syncType", string(param.SyncType)).Msg("SyncAllImage start")

	// 每次都去数据库查询，因为数据增加了用户之后要能感知到
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{
		UseTypes:    []int64{model.UserRegistry, model.NodeBuffRegistry},
		RegistryIds: param.RegistryIds,
		NoDelete:    true}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("查询仓库信息出错")
		return err
	}
	logging.GetLogger().Info().Str("syncType", string(param.SyncType)).Interface("registries", registries).Msg("SyncAllImage start")

	for i := range registries {
		driver, err := s.getRegistryDriver(ctx, registries[i])
		if err != nil {
			logging.GetLogger().Err(err).Str("regName", registries[i].Name).Str("regUrl", registries[i].Url).Msg("SyncAddImage getRegistryDriver")
			continue
		}
		regID := registries[i].ID

		if (registries[i].WhetherToStartSync() && !driver.SupportIncrementalSync(ctx)) || param.SyncType == consts.TimingFullSync || param.SyncType == consts.ManualSync {
			// 兜底的同步，不需要同步缓存仓库
			if param.SyncType == consts.TimingFullSync && registries[i].UseType != model.UserRegistry {
				continue
			}

			logging.GetLogger().Info().Str("syncType", string(param.SyncType)).Int64("regID", regID).Msg("SyncAllImage start")
			if err := s.startSyncAllImage(ctx, regID, param.SyncType); err != nil {
				logging.GetLogger().Err(err).Str("regName", registries[i].Name).Str("syncType", string(param.SyncType)).Msg("SyncAllImage failure")
			}
		}
	}
	logging.GetLogger().Info().Str("syncType", string(param.SyncType)).Msg("SyncAllImage end")
	return nil
}

func (s *SyncRepoImage) preSync(ctx context.Context, syncType consts.SyncType) error {

	// 持续等待，直到抢到锁
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()
	ti := 0
	for {
		<-ticker.C
		logging.GetLogger().Info().Str("syncType", string(syncType)).Msg("preSync try to get lock")

		if syncType == consts.TimingFullSync {
			if !s.getAndSetMutex(ctx, NoRunning, ClearUpRunning) {
				logging.GetLogger().Info().Str("syncType", string(syncType)).Int32("preTask", s.mutex.Load()).Msg("has task is running")
				ti++
			} else {
				break
			}
		} else {
			if !s.getAndSetMutex(ctx, NoRunning, SyncRunning) && !s.getAndSetMutex(ctx, SyncRunning, SyncRunning) {
				logging.GetLogger().Info().Str("syncType", string(syncType)).Int32("preTask", s.mutex.Load()).Msg("has task is running")
				ti++
			} else {
				break
			}
		}

		if ti > 12*10 { // 最多等待10分钟
			logging.GetLogger().Info().Str("syncType", string(syncType)).Msg("preSync not get lock")
			return fmt.Errorf("%s not get lock", string(syncType))
		}
	}
	return nil
}

func (s *SyncRepoImage) SyncAddImage(ctx context.Context, syncType consts.SyncType) error {
	if err := s.preSync(ctx, syncType); err != nil {
		return err
	}

	defer s.mutex.Store(NoRunning)

	// 每次都去数据库查询，因为数据增加了用户之后要能感知到
	logging.GetLogger().Info().Str("syncType", string(syncType)).Msg("SyncAddImage start")
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{
		UseTypes: []int64{model.UserRegistry, model.NodeBuffRegistry},
		NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("查询仓库信息出错")
		return err
	}

	for i := range registries {
		driver, err := s.getRegistryDriver(ctx, registries[i])
		if err != nil {
			logging.GetLogger().Err(err).Str("regName", registries[i].Name).Str("regUrl", registries[i].Url).Msg("SyncAddImage getRegistryDriver")
			continue
		}

		if !driver.SupportIncrementalSync(ctx) {
			continue
		}

		if err := s.startSyncIncrementallyImage(ctx, registries[i].ID); err != nil {
			logging.GetLogger().Err(err).Str("regName", registries[i].Name).Str("regUrl", registries[i].Url).Msg("SyncAddImage failure")
			continue
		}
	}
	logging.GetLogger().Info().Str("syncType", string(syncType)).Msg("SyncAddImage end")
	return nil
}

func (s *SyncRepoImage) clearUpImage(ctx context.Context, imageIds []int64) error {
	if len(imageIds) == 0 {
		return nil
	}
	// 清理镜像时排除在线镜像
	onlineSQL := fmt.Sprintf("select distinct a.id  from  %s a  join %s b  on  a.image_uuid = b.image_uuid where b.status = 0", model.ImageList{}.TableName(), model.TensorContainer{}.TableName())
	online, err := s.imageDal.GetOnlineImage(ctx, store.GetOnlineImageParam{SQL: onlineSQL})
	if err != nil {
		logging.GetLogger().Err(err).Msg("GetOnlineImageId.GetOnlineImage")
		return err
	}
	onlineMap := make(map[int64]bool)
	for i := range online {
		onlineMap[online[i].ID] = true
	}
	logging.GetLogger().Info().Msg("ClearUp start")

	deleteIds := make([]int64, 0)

	for i := range imageIds {
		if !onlineMap[imageIds[i]] {
			deleteIds = append(deleteIds, imageIds[i])
		}
	}
	if len(deleteIds) == 0 {
		return nil
	}
	// 为了防止其他数据已清除ivan_scanner_image_list未删除的情况， 先删除 ivan_scanner_image_list 表，
	// 这情情况下可能会出现脏数据,之后版本时间充足时再修复
	if err := s.imageDal.DeleteImage(ctx, deleteIds); err != nil {
		logging.GetLogger().Err(err).Msg("ClearUp")
		return err
	}
	// 删除 ivan_scanner_vuln_images表
	if err := s.vulnDal.DeleteVulnImage(ctx, deleteIds); err != nil {
		logging.GetLogger().Err(err).Msg("ClearUp")
		return err
	}

	// 删除 ivan_scanner_scan_layers 表
	if err := s.scannerDB.DeleteScanLayer(ctx, deleteIds); err != nil {
		logging.GetLogger().Err(err).Msg("ClearUp")
		return err
	}
	// 删除 ivan_scanner_scan_images 表
	if err := s.imageDal.DeleteScanImage(ctx, deleteIds); err != nil {
		logging.GetLogger().Err(err).Msg("ClearUp")
		return err
	}

	logging.GetLogger().Info().Msg("ClearUp end")
	return nil
}

// 清理已删除的仓库的镜像
func (s *SyncRepoImage) clearUpImageAfterDeleteRegistry(ctx context.Context) error {
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{NoDelete: false}, nil)
	if err != nil {
		return err
	}
	for i := range registries {
		if registries[i].DeletedAt == 0 {
			continue
		}
		regID := registries[i].ID
		var startID int64
		for {
			image, _, err := s.imageDal.SearchImage(ctx, store.SearchImageParam{StartID: startID, Fields: []string{"id"}, RegistryIds: []int64{regID}},
				&model.Filter{Limit: consts.DefaultLimit, SortFiled: "id", SortBy: consts.SortByAsc})
			if err != nil {
				return err
			}
			if len(image) == 0 {
				break
			}
			startID = image[len(image)-1].ID
			imaIds := make([]int64, 0)
			for j := range image {
				imaIds = append(imaIds, image[j].ID)
			}

			if err := s.clearUpImage(ctx, imaIds); err != nil {
				return err
			}
		}
	}
	return nil
}

// 全量同步
func (s *SyncRepoImage) startSyncAllImage(ctx context.Context, regID int64, syncType consts.SyncType) error {
	logging.GetLogger().Info().Int64("regID", regID).Str("syncType", string(syncType)).Msg("StartSyncAllImage start")
	regs, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{ID: regID}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("查询仓库信息出错")
		return err
	}

	reg := regs[0]
	logging.GetLogger().Info().Str("regName", reg.Name).Int64("regID", regID).Str("regUrl", reg.Url).Msg("StartSyncAllImage start")
	defer s.syncAllImageMap.Store(reg.ID, consts.NotSyncingImage)
	driver, err := s.getRegistryDriver(ctx, reg)
	if err != nil {
		logging.GetLogger().Err(err).Str("regName", reg.Name).Msg("StartSyncAllImage.getRegistryDriver")
		return err
	}

	if ex, ok := s.syncAllImageMap.Load(reg.ID); ok {
		if ex1, ok := ex.(bool); ok && ex1 == consts.IsSyncingImage {
			logging.GetLogger().Info().Str("regName", reg.Name).Str("regUrl", reg.Url).Msg("StartSyncAllImage last synchronization has not been completed")
			return nil
		}
	}

	s.syncAllImageMap.Store(reg.ID, consts.IsSyncingImage)
	now := time.Now().Unix()
	res, err := driver.ListImages(ctx, s.getExtender(), registry.ListImagesRequest{NeedToReturnAdded: true, NeedToReturnAll: false})
	if err != nil {
		logging.GetLogger().Err(err).Msg("StartSyncAllImage get images err")
		return nil
	}
	if err := s.registryDal.UpdateRegistry(ctx, store.SearchRegistryParam{ID: reg.ID}, map[string]interface{}{"last_sync_at": now}); err != nil {
		logging.GetLogger().Err(err).Msg("StartSyncAllImage UpdateRegistry last_sync_at error")
	}

	// 下发扫描任务
	if err := s.addScanTask(ctx, res); err != nil {
		logging.GetLogger().Err(err).Msg("StartSyncAllImage.addScanTask")
	}
	logging.GetLogger().Info().
		Str("regName", reg.Name).
		Str("regUrl", reg.Url).
		Int("all-images", len(res.All)).
		Int("add-images", len(res.Added)).
		Int64("Cost", time.Now().Unix()-now).
		Bool("HasErr", res.HasErr).
		Msg("StartSyncAllImage end")

	if syncType != consts.TimingFullSync || res.HasErr {
		logging.GetLogger().Info().
			Str("syncType", string(syncType)).
			Bool("HasErr", res.HasErr).Msg("not ClearUp image")
		return nil
	}

	if syncType == consts.TimingFullSync && !res.HasErr {
		// 标记清理任务
		logging.GetLogger().Info().Int64("regID", regID).Str("regName", reg.Name).Msg("start searchDeletedImage")
		deleteIds, err := s.searchDeletedImage(ctx, now, regID)
		if err != nil {
			logging.GetLogger().Err(err).Msg("StartSyncAllImage.searchDeletedImage")
			return err
		}
		logging.GetLogger().Info().Int64("regID", regID).Str("regName", reg.Name).Msg("end searchDeletedImage")

		// 然后马上执行删除
		if err := s.clearUpImage(ctx, deleteIds); err != nil {
			logging.GetLogger().Err(err).Msg("ClearUp after TimingFullSync clearUP failure")
			return err
		}
		logging.GetLogger().Info().Int64("regID", regID).Msg("ClearUp after TimingFullSync clearUP success")

		if err := s.clearUpImageAfterDeleteRegistry(ctx); err != nil {
			logging.GetLogger().Err(err).Msg("ClearUp after TimingFullSync clearUpImageAfterDeleteRegistry failure")
			return err
		}
		logging.GetLogger().Info().Int64("regID", regID).Msg("ClearUp after TimingFullSync clearUpImageAfterDeleteRegistry success")

	}

	return nil
}

// 增量同步
func (s *SyncRepoImage) startSyncIncrementallyImage(ctx context.Context, regID int64) error {
	logging.GetLogger().Info().Int64("regID", regID).Msg("StartSyncIncrementallyImage start")

	regs, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{ID: regID}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Int64("regID", regID).Msg("查询仓库信息出错")
		return err
	}

	if len(regs) == 0 {
		return nil
	}

	reg := regs[0]

	if reg.LastSyncAt <= 0 {
		logging.GetLogger().Info().Int64("LastSyncAt", reg.LastSyncAt).Msg("StartSyncIncrementallyImage start must more than 0")
		return nil
	}

	defer s.syncAddImageMap.Store(reg.ID, consts.NotSyncingImage)

	if ex, ok := s.syncAddImageMap.Load(reg.ID); ok {
		if ex1, ok := ex.(bool); ok && ex1 == consts.IsSyncingImage {
			logging.GetLogger().Info().Str("regName", reg.Name).Str("regUrl", reg.Url).Msg("StartSyncIncrementallyImage last synchronization has not been completed")
			return nil
		}
	}
	driver, err := s.getRegistryDriver(ctx, reg)
	if err != nil {
		logging.GetLogger().Err(err).Str("regName", reg.Name).Msg("StartSyncIncrementallyImage.getRegistryDriver")
		return err
	}
	if !driver.SupportIncrementalSync(ctx) {
		return nil
	}

	now := time.Now().Unix()
	logging.GetLogger().Info().Str("regName", reg.Name).Str("regUrl", reg.Url).Msg("StartSyncIncrementallyImage start")
	s.syncAddImageMap.Store(reg.ID, consts.IsSyncingImage)

	res, err := driver.ListImagesWithAuditLog(ctx, s.getExtender(),
		registry.ListImagesAuditLog{
			StartAt: reg.LastSyncAt,
			EndAt:   now,
		})
	if err != nil {
		logging.GetLogger().Err(err).Msg("ListImagesWithAuditLog")
		return err
	}
	if !res.GetAuditLogError {
		if err := s.registryDal.UpdateRegistry(ctx, store.SearchRegistryParam{ID: reg.ID}, map[string]interface{}{"last_sync_at": now}); err != nil {
			logging.GetLogger().Err(err).Msg("UpdateRegistry last_sync_at error")
		}
	}

	// 下发扫描任务
	if err := s.addScanTask(ctx, res); err != nil {
		logging.GetLogger().Err(err).Msg("StartSyncIncrementallyImage.addScanTask")
	}
	logging.GetLogger().Info().
		Str("regName", reg.Name).
		Str("regUrl", reg.Url).
		Int("all-images", len(res.All)).
		Int("add-images", len(res.Added)).
		Int64("Cost", time.Now().Unix()-now).
		Msg("StartSyncIncrementallyImage end")
	return nil
}

func (s *SyncRepoImage) searchDeletedImage(ctx context.Context, lastFullSyncAt int64, registryID int64) ([]int64, error) {
	// 找出已删除的镜像
	image, _, err := s.imageDal.SearchImage(ctx, store.SearchImageParam{Where: fmt.Sprintf("registry_id = %d AND last_full_sync_at < %d", registryID, lastFullSyncAt), Fields: []string{"id", "last_full_sync_at"}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchImage")
		return nil, err
	}
	imageIds := make([]int64, len(image))
	for i := range image {
		imageIds[i] = image[i].ID
	}
	return imageIds, nil
}

func (s *SyncRepoImage) transImageToImageList(ctx context.Context, image registry.Image) (model.ImageList, error) {
	tmpLib := image.RegistryUrl
	tmpLib = strings.TrimPrefix(tmpLib, "http://") // trimPrefix http or https
	tmpLib = strings.TrimPrefix(tmpLib, "https://")
	tmpLib = strings.TrimRight(tmpLib, "/")

	img := model.ImageList{
		FullRepoName:   image.Repository,
		Tags:           image.Tag,
		Digest:         image.ImageDigest,
		Size:           int(image.Size),
		Library:        image.RegistryUrl,
		RegistryID:     image.RegistryID,
		FirstPushTime:  image.Created,
		LastPushTime:   image.LastPushTime,
		LastPullTime:   image.LastPullTime,
		ManifestV1JSON: []byte(image.ManifestV1),
		ManifestV2JSON: []byte(image.ManifestV2),
		ConfigJSON:     []byte(image.ConfigJSON),
		FromType:       image.FromType,
		ImageUUID:      util.GenerateUUID(fmt.Sprintf("%s/%s:%s", tmpLib, image.Repository, image.Tag)),
		LastFullSyncAt: time.Now().UnixMilli(),
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

	if img.FromType == model.NodeBuffRegistry {
		// logging.GetLogger().Info().Msgf("transImageToImageList Url:%s,UseType:%d", reg.Url, reg.UseType)
		newImage, err := s.parseImageFromNodeSafe(ctx, image.Repository)
		if err != nil {
			if err != consts.ErrNotNodeImage {
				logging.GetLogger().Err(err).Msgf("reg.UseType:%d,reg.url:%s", image.FromType, image.RegistryUrl)
			}
			return img, err
		}
		img.NodeIP = newImage.NodeIP
		img.NodeHostname = newImage.NodeHostname
		img.OS = newImage.OS
		img.Project = newImage.Project
		img.RepoName = newImage.RepoName
		img.FromType = model.NodeBuffRegistry
	} else if image.FromType == model.UserRegistry {
		split := strings.Split(img.FullRepoName, "/")
		if len(split) >= 2 {
			img.Project = split[0]
			img.RepoName = strings.Join(split[1:], "/")
		}
	}
	img.Deserialize(false)
	if img.ConfigFile != nil {
		if img.ConfigFile.Config.User == "" || strings.Contains(img.ConfigFile.Config.User, "root") {
			img.PrivilegedBoot = consts.PrivilegedBootImage
		}
		for _, v := range img.ConfigFile.History {
			if strings.Contains(v.CreatedBy, "/tmp/file-checker") {
				img.IsReinforce = consts.IsReinforceImage
			}
		}
	}

	img.Layers = img.GetLayerString()
	img.CheckSum = img.GenImageCheckSum()

	return img, nil
}

// RegToRegistryConf 把model.Registry转为registry.RegistrableComponentConfig
func RegToRegistryConf(reg model.Registry) registry.RegistrableComponentConfig {
	opt := make(map[string]interface{})
	opt["type"] = reg.RegType
	opt["use_type"] = reg.UseType
	opt["registry_id"] = reg.ID
	opt["url"] = reg.Url
	opt["username"] = reg.Username
	opt["password"] = reg.PasswordString
	opt["skip_tls_verify"] = true
	opt["insecure"] = true
	opt["access_key"] = reg.AccessKey
	opt["access_secret"] = reg.AccessSecret
	opt["instance_id"] = reg.InstanceID
	opt["region_id"] = reg.RegionID

	if reg.RegType == consts.HaiWeiSwrVersion {
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
	if len(split) <= model.NodeImageSplitCount {
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

	if len(split) >= model.NodeImageSplitCount+1 {
		im.RepoName = strings.Join(split[model.NodeImageSplitCount+1:], "/")
	}
	// NodeSafeTage     = NodeSafeSalt + "/%s/%s/%s/%s/%s" // tensorsec/clusterKey/namespace/podName/podIp/os/镜像名
	if !strings.Contains(im.Library, "http://") && !strings.Contains(im.Library, "https://") {
		im.Library = "https://" + im.Library
	}
	return im, nil
}

func (s *SyncRepoImage) createImageExtender(ctx context.Context, image registry.Image) (*registry.ListImagesRes, error) {
	res := new(registry.ListImagesRes)
	img, err := s.transImageToImageList(ctx, image)

	if err != nil {
		if err != consts.ErrNotNodeImage {
			logging.GetLogger().Err(err).Msgf("SyncAllImage.InsertImageList,error:%s", err.Error())
		}
		return nil, err
	}
	// 先查一下
	img.UniqueImage = img.GenUniqueImage()
	searchImage, _, err := s.imageDal.SearchImage(ctx, store.SearchImageParam{UniqueImage: img.UniqueImage,
		OmitFields: []string{"config_json", "manifest_v1_json", "manifest_v2_json"}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SyncAllImage.InsertImageList")
		return nil, err
	}
	if len(searchImage) == 0 {
		img.GenImageFlag()
		img.SetScanStatusFlag(model.FlagImageNotScan)
		if _, err := s.imageDal.CreateImage(context.Background(), &img); err != nil {
			logging.GetLogger().Err(err).Msg("SyncAllImage.InsertImageList")
			return nil, err
		}
		res.Added = append(res.Added, &img)
		logging.GetLogger().Debug().Int64("RegistryID", img.RegistryID).
			Int64("FromType", img.FromType).
			Str("Library", img.Library).
			Str("FullRepoName", img.FullRepoName).
			Str("Tag", img.Tags).
			Uint64("flag", img.Flag).
			Int64("imageID", img.ID).
			Msg("sync new image Create")
	}
	// 如果值有变动，就全量更新
	if len(searchImage) > 0 {
		img.Flag = searchImage[0].Flag
		img.GenImageFlag()

		img.CheckSum = img.GenImageCheckSum()
		if img.CheckSum != searchImage[0].CheckSum || img.Digest != searchImage[0].Digest {
			res.Added = append(res.Added, &img)
			// 全量更新
			if err := s.imageDal.UpdateImage(ctx, fmt.Sprintf("id = %d", searchImage[0].ID), nil, &img); err != nil {
				logging.GetLogger().Err(err).Msg("SyncAllImage.InsertImageList,UpdateImageType")
				return nil, err
			}
			logging.GetLogger().Debug().Int64("RegistryID", img.RegistryID).
				Int64("FromType", img.FromType).
				Str("Library", img.Library).
				Str("FullRepoName", img.FullRepoName).
				Uint64("flag", img.Flag).
				Uint64("preFlag", searchImage[0].Flag).
				Int64("imageID", searchImage[0].ID).
				Str("Tag", img.Tags).Msg("sync new image Update")
		} else {
			// 如果没有变动，就只更新LastFullSyncAt
			updater := map[string]interface{}{"last_full_sync_at": img.LastFullSyncAt}
			if err := s.imageDal.UpdateImage(ctx, fmt.Sprintf("id = %d", searchImage[0].ID), updater, nil); err != nil {
				logging.GetLogger().Err(err).Msg("SyncAllImage.InsertImageList,UpdateImageType")
				return nil, err
			}

			logging.GetLogger().Debug().Int64("RegistryID", img.RegistryID).
				Int64("FromType", img.FromType).
				Str("Library", img.Library).
				Str("FullRepoName", img.FullRepoName).
				Uint64("flag", img.Flag).
				Uint64("preFlag", searchImage[0].Flag).
				Int64("imageID", searchImage[0].ID).
				Str("Tag", img.Tags).Msg("The data already exists and has not changed, no need to synchronize")
		}
	}
	res.All = append(res.All, &img)
	return res, nil
}

func (s *SyncRepoImage) updateImageLastSyncExtender(ctx context.Context, image registry.Image) error {
	img := model.ImageList{
		FullRepoName: image.Repository,
		Tags:         image.Tag,
		RegistryID:   image.RegistryID,
		FromType:     image.FromType,
	}

	img.UniqueImage = img.GenUniqueImage()
	// 更新最后同步时间，做删除处理
	updater := map[string]interface{}{"last_full_sync_at": time.Now().UnixMilli()}
	if err := s.imageDal.UpdateImage(ctx, fmt.Sprintf("unique_image = %d", img.UniqueImage), updater, nil); err != nil {
		logging.GetLogger().Err(err).Msg("SyncAllImage.updateImageLastSyncExtender,UpdateImage")
		return err
	}
	return nil
}

func (s *SyncRepoImage) createOrAddRetryCountExtender(ctx context.Context, image registry.Image) error {
	data := model.SyncRetryImage{
		FullRepoName: image.Repository,
		Tag:          image.Tag,
		RegistryID:   image.RegistryID,
		Message:      image.Message,
	}
	data.UniqueImage = data.GenUniqueImage()

	// 先查一下，
	imageRetry, err := s.syncRetryImageDal.SearchImageRetry(ctx, store.SearchImageRetryParam{UniqueImage: data.UniqueImage})
	if err != nil {
		logging.GetLogger().Err(err).Str("FullRepoName", data.FullRepoName).Str("Tag", data.Tag).Msg("SyncAllImage.SearchImageRetry")
		return err
	}
	if len(imageRetry) > 0 {
		if err := s.syncRetryImageDal.AddRetryCount(ctx, data.UniqueImage); err != nil {
			logging.GetLogger().Err(err).Str("FullRepoName", data.FullRepoName).Str("Tag", data.Tag).Msg("SyncAllImage.AddRetryCount")
			return err
		}
		return nil
	}
	if err := s.syncRetryImageDal.CreateImageRetry(ctx, data); err != nil {
		logging.GetLogger().Err(err).Str("FullRepoName", data.FullRepoName).Str("Tag", data.Tag).Msg("SyncAllImage.CreateImageRetry")
		return err
	}
	return nil
}

func (s *SyncRepoImage) deleteImageRetryExtender(ctx context.Context, image registry.Image) error {
	data := model.SyncRetryImage{
		FullRepoName: image.Repository,
		Tag:          image.Tag,
		RegistryID:   image.RegistryID,
	}
	data.UniqueImage = data.GenUniqueImage()

	// 先查一下，
	err := s.syncRetryImageDal.DeleteImageRetry(ctx, store.SearchImageRetryParam{UniqueImage: data.UniqueImage})
	if err != nil {
		logging.GetLogger().Err(err).Str("FullRepoName", data.FullRepoName).Str("Tag", data.Tag).Msg("SyncAllImage.SearchImageRetry")
		return err
	}
	return nil
}

func (s *SyncRepoImage) getExtender() registry.Extender {
	return registry.Extender{
		CreateImageExtender:           s.createImageExtender,
		CreateOrAddRetryCountExtender: s.createOrAddRetryCountExtender,
		DeleteImageRetryExtender:      s.deleteImageRetryExtender,
		UpdateImageLastSyncExtender:   s.updateImageLastSyncExtender,
	}
}

func (s *SyncRepoImage) addScanTask(ctx context.Context, res *registry.ListImagesRes) error {
	// 下发扫描任务
	configs, _, err := s.scanConfigDal.SearchScanConfig(ctx, store.SearchScanConfigParam{}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchScanConfig")
		return err
	}
	if len(configs) == 0 {
		logging.GetLogger().Warn().Msg("not fond scan config")
		return fmt.Errorf("not find scan config")
	}
	config := configs[0]
	logging.GetLogger().Debug().Interface("scan config", config).Msg("addScanTask")
	if config.NodeImageAddTrigEnable {
		imgIds := make([]int64, 0)
		for i := range res.Added {
			// 更新需求，所有的节点的新增镜像都会创建扫描任务
			if res.Added[i].FromType == model.NodeBuffRegistry {
				imgIds = append(imgIds, res.Added[i].ID)
			}
		}
		imgIds = util.DeDuplicationInt64Slice(imgIds)
		if len(imgIds) > 0 {
			logging.GetLogger().Info().Int("ImageIds", len(imgIds)).Msg("addScanTask send node image scan tasks")
			ts := task.NewTaskSrv()
			if err := ts.GenerateScanTask(ctx, imgIds, task.UpdateTaskInfo{Scope: consts.SingleScan,
				TriggerType: consts.ImageSyncTrigger,
				Operator:    consts.SyncTriggerOperator,
				StrategyID:  config.NodeImageConfig.StrategyID}); err != nil {
				logging.GetLogger().Err(err).Msg("addScanTask add scan task failed")
				return err
			}
		}
	}
	if config.LibraryImageAddTrigEnable {
		imgIds := make([]int64, 0)
		for i := range res.Added {
			// 更新需求，所有的仓库的新增镜像都会创建扫描任务
			if res.Added[i].FromType == model.UserRegistry {
				imgIds = append(imgIds, res.Added[i].ID)
			}
		}
		imgIds = util.DeDuplicationInt64Slice(imgIds)
		if len(imgIds) > 0 {
			logging.GetLogger().Info().Int("ImageIds", len(imgIds)).Msg("addScanTask send library image scan tasks")
			ts := task.NewTaskSrv()
			if err := ts.GenerateScanTask(ctx, imgIds, task.UpdateTaskInfo{
				Scope:       consts.SingleScan,
				Operator:    consts.SyncTriggerOperator,
				TriggerType: consts.ImageSyncTrigger,
				StrategyID:  config.LibraryImageConfig.StrategyID,
			}); err != nil {
				logging.GetLogger().Err(err).Msg("addScanTask add scan task failed")
				return err
			}
		}
	}
	return nil
}

func (s *SyncRepoImage) getRegistryDriver(ctx context.Context, reg model.Registry) (registry.Registry, error) {

	drive, err := registry.Open(RegToRegistryConf(reg))
	if err != nil {
		logging.GetLogger().Err(err).Str("name", reg.Name).Msg("open registry driver err")
		return nil, err
	}
	if err := drive.Ping(); err != nil {
		logging.GetLogger().Err(err).Msgf("尝试连接到仓库出错:%s", reg.Name)
		return nil, err
	}

	return drive, nil
}

func (s *SyncRepoImage) getSyncRegistryByRegID(ctx context.Context, registryId int64) (*registry.RegistryWithConf, error) {

	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{NoDelete: true,
		UseTypes: []int64{model.UserRegistry, model.NodeBuffRegistry}, RegistryIds: []int64{registryId}}, nil)
	if err != nil {
		return nil, err
	}
	if len(registries) == 0 {
		return nil, fmt.Errorf("not fond registry registryId:%d", registryId)
	}

	drive, err := registry.Open(RegToRegistryConf(registries[0]))
	if err != nil {
		logging.GetLogger().Err(err).Str("name", registries[0].Name).Msg("open registry driver err")
		return nil, err
	}
	if err := drive.Ping(); err != nil {
		logging.GetLogger().Err(err).Msgf("尝试连接到仓库出错:%s", registries[0].Name)
		return nil, err
	}

	res := registry.RegistryWithConf{
		Registry: drive,
		Config:   registries[0],
	}
	return &res, nil
}

func (s *SyncRepoImage) getAndSetMutex(ctx context.Context, oldTask, newTask int32) bool {
	return s.mutex.CAS(oldTask, newTask)
}

type SyncAllImageParam struct {
	RegistryIds []int64 `json:"registryIds"`
	SyncType    consts.SyncType
}

type SyncAddImageParam struct {
	RegistryId int64 `json:"registryId"`
}

const (
	NoRunning      = 0
	ClearUpRunning = 1
	SyncRunning    = 2
)
