package imagemeta

import (
	"context"
	"os"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta/metaGlobal"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageUpdateService interface {
	ContinueUpdate(ctx context.Context) error
}

type ImageUpdateSrv struct {
	imageDal        imagesecStore.ImageMetaDal
	registryDal     imagesecStore.RegistryDal
	policyDal       imagesecStore.DetectPolicyDal
	detectResultDal imagesecStore.ImageDetectResultDal
	detectTaskDal   imagesecStore.DetectTaskDal
	scanIssueDal    imagesecStore.ScanIssueDal
	trustedDal      adaptStore.TrustedImageDal
	configDal       imagesecStore.ScanImageConfigDal
	scanTaskDal     imagesecStore.ScanTaskDal
	nodeDal         imagesecStore.NodeInfoDal
	scanResult      imagesecStore.ScanResultDal
	imageCacheDal   imagesecStore.ImageCacheDal
	imageDetectSrv  detect.ImageDetectTaskService
	preImageDal     adaptStore.ImageDal
	onlineImageDal  imagesecStore.OnlineImageDal
	TrustedDigest   map[string]struct{} // 可信镜像的 digest
	Log             *scannerUtils.LogEvent
}

func NewImageUpdateSrv(
	imageDal imagesecStore.ImageMetaDal,
	registryDal imagesecStore.RegistryDal,
	policyDal imagesecStore.DetectPolicyDal,
	detectResultDal imagesecStore.ImageDetectResultDal,
	detectTaskDal imagesecStore.DetectTaskDal,
	scanIssueDal imagesecStore.ScanIssueDal,
	trustedDal adaptStore.TrustedImageDal,
	configDal imagesecStore.ScanImageConfigDal,
	nodeTaskDal imagesecStore.ScanTaskDal,
	nodeDal imagesecStore.NodeInfoDal,
	scanResult imagesecStore.ScanResultDal,
	imageDetectSrv detect.ImageDetectTaskService,
	imageCacheDal imagesecStore.ImageCacheDal,
	preImageDal adaptStore.ImageDal,
	onlineImageDal imagesecStore.OnlineImageDal,
) *ImageUpdateSrv {
	srv := ImageUpdateSrv{
		imageDal:        imageDal,
		registryDal:     registryDal,
		policyDal:       policyDal,
		detectResultDal: detectResultDal,
		detectTaskDal:   detectTaskDal,
		scanIssueDal:    scanIssueDal,
		trustedDal:      trustedDal,
		configDal:       configDal,
		scanTaskDal:     nodeTaskDal,
		nodeDal:         nodeDal,
		scanResult:      scanResult,
		imageDetectSrv:  imageDetectSrv,
		imageCacheDal:   imageCacheDal,
		preImageDal:     preImageDal,
		onlineImageDal:  onlineImageDal,
		TrustedDigest:   make(map[string]struct{}),
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("ImageUpdate"),
			scannerUtils.WithModule(consts.ModuleImageMeta),
		),
	}
	return &srv
}

func (s *ImageUpdateSrv) ContinueUpdate(ctx context.Context) error {

	update := os.Getenv("CONTINUE_UPDATE_IMAGE")
	if update == consts.FalseString {
		s.Log.Info().Msg("Close update image")
		return nil
	}

	go func() {
		defer func() {
			if err := recover(); err != nil {
				s.Log.Error().Msg("ContinueUpdate recover")
			}
		}()
		ticker := time.NewTicker(time.Minute * 5)
		defer ticker.Stop()
		for {
			_ = s.updateOnlineImage(ctx)
			_ = s.updateTrustedImage(ctx)
			_ = s.cleanAfterDeleteRegistry(ctx)
			_ = s.cleanDeletedDetectPolicy(ctx)
			_ = s.updateSafeFlag(ctx)
			ticker.Reset(time.Minute * 5)
			<-ticker.C
		}
	}()

	go func() {
		defer func() {
			if err := recover(); err != nil {
				s.Log.Error().Msg("ContinueUpdate recover")
			}
		}()
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			<-ticker.C
			_ = s.deleteOverdueImage(ctx)
			ticker.Reset(time.Hour)
		}
	}()

	go func() {
		defer func() {
			if err := recover(); err != nil {
				s.Log.Error().Msg("ContinueUpdate recover")
			}
		}()

		ticker := time.NewTicker(time.Minute * 5)
		defer ticker.Stop()
		for {
			_ = s.UpdateImagePrepareData(ctx)
			<-ticker.C
		}
	}()

	_ = s.updateImageInReg(ctx)
	_ = s.UpdateVulnFlag(ctx)

	return nil
}

// 删除仓库后删除镜像
func (s *ImageUpdateSrv) cleanAfterDeleteRegistry(ctx context.Context) error {
	registries, _, err := s.registryDal.SearchRegistry(ctx,
		imagesecModel.SearchRegistryParam{Deleted: consts.TrueString, Filter: imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit)})

	if err != nil {
		s.Log.Err(err).Msg("cleanAfterDeleteRegistry SearchRegistry")
		return err
	}
	if len(registries) == 0 {
		return nil
	}
	for j := range registries {
		reg := registries[j]

		if err := s.updatePolicyAfterDeleteReg(ctx, reg.ID); err != nil {
			s.Log.Err(err).Int64("regID", reg.ID).Msg("cleanAfterDeleteRegistry updatePolicy")
			return err
		}
		if err := s.updateScanConfigAfterDeleteReg(ctx, reg.ID); err != nil {
			s.Log.Err(err).Int64("regID", reg.ID).Msg("cleanAfterDeleteRegistry updateScanConfig")
			return err
		}

		filter := imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortAsc().SetSortFiledByID()

		for {
			images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
				RegIds: []int64{reg.ID}, ImageFromType: imagesecModel.ImageFromRegistry,
				Fields: []string{"id", "flag", "unique_id"}, Filter: filter})
			if err != nil {
				s.Log.Err(err).Int64("regID", reg.ID).Msg("cleanAfterDeleteRegistry DeleteImage")
				return err
			}
			if len(images) == 0 {
				break
			}
			for i := range images {
				if err := s.clearImage(ctx, images[i]); err != nil {
					s.Log.Err(err).Int64("imageID", images[i].ID).Msg("cleanAfterDeleteRegistry DeleteImage")
					return err
				}
			}
			s.Log.Info().Int64("regId", reg.ID).Msg("cleanAfterDeleteRegistry delete registry and delete imageMeta finished")
		}

		// 老版本的镜像也要删除
		for {
			images, _, err := s.preImageDal.SearchImage(ctx, imagesecModel.SearchImageParam{RegIds: []int64{reg.ID}, Fields: []string{"id"}}, filter)

			if err != nil {
				s.Log.Err(err).Int64("regID", reg.ID).Msg("cleanAfterDeleteRegistry pre DeleteImage")
				return err
			}
			if len(images) == 0 {
				break
			}
			for i := range images {
				if err := s.preImageDal.DeleteImage(ctx, images[i].ID); err != nil {
					s.Log.Err(err).Int64("imageID", images[i].ID).Msg("cleanAfterDeleteRegistry pre DeleteImage")
					return err
				}
			}
			s.Log.Info().Int64("regId", reg.ID).Msg("cleanAfterDeleteRegistry delete registry and delete imageList finished")
		}
		_ = s.registryDal.DeleteRegistry(ctx, reg.ID)
	}
	return nil
}

// 更新可信息镜像
// 有问题
func (s *ImageUpdateSrv) updateTrustedImage(ctx context.Context) error {

	trusted, err := s.trustedDal.SearchTrustedImage(ctx, adaptStore.SearchTrustedImageParam{IsTrusted: consts.TrueString})
	if err != nil {
		s.Log.Err(err).Msg("updateTrustedImage SearchTrustedImage")
		return err
	}
	trustedDigestMap := make(map[string]bool)
	trustedDigest := make([]string, 0)
	for i := range trusted {
		trustedDigestMap[trusted[i].Digest] = true
		trustedDigest = append(trustedDigest, trusted[i].Digest)
	}
	changed, tr := trustedChanged(s.TrustedDigest, trustedDigest)
	if !changed {
		s.Log.Info().Int("TrustedDigest", len(tr)).Msg("updateTrustedImage not changed")
		return nil
	}

	// NotTrusted--->trusted
	if len(trustedDigest) > 0 {
		cnt := 0
		var startID int64
		filter := imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortAsc().SetSortFiledByID()

		for {
			images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
				Digests: trustedDigest,
				Fields:  []string{"id", "flag"},
				StartID: startID,
				Filter:  filter,
			})
			if err != nil {
				s.Log.Err(err).Msg("updateTrustedImage SearchImage")
				return err
			}
			if len(images) == 0 {
				break
			}
			startID = images[len(images)-1].ID

			for i := range images {
				flag := images[i].Flag
				flag = util.SetBit1(flag, imagesecModel.FlagImageTrusted)
				flag = util.SetBit0(flag, imagesecModel.FlagImageUnTrusted)
				if images[i].Flag == flag {
					continue
				}
				cnt++
				updater := map[string]interface{}{"flag": flag}

				if err := s.imageDal.UpdateImage(ctx,
					imagesecModel.UpdateImageParam{
						ID:      images[i].ID,
						Updater: updater,
					}); err != nil {
					s.Log.Err(err).Int64("imageID", images[i].ID).
						Msg("updateTrustedImage UpdateImage")
					return err
				}
			}
		}
		s.Log.Info().Int("change", cnt).Msg("updateTrustedImage NotTrusted->trusted")
	}

	// trusted ----> notTrusted
	var startID int64
	cnt := 0
	for {
		filter := imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortAsc().SetSortFiledByID()
		images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
			StartID: startID,
			Fields:  []string{"id", "flag", "digest"},
			Filter:  filter,
		})
		if err != nil {
			s.Log.Err(err).Msg("updateTrustedImage ListImageWithScanInfo")
			return err
		}
		if len(images) == 0 {
			break
		}
		startID = images[len(images)-1].ID

		for i := range images {
			if trustedDigestMap[images[i].Digest] && util.ExistBit1(images[i].Flag, imagesecModel.FlagImageTrusted) {
				continue
			}
			flag := images[i].Flag
			flag = util.SetBit1(flag, imagesecModel.FlagImageUnTrusted)
			flag = util.SetBit0(flag, imagesecModel.FlagImageTrusted)
			if images[i].Flag == flag {
				continue
			}
			cnt++
			updater := map[string]interface{}{"flag": flag}

			if err := s.imageDal.UpdateImage(ctx, imagesecModel.UpdateImageParam{
				ID:      images[i].ID,
				Updater: updater,
			}); err != nil {
				s.Log.Err(err).Int64("imageID", images[i].ID).Msg("updateTrustedImage UpdateImage")
				return err
			}
		}
	}

	s.TrustedDigest = tr
	s.Log.Info().Int("TrustedDigest", len(tr)).Msg("updateTrustedImage")
	return nil
}

// 清理镜像
// 暂时只支持节点镜像
func (s *ImageUpdateSrv) deleteOverdueImage(ctx context.Context) error {
	nodeConfig, err := s.configDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
	if err != nil {
		s.Log.Err(err).Msg("deleteOverdueImage GetScanImageConfig")
		return err
	}

	sub := time.Now().UnixMilli() - nodeConfig.ImageScanConfig.ClearInterval*consts.MillisecondPerDay // 数据库:milliseconds

	images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
		LessHeartbeat: sub,
		ImageFromType: imagesecModel.ImageFromNode,
		Fields:        []string{"id", "unique_id"}})
	if err != nil {
		s.Log.Err(err).Msg("deleteOverdueImage SearchImage")
		return err
	}
	s.Log.Info().Int("images", len(images)).
		Msg("deleteOverdueImage find overdue image")

	for i := range images {
		if err := s.clearImage(ctx, images[i]); err != nil {
			s.Log.Err(err).Int64("imageID", images[i].ID).
				Msg("deleteOverdueImage DeleteImage")
			return err
		}
	}
	s.Log.Info().Int("images", len(images)).
		Msg("deleteOverdueImage find overdue image and deleted")
	return nil
}

// 更新在线镜像
func (s *ImageUpdateSrv) updateOnlineImage(ctx context.Context) error {
	updateVuln := metaGlobal.GetVulnUpdate()

	currentOnlineImages := make([]*imagesecModel.Image, 0)

	// 定义批量查询的大小
	const batchSize = 1000
	var startID int64 = 0
	var preOnlineCnt int = 0

	for {
		// 分批查询在线镜像
		batch, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
			Fields:     []string{"id", "flag", "image_uuid", "unique_id", "image_name"},
			OnlineFlag: util.SetBit1(0, imagesecModel.FlagImageOnline),
			StartID:    startID,
			Filter:     imagesecModel.EmptyFilter().SetLimit(batchSize).SetSortAsc().SetSortFiledByID(),
		})
		if err != nil {
			s.Log.Err(err).Msg("updateOnlineImage SearchImage for online images")
			return err
		}

		// 如果没有更多数据，退出循环
		if len(batch) == 0 {
			break
		}

		// 更新下一批的起始ID
		startID = batch[len(batch)-1].ID

		// 添加到结果集
		currentOnlineImages = append(currentOnlineImages, batch...)
		preOnlineCnt += len(batch)
	}

	s.Log.Info().Int("preOnlineCnt", preOnlineCnt).Msg("updateOnlineImage get pre online images")

	// 2. 获取所有在线容器的image_uuid (status=0的容器)
	// 3. 查询这些image_uuid对应的镜像，记录成集合B
	// 使用onlineImageDal获取在线容器的image_uuid (status=0的容器)
	curContainerImageUuids, err := s.onlineImageDal.GetOnlineImageUUID(ctx)
	if err != nil {
		s.Log.Err(err).Msg("updateOnlineImage GetOnlineImageUUID for containers")
		return err
	}

	// 把原来在线的更新成离线
	for i := range currentOnlineImages {
		image := currentOnlineImages[i]
		// 只有当前是在线状态的镜像才需要更新
		flag := util.SetBit1(util.SetBit0(image.Flag, imagesecModel.FlagImageOnline), imagesecModel.FlagImageNotOnline)

		go func(im *imagesecModel.Image) { updateVuln.SubImage <- im }(image)

		updater := map[string]interface{}{"flag": flag}
		if err := s.imageDal.UpdateImage(ctx,
			imagesecModel.UpdateImageParam{
				ID:      image.ID,
				Updater: updater,
			}); err != nil {
			s.Log.Err(err).Int64("imageID", image.ID).Msg("updateOnlineImage UpdateImage to offline")
			continue
		}
	}

	// 6. 把集合B中的镜像更新成在线
	nowOnlineCnt := 0
	for i := range curContainerImageUuids {
		uid := curContainerImageUuids[i]
		// 分批查询在线镜像
		images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
			Fields: []string{"id", "flag", "image_uuid", "unique_id", "image_name"},
			UUIDs:  []uint32{uid},
		})
		if err != nil {
			s.Log.Err(err).Msg("updateOnlineImage SearchImage for online images")
			continue
		}
		nowOnlineCnt += len(images)
		// 处理当前批次的镜像
		for j := range images {
			flag := util.SetBit0(util.SetBit1(images[j].Flag, imagesecModel.FlagImageOnline), imagesecModel.FlagImageNotOnline)

			// 将镜像加入到AddImage通道
			go func(im *imagesecModel.Image) { updateVuln.AddImage <- im }(images[j])

			updater := map[string]interface{}{"flag": flag}
			if err := s.imageDal.UpdateImage(ctx,
				imagesecModel.UpdateImageParam{
					ID:      images[j].ID,
					Updater: updater,
				}); err != nil {
				s.Log.Err(err).Int64("imageID", images[j].ID).Msg("updateOnlineImage UpdateImage to online")
				continue
			}
		}
	}

	// 记录详细的镜像状态变化统计
	s.Log.Info().
		Int("nowOnlineCnt", nowOnlineCnt).
		Int("previousOnlineImages", preOnlineCnt).
		Msg("updateOnlineImage completed with image status changes")
	return nil
}

func (s *ImageUpdateSrv) updateImageInReg(ctx context.Context) error {
	// 仓库镜像增加了镜像
	updateImage := metaGlobal.GetImageUpdateChan()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Msg("updateImageInReg recover panic")
			}
		}()

		for im := range updateImage.AddRegImageChan {
			if im == nil {
				continue
			}
			// 本身属性
			dig := im.GenUUID()
			images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{
				ImageFromType: imagesecModel.ImageFromNode,
				Fields:        []string{"id", "flag", "image_uuid"},
				UUIDs:         []uint32{dig},
			})
			if err != nil {
				s.Log.Err(err).Msg("updateImageInReg SearchImage")
				continue
			}
			for i := range images {
				nodeImage := images[i]
				flag := util.SetBit1(nodeImage.Flag, imagesecModel.FlagImageInRegistry)
				flag = util.SetBit0(nodeImage.Flag, imagesecModel.FlagImageNotInRegistry)

				if flag == nodeImage.Flag {
					continue
				}
				err = s.imageDal.UpdateImage(ctx, imagesecModel.UpdateImageParam{
					ID:      nodeImage.ID,
					Updater: map[string]interface{}{"flag": flag},
				})
				if err != nil {
					s.Log.Err(err).Msg("updateImageInReg UpdateImage")
					continue
				}
			}
			s.Log.Info().Uint32("imageUUID", dig).
				Msg("updateImageInReg update node image in registry")
			// 最新的需求，增加镜像不检测，只有当镜像扫描之后再检测
			// imageSearchParam := imagesecModel.ImageSearchApiParam{
			// 	ImageFromType: imagesecModel.ImageFromNode,
			// 	UUIDs:         []uint32{dig},
			// }
			// if err := s.imageDetectSrv.CreateImageDetectTask(ctx,
			// 	imageSearchParam,
			// 	imagesecModel.ImageDetectTask{Priority: imagesecModel.DetectUpdateNodeImageInReg},
			// 	nil,
			// ); err != nil {
			// 	s.Log.Err(err).Msg("updateImageInReg CreateDetectTask")
			// 	return
			// }

			s.Log.Info().Str("digest", im.Digest).
				Msg("updateImageInReg create detect task update node image in registry")
		}
	}()

	return nil
}

// 删除安全策略后，异步删除镜像的的检查结果
func (s *ImageUpdateSrv) cleanDeletedDetectPolicy(ctx context.Context) error {

	policy, _, err := s.policyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{
		Deleted: consts.TrueString, Default: consts.FalseString,
		Filter: &imagesecModel.Filter{Limit: consts.DefaultMaxLimit}})
	if err != nil {
		s.Log.Err(err).Msg("cleanDeletedDetectPolicy GetScanImageConfig")
		return err
	}

	if len(policy) == 0 {
		return nil
	}
	s.Log.Info().Int("policy", len(policy)).
		Msg("cleanDeletedDetectPolicy find deleted detect policy")
	for i := range policy {
		if policy[i].PolicyType != imagesecModel.ConfigTypeDeploy {
			if err := s.deletePolicyDetect(ctx, policy[i].ID); err != nil {
				s.Log.Err(err).Int64("scanConfigID", policy[i].ID).
					Msg("cleanDeletedDetectPolicy deletePolicyDetect")
				return err
			}
		}

		if err := s.policyDal.UpdateDetectPolicy(ctx, imagesecModel.UpdateSecurityPolicyParam{
			ID:      policy[i].ID,
			Updater: map[string]interface{}{"deleted_at": imagesecModel.DeletePolicyAndDeletedDetectResult},
		}); err != nil {
			s.Log.Err(err).Int64("policyID", policy[i].ID).Str("policyName", policy[i].Name).
				Msg("deleteDetectResultAfterDeleteDetectPolicy UpdateDetectPolicy")
			return err
		}
		s.Log.Info().Str("policy", policy[i].Name).
			Msg("cleanDeletedDetectPolicy succeed")
	}
	return nil
}

// 删除特定policy 的检测结果
func (s *ImageUpdateSrv) deletePolicyDetect(ctx context.Context, configID int64) error {

	filter := &imagesecModel.Filter{Limit: consts.DefaultMaxLimit, SortFiled: "id", SortBy: consts.SortByAsc}

	for _, det := range imagesecModel.GetDetectTypes() {
		var startID int64
		for {
			result, err := s.detectResultDal.SearchDetectResult(ctx, imagesecModel.SearchDetectResultParam{
				DetectType: det,
				StartID:    startID,
				PolicyIds:  []int64{configID},
				Filter:     filter,
				Fields:     []string{"id"},
			})
			if err != nil {
				s.Log.Err(err).
					Msg("cleanDeletedDetectPolicy SearchDetectResult")
				return err
			}
			if len(result) == 0 {
				s.Log.Info().
					Msg("cleanDeletedDetectPolicy SearchDetectResult has no result")
				break
			}
			startID = result[len(result)-1].ID
			resultIds := make([]int64, 0)
			for i := range result {
				resultIds = append(resultIds, result[i].ID)
			}
			detectParam := imagesecModel.SearchDetectResultParam{Ids: resultIds, DetectType: det}

			if err := s.detectResultDal.DeleteDetectResult(ctx, detectParam); err != nil {
				s.Log.Err(err).
					Msg("cleanDeletedDetectPolicy DeleteDetectResult")
				return err
			}
			s.Log.Info().Str("detectType", det).
				Int("resultIds", len(resultIds)).Msg("DeleteDetectResult succeed")
		}
		s.Log.Info().Str("detectType", det).
			Msg("cleanDeletedDetectPolicy deletePolicyDetect succeed")
	}

	var startID int64
	for {
		result, err := s.detectResultDal.SearchDetectBrief(ctx, imagesecModel.SearchDetectBriefParam{
			LastID:   startID,
			PolicyID: configID,
			Filter:   filter,
			Fields:   []string{"id", "flag"},
		})
		if err != nil {
			s.Log.Err(err).Msg("SearchDetectBrief")
			return err
		}
		if len(result) == 0 {
			s.Log.Info().Msg("SearchDetectBrief has no result")
			break
		}
		startID = result[len(result)-1].ID
		resultIds := make([]int64, 0)
		for i := range result {
			resultIds = append(resultIds, result[i].ID)
		}
		if err := s.detectResultDal.DeleteDetectBrief(ctx, imagesecModel.SearchDetectBriefParam{Ids: resultIds}); err != nil {
			s.Log.Err(err).Msg("DeleteDetectBrief")
			return err
		}
		s.Log.Info().Int("resultIds", len(resultIds)).
			Msg("cleanDeletedDetectPolicy DeleteDetectBrief succeed")
	}
	s.Log.Info().
		Msg("cleanDeletedDetectPolicy DeleteDetectBrief succeed")
	return nil
}

// 删除安全策略之后更新镜像是否安全的 flag
func (s *ImageUpdateSrv) updateSafeFlag(ctx context.Context) error {
	// 情况一：删除了策略
	// 等待所有已删除的策略先删除检测结果
	policy, _, err := s.policyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{Deleted: consts.TrueString})
	if err != nil {
		s.Log.Err(err).Msg("updateSafeFlag SearchDetectPolicy")
		return err
	}

	s.Log.Info().Int("policy", len(policy)).Msg("updateSafeFlag find detect policy")

	if len(policy) == 0 {
		return nil
	}
	ready := true
	configIds := make([]int64, 0)

	for i := range policy {
		configIds = append(configIds, policy[i].ID)
		if policy[i].DeletedAt != imagesecModel.DeletePolicyAndDeletedDetectResult {
			ready = false
		}
	}
	if !ready {
		s.Log.Info().Int("policy", len(policy)).Msg("updateSafeFlag " +
			"find deleted detect policy but not ready")
		return nil
	}

	s.Log.Info().Int("policy", len(policy)).Msg("updateSafeFlag " +
		"find deleted detect policy and ready update image")

	if err := s.updateImageSafeFlag(ctx); err != nil {
		s.Log.Err(err).Msg("updateSafeFlag updateImageSafeFlag")
		return err
	}
	s.Log.Info().Msg("updateSafeFlag updateImageSafeFlag succeed")
	// 更新完成之后就彻底删除策略
	for i := range configIds {
		if err := s.policyDal.DeleteDetectPolicy(ctx, configIds[i]); err != nil {
			s.Log.Err(err).Msg("updateSafeFlag DeleteDetectPolicy")
			return err
		}
	}
	s.Log.Info().Interface("policyIds", configIds).
		Msg("updateSafeFlag update image " +
			"safe flag adn delete deleted delete policy")
	return nil
}

// 更新镜像是否安全的Flag
func (s *ImageUpdateSrv) updateImageSafeFlag(ctx context.Context) error {

	var startID int64
	filter := &imagesecModel.Filter{Limit: consts.DefaultExportBathSize, SortFiled: "id", SortBy: consts.SortByAsc}

	for {
		images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{StartID: startID, Filter: filter})
		if err != nil {
			s.Log.Err(err).Msg("SearchImage")
			return err
		}
		if len(images) == 0 {
			break
		}
		startID = images[len(images)-1].ID

		for i := range images {
			brief, err := s.detectResultDal.SearchDetectBrief(ctx, imagesecModel.SearchDetectBriefParam{
				ImageUniqueID: images[i].UniqueID})
			if err != nil {
				s.Log.Err(err).Int64("imageID", images[i].ID).
					Msg("SearchDetectBrief")
				return err
			}
			flag := imagesecModel.AddImageSafeFlag(brief, images[0].Flag)
			if images[0].Flag == flag {
				continue
			}
			updater := map[string]interface{}{"flag": flag}
			if err := s.imageDal.UpdateImage(ctx, imagesecModel.UpdateImageParam{
				ID:      images[i].ID,
				Updater: updater,
			}); err != nil {
				s.Log.Err(err).Int64("ImageID", images[i].ID).
					Msg("UpdateImage UpdateImage")
				return err
			}
		}
	}
	return nil
}

func (s *ImageUpdateSrv) clearImage(ctx context.Context, image *imagesecModel.Image) error {
	if image == nil {
		return nil
	}

	// 扫描结果
	if err := s.scanIssueDal.CreateMalwareToImage(ctx, imagesecModel.CreateMalwareToImageParam{ImageUniqueID: image.UniqueID}); err != nil {
		s.Log.Err(err).Msg("clearImage malware")
		return err
	}

	if err := s.scanIssueDal.CreateSensitiveToImage(ctx, imagesecModel.CreateSensitiveToImageParam{ImageUniqueID: image.UniqueID}); err != nil {
		s.Log.Err(err).Msg("clearImage sensitive file")
		return err
	}
	if err := s.scanIssueDal.CreatePkgToImage(ctx, imagesecModel.CreatePkgToImageParam{ImageUniqueID: image.UniqueID}); err != nil {
		s.Log.Err(err).Msg("clearImage pkg")
		return err
	}
	if err := s.scanIssueDal.CreateVulnToImage(ctx, imagesecModel.CreateVulnToImageParam{ImageUniqueID: image.UniqueID}); err != nil {
		s.Log.Err(err).Msg("clearImage vuln")
		return err
	}
	if err := s.scanIssueDal.CreateWebshellToImage(ctx, imagesecModel.CreateWebshellToImageParam{ImageUniqueID: image.UniqueID}); err != nil {
		s.Log.Err(err).Msg("clearImage webshell")
		return err
	}
	if err := s.scanIssueDal.CreateLicenseToImage(ctx, imagesecModel.CreateLicenseToImageParam{ImageUniqueID: image.UniqueID}); err != nil {
		s.Log.Err(err).Msg("clearImage license")
		return err
	}

	// 检测任务
	if err := s.detectTaskDal.DeleteDetectSubtask(ctx, imagesecModel.SearchTaskParam{ImageUniqueID: image.UniqueID}); err != nil {
		s.Log.Err(err).Msg("clearImage")
		return err
	}

	// 检测结果
	for _, det := range imagesecModel.GetDetectTypes() {
		if err := s.detectResultDal.DeleteDetectResult(ctx, imagesecModel.SearchDetectResultParam{
			ImageUniqueID: image.UniqueID,
			DetectType:    det,
		}); err != nil {
			s.Log.Err(err).Msg("clearImage")
			return err
		}
	}
	// 注意：扫描任务不清理
	// 镜像
	if err := s.imageDal.DeleteImage(ctx, image.ID); err != nil {
		s.Log.Err(err).Msg("clearImage")
		return err
	}

	s.Log.Info().Int64("imageID", image.ID).Msg("clearImage end")
	return nil
}

func trustedChanged(pre map[string]struct{}, now []string) (bool, map[string]struct{}) {
	nw := make(map[string]struct{})
	for i := range now {
		nw[now[i]] = struct{}{}
	}
	if len(pre) != len(nw) {
		return true, nw
	}

	for k := range pre {
		if _, ok := nw[k]; !ok {
			return true, nw
		}
	}
	for k := range nw {
		if _, ok := pre[k]; !ok {
			return true, nw
		}
	}
	return false, nw
}

func (s *ImageUpdateSrv) updatePolicyAfterDeleteReg(ctx context.Context, regID int64) error {
	policy, _, err := s.policyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{})
	if err != nil {
		s.Log.Err(err).Msg("SearchDetectPolicy")
		return err
	}
	for i := range policy {
		po := policy[i]
		if po.Scope.AllReg {
			continue
		}
		if util.ExistInInt64Slice(po.Scope.RegIds, regID) {
			regIds := make([]int64, 0)
			for _, reg := range po.Scope.RegIds {
				if reg != regID {
					regIds = append(regIds, reg)
				}
			}
			po.Scope.RegIds = regIds
			po.Serialize()
			param := imagesecModel.UpdateSecurityPolicyParam{
				ID: po.ID, Updater: po.ToUpdater()}
			if err := s.policyDal.UpdateDetectPolicy(ctx, param); err != nil {
				s.Log.Err(err).Msg("UpdateDetectPolicy")
				return err
			}
		}
	}
	return nil
}

func (s *ImageUpdateSrv) updateScanConfigAfterDeleteReg(ctx context.Context, regID int64) error {
	policy, err := s.configDal.SearchImageConfig(ctx)
	if err != nil {
		s.Log.Err(err).Msg("SearchImageConfig")
		return err
	}
	for i := range policy {
		po := policy[i].ImageScanConfig
		if po.ScanCycle.AllReg {
			continue
		}
		if util.ExistInInt64Slice(po.ScanCycle.RegIds, regID) {
			regIds := make([]int64, 0)
			for _, reg := range po.ScanCycle.RegIds {
				if reg != regID {
					regIds = append(regIds, reg)
				}
			}
			po.ScanCycle.RegIds = regIds
			data := policy[i]
			data.ImageScanConfig = po

			if err := s.configDal.UpdateScanImageConfig(ctx, po.ID, data); err != nil {
				s.Log.Err(err).Msg("UpdateScanImageConfig")
				return err
			}
		}
	}
	return nil
}
