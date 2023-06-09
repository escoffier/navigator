package imagemeta

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageUpdateService interface {
	ContinueUpdateAndCleanImage(ctx context.Context) error
}

type ImageUpdateSrv struct {
	imageDal        imagesecStore.ImageMetaDal
	registryDal     store.RegistryDal
	policyDal       imagesecStore.DetectPolicyDal
	detectResultDal imagesecStore.ImageDetectResultDal
	trustedDal      store.TrustedImageDal
	configDal       imagesecStore.ScanImageConfigDal
	nodeTaskDal     imagesecStore.ScanTaskDal
	libImageDal     store.ImageDal
}

func NewImageUpdateSrv(
	imageDal imagesecStore.ImageMetaDal,
	registryDal store.RegistryDal,
	policyDal imagesecStore.DetectPolicyDal,
	detectResultDal imagesecStore.ImageDetectResultDal,
	trustedDal store.TrustedImageDal,
	configDal imagesecStore.ScanImageConfigDal,
	nodeTaskDal imagesecStore.ScanTaskDal,
	libImageDal store.ImageDal,
) *ImageUpdateSrv {
	srv := ImageUpdateSrv{
		imageDal:        imageDal,
		registryDal:     registryDal,
		policyDal:       policyDal,
		detectResultDal: detectResultDal,
		trustedDal:      trustedDal,
		configDal:       configDal,
		nodeTaskDal:     nodeTaskDal,
		libImageDal:     libImageDal,
	}
	return &srv
}

func (s *ImageUpdateSrv) ContinueUpdateAndCleanImage(ctx context.Context) error {

	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Msg("ContinueUpdateAndCleanImage recover")
			}
		}()
		ticker := time.NewTicker(time.Minute * 20)
		defer ticker.Stop()
		for {
			<-ticker.C
			_ = s.updateOnlineImage(ctx)
			_ = s.updateImageInLibOrNot(ctx)
			// _ = s.updateTrustedImage(ctx)
			ticker.Reset(time.Minute * 20)
		}
	}()

	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Msg("ContinueUpdateAndCleanImage recover")
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
				logging.Get().Error().Msg("ContinueUpdateAndCleanImage recover")
			}
		}()

		ticker := time.NewTicker(time.Minute * 1)
		defer ticker.Stop()
		for {
			<-ticker.C
			// _ = s.deleteImageAfterDeleteRegistry(ctx)
			_ = s.deleteDetectResultAfterDeleteDetectPolicy(ctx)
			_ = s.updateSafeFlagAfterDeletePolicy(ctx)
		}
	}()

	return nil
}

// 删除仓库后删除镜像
func (s *ImageUpdateSrv) deleteImageAfterDeleteRegistry(ctx context.Context) error {
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{Deleted: consts.TrueString}, nil)

	if err != nil {
		logging.Get().Err(err).Msg("deleteImageAfterDeleteRegistry SearchRegistry")
		return err
	}

	for j := range registries {
		reg := registries[j]
		var startID int64
		filter := model.EmptyFilter().SetLimit(consts.DefaultLimit).SetSortAsc().SetSortFiledByID()
		for {
			images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{
				RegistryIds: []int64{reg.ID}, ImageFromType: imagesecModel.ImageFromRegistry,
				Fields: []string{"id"}, StartID: startID, Filter: filter})
			if err != nil {
				break
			}
			if len(images) == 0 {
				break
			}
			startID = images[len(images)-1].ID

			for i := range images {
				if err := s.imageDal.DeleteImage(ctx, imagesecModel.ImageFromRegistry, images[i].ID); err != nil {
					logging.Get().Err(err).Int64("imageID", images[i].ID).Msg("deleteImageAfterDeleteRegistry DeleteImage")
					return err
				}
			}
		}
	}
	return nil
}

// 更新可信息镜像
func (s *ImageUpdateSrv) updateTrustedImage(ctx context.Context) error {

	trusted, err := s.trustedDal.SearchTrustedImage(ctx, store.SearchTrustedImageParam{IsTrusted: consts.TrueString})
	if err != nil {
		logging.Get().Err(err).Msg("updateTrustedImage SearchTrustedImage")
		return err
	}
	trustedDigest := make([]string, 0)
	for i := range trusted {
		trustedDigest = append(trustedDigest, trusted[i].Digest)
	}

	// NotTrusted ---> trusted
	if len(trustedDigest) > 0 {
		var startID int64
		filter := model.EmptyFilter().SetLimit(consts.DefaultLimit).SetSortAsc().SetSortFiledByID()

		for {
			images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{
				Digests: trustedDigest,
				Fields:  []string{"id", "flag"},
				StartID: startID,
				Filter:  filter,
			})
			if err != nil {
				logging.Get().Err(err).Msg("updateTrustedImage SearchImage")
				return err
			}
			if len(images) == 0 {
				break
			}
			startID = images[len(images)-1].ID

			for i := range images {
				flag := util.SetBit0(util.SetBit1(images[i].Flag, model.FlagImageTrusted), model.FlagImageUnTrusted)
				if images[i].Flag == flag {
					continue
				}

				updater := map[string]interface{}{"flag": flag}

				if err := s.imageDal.UpdateImage(ctx,
					imagesecModel.UpdateImageParam{
						ID:      images[i].ID,
						Updater: updater,
					}); err != nil {
					logging.Get().Err(err).Int64("imageID", images[i].ID).Msg("updateTrustedImage UpdateImage")
					return err
				}
			}
		}
	}
	// trusted ----> notTrusted
	var startID int64
	for {
		filter := model.EmptyFilter().SetLimit(consts.DefaultLimit).SetSortAsc().SetSortFiledByID()
		images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{
			AndFlag: util.SetBit1(0, model.FlagImageTrusted),
			StartID: startID,
			Fields:  []string{"id", "flag", "digest"},
			Filter:  filter,
		})
		if err != nil {
			logging.Get().Err(err).Msg("updateTrustedImage ListImageWithScanInfo")
			return err
		}
		if len(images) == 0 {
			break
		}
		startID = images[len(images)-1].ID

		for i := range images {
			if len(trustedDigest) > 0 && util.ExistInStringSlice(trustedDigest, images[i].Digest) {
				continue
			}
			flag := util.SetBit0(util.SetBit1(images[i].Flag, model.FlagImageUnTrusted), model.FlagImageTrusted)
			if images[i].Flag == flag {
				continue
			}

			updater := map[string]interface{}{"flag": flag}

			if err := s.imageDal.UpdateImage(ctx, imagesecModel.UpdateImageParam{
				ID:      images[i].ID,
				Updater: updater,
			}); err != nil {
				logging.Get().Err(err).Int64("imageID", images[i].ID).Msg("updateTrustedImage UpdateImage")
				return err
			}
		}
	}
	return nil
}

// 清理镜像
func (s *ImageUpdateSrv) deleteOverdueImage(ctx context.Context) error {
	config, err := s.configDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
	if err != nil {
		logging.Get().Err(err).Msg("deleteOverdueImage GetScanImageConfig")
		return err
	}

	sub := time.Now().UnixMilli() - config.NodeImageConfig.ClearInterval*24*60*60*1000*1000 // 数据库:milliseconds

	images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{LessHeartbeat: sub,
		Fields: []string{"id"}})
	if err != nil {
		logging.Get().Err(err).Msg("deleteOverdueImage SearchImage")
		return err
	}
	logging.Get().Info().Int("images", len(images)).Msg("deleteOverdueImage find overdue image")

	for i := range images {
		if err := s.imageDal.DeleteImage(ctx, images[i].ImageFromType, images[i].ID); err != nil {
			logging.Get().Err(err).Int64("imageID", images[i].ID).Msg("deleteOverdueImage DeleteImage")
			return err
		}
	}
	logging.Get().Info().Int("images", len(images)).Msg("deleteOverdueImage find overdue image and deleted")
	return nil
}

// 更新在线镜像
func (s *ImageUpdateSrv) updateOnlineImage(ctx context.Context) error {
	onlineMap := make(map[uint32]bool)
	ticker := time.NewTicker(time.Minute * 5)
	defer ticker.Stop()
	var startUUID uint32
	// NotOnline ---> online
	for {
		uuids, err := s.imageDal.GetOnlineImageUUID(ctx, startUUID, consts.DefaultLimit)
		if err != nil {
			logging.Get().Err(err).Msg("updateOnlineImage")
			break
		}
		logging.Get().Info().Int("uuids", len(uuids)).Msg("updateOnlineImage getOnlineImageUUID")
		if len(uuids) == 0 {
			break
		}
		for i := range uuids {
			onlineMap[uuids[i]] = true
		}

		images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{
			UUIDs:  uuids,
			Fields: []string{"id", "flag", "image_uuid"},
		})
		if err != nil {
			logging.Get().Err(err).Msg("updateOnlineImage SearchImage")
			return err
		}
		startUUID = uuids[len(uuids)-1] + 1

		logging.Get().Info().Int("uuids", len(uuids)).Int("images", len(images)).Msg("updateOnlineImage search online image")
		for i := range images {
			flag := util.SetBit0(util.SetBit1(images[i].Flag, model.FlagImageOnline), model.FlagImageNotOnline)
			if images[i].Flag == flag {
				continue
			}

			updater := map[string]interface{}{"flag": flag}

			if err := s.imageDal.UpdateImage(ctx,
				imagesecModel.UpdateImageParam{
					ID:      images[i].ID,
					Updater: updater,
				}); err != nil {
				logging.Get().Err(err).Int64("imageID", images[i].ID).Msg("updateOnlineImage UpdateImage")
				return err
			}
		}

		logging.Get().Info().Int("images", len(images)).Msg("updateOnlineImage update online")
	}

	logging.Get().Info().Msg("updateOnlineImage NotOnline -> online succeed")

	var startID int64
	// online ----> notOnline
	for {
		filter := model.EmptyFilter().SetLimit(consts.DefaultLimit).SetSortAsc().SetSortFiledByID()
		images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{
			AndFlag: util.SetBit1(0, model.FlagImageOnline),
			Fields:  []string{"id", "image_uuid", "flag"},
			StartID: startID,
			Filter:  filter,
		})
		if err != nil {
			logging.Get().Err(err).Msg("updateOnlineImage SearchImage")
			return err
		}
		logging.Get().Info().Int("images", len(images)).Msg("updateOnlineImage get online image")
		if len(images) == 0 {
			break
		}
		startID = images[len(images)-1].ID

		for i := range images {
			if onlineMap[images[i].ImageUUID] {
				continue
			}

			flag := util.SetBit0(util.SetBit1(images[i].Flag, model.FlagImageNotOnline), model.FlagImageOnline)
			if images[i].Flag == flag {
				continue
			}

			updater := map[string]interface{}{"flag": flag}

			if err := s.imageDal.UpdateImage(ctx, imagesecModel.UpdateImageParam{
				ID:      images[i].ID,
				Updater: updater,
			}); err != nil {
				logging.Get().Err(err).Int64("imageID", images[i].ID).Msg("updateOnlineImage UpdateImage")
				return err
			}
		}

		logging.Get().Info().Int("images", len(images)).Msg("updateOnlineImage update not online")
	}

	logging.Get().Info().Msg("updateOnlineImage online --> notOnline succeed")
	return nil
}

// 节点镜像不在仓库镜像
func (s *ImageUpdateSrv) updateImageInLibOrNot(ctx context.Context) error {

	ticker := time.NewTicker(time.Minute * 5)
	defer ticker.Stop()
	var startID int64
	filter := model.EmptyFilter().SetLimit(consts.DefaultLimit).SetSortAsc().SetSortFiledByID()
	// NotIN ---> IN
	for {
		digests := make([]string, 0)
		libImages, _, err := s.libImageDal.SearchImage(ctx, imagesecModel.SearchImageParam{
			StartID:  startID,
			NotCount: true,
			Fields:   []string{"digest", "id"},
		}, filter)
		if err != nil {
			logging.Get().Err(err).Msg("updateImageInLibOrNot")
			break
		}
		logging.Get().Info().Int("libImages", len(libImages)).Int64("startID", startID).
			Msg("updateImageInLibOrNot get lib image")

		if len(libImages) == 0 {
			break
		}

		startID = libImages[len(libImages)-1].ID

		for i := range libImages {
			digests = append(digests, libImages[i].Digest)
		}

		nodeImage, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{
			Digests: digests,
			Fields:  []string{"id", "flag", "digest"},
		})
		if err != nil {
			logging.Get().Err(err).Msg("updateImageInLibOrNot get node image")
			return err
		}

		for i := range nodeImage {
			if util.ExistBit1(nodeImage[i].Flag, model.FlagNodeImageInLib) {
				continue
			}

			flag := util.SetBit0(util.SetBit1(nodeImage[i].Flag, model.FlagNodeImageInLib), model.FlagNodeImageNotInLib)
			if nodeImage[i].Flag == flag {
				continue
			}

			updater := map[string]interface{}{"flag": flag}

			if err := s.imageDal.UpdateImage(ctx,
				imagesecModel.UpdateImageParam{
					ID:      nodeImage[i].ID,
					Updater: updater,
				}); err != nil {
				logging.Get().Err(err).Int64("imageID", nodeImage[i].ID).Msg("updateImageInLibOrNot update node image in lib")
				return err
			}
		}
		logging.Get().Info().Int("nodeImage", len(nodeImage)).Msg("updateImageInLibOrNot update in lib image")
	}
	logging.Get().Info().Int64("startLibID", startID).Msg("updateImageInLibOrNot notINLib->inLib succeed")

	startID = 0
	// In ----> NotIN
	for {
		digests := make([]string, 0)
		nodeImage, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{
			AndFlag: util.SetBit1(0, model.FlagNodeImageInLib),
			Fields:  []string{"id", "digest", "flag"},
			StartID: startID,
			Filter:  filter,
		})
		if err != nil {
			logging.Get().Err(err).Msg("updateImageInLibOrNot SearchImage node image")
			return err
		}
		logging.Get().Info().Int("nodeImage", len(nodeImage)).Int64("startID", startID).Msg("updateImageInLibOrNot find in lib image")

		if len(nodeImage) == 0 {
			break
		}
		startID = nodeImage[len(nodeImage)-1].ID

		for i := range nodeImage {
			digests = append(digests, nodeImage[i].Digest)
		}

		libImage, _, err := s.libImageDal.SearchImage(ctx, imagesecModel.SearchImageParam{Digests: digests, NotCount: true}, nil)
		if err != nil {
			logging.Get().Err(err).Msg("updateImageInLibOrNot SearchImage")
			return err
		}
		inMap := make(map[string]bool)
		for i := range libImage {
			inMap[libImage[i].Digest] = true
		}
		logging.Get().Debug().Int("libImage", len(libImage)).Msg("updateImageInLibOrNot find in lib image")

		for i := range nodeImage {
			if inMap[nodeImage[i].Digest] {
				continue
			}
			flag := util.SetBit0(util.SetBit1(nodeImage[i].Flag, model.FlagNodeImageNotInLib), model.FlagNodeImageInLib)
			if nodeImage[i].Flag == flag {
				continue
			}

			updater := map[string]interface{}{"flag": flag}

			if err := s.imageDal.UpdateImage(ctx, imagesecModel.UpdateImageParam{
				ID:      nodeImage[i].ID,
				Updater: updater,
			}); err != nil {
				logging.Get().Err(err).Int64("imageID", nodeImage[i].ID).Msg("updateImageInLibOrNot UpdateImage")
				return err
			}
		}
		logging.Get().Info().Int("nodeImage", len(nodeImage)).Msg("updateImageInLibOrNot update not in lib")
	}

	logging.Get().Info().Msg("updateImageInLibOrNot in->not succeed")

	return nil
}

// 删除安全策略后，异步删除镜像的的检查结果
func (s *ImageUpdateSrv) deleteDetectResultAfterDeleteDetectPolicy(ctx context.Context) error {

	config, _, err := s.policyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{
		Deleted: consts.TrueString, Default: consts.FalseString})
	if err != nil {
		logging.Get().Err(err).Msg("deleteDetectResultAfterDeleteDetectPolicy GetScanImageConfig")
		return err
	}

	logging.Get().Info().Int("policy", len(config)).
		Msg("deleteDetectResultAfterDeleteDetectPolicy find deleted detect policy")

	if len(config) == 0 {
		return nil
	}
	if err := s.deleteDetectResult(ctx, config[0].ID); err != nil {
		logging.Get().Err(err).Int64("scanConfigID", config[0].ID).
			Msg("deleteDetectResultAfterDeleteDetectPolicy deleteDetectResult")
		return err
	}

	if err := s.policyDal.UpdateDetectPolicy(ctx, imagesecModel.UpdateSecurityPolicyParam{
		ID:      config[0].ID,
		Updater: map[string]interface{}{"deleted_at": imagesecModel.DeletePolicyAndDeletedDetectResult},
	}); err != nil {
		logging.Get().Err(err).Int64("policyID", config[0].ID).Str("policyName", config[0].Name).
			Msg("deleteDetectResultAfterDeleteDetectPolicy UpdateDetectPolicy")
		return err
	}

	logging.Get().Info().Str("policy", config[0].Name).Msg("deleteDetectResultAfterDeleteDetectPolicy succeed")
	return nil
}

// 删除特定policy 的检测结果
func (s *ImageUpdateSrv) deleteDetectResult(ctx context.Context, configID int64) error {

	filter := &model.Filter{Limit: consts.DefaultLimit, SortFiled: "id", SortBy: consts.SortByAsc}
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
				logging.Get().Err(err).Msg("deleteDetectResultAfterDeleteDetectPolicy SearchDetectResult")
				return err
			}
			if len(result) == 0 {
				logging.Get().Info().Msg("deleteDetectResultAfterDeleteDetectPolicy SearchDetectResult has no result")
				break
			}
			startID = result[len(result)-1].ID
			resultIds := make([]int64, 0)
			for i := range result {
				resultIds = append(resultIds, result[i].ID)
			}
			if err := s.detectResultDal.DeleteDetectResult(ctx, imagesecModel.SearchDetectResultParam{Ids: resultIds, DetectType: det}); err != nil {
				logging.Get().Err(err).Msg("deleteDetectResultAfterDeleteDetectPolicy DeleteDetectResult")
				return err
			}
			logging.Get().Info().Str("detectType", det).Int("resultIds", len(resultIds)).Msg("DeleteDetectResult succeed")
		}
		logging.Get().Info().Str("detectType", det).Msg("deleteDetectResultAfterDeleteDetectPolicy deleteDetectResult succeed")
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
			logging.Get().Err(err).Msg("SearchDetectBrief")
			return err
		}
		if len(result) == 0 {
			logging.Get().Info().Msg("SearchDetectBrief has no result")
			break
		}
		startID = result[len(result)-1].ID
		resultIds := make([]int64, 0)
		for i := range result {
			resultIds = append(resultIds, result[i].ID)
		}
		if err := s.detectResultDal.DeleteDetectBrief(ctx, imagesecModel.SearchDetectBriefParam{Ids: resultIds}); err != nil {
			logging.Get().Err(err).Msg("DeleteDetectBrief")
			return err
		}
		logging.Get().Info().Int("resultIds", len(resultIds)).Msg("deleteDetectResultAfterDeleteDetectPolicy DeleteDetectBrief succeed")
	}
	logging.Get().Info().Msg("deleteDetectResultAfterDeleteDetectPolicy DeleteDetectBrief succeed")
	return nil
}

// 删除安全策略之后更新镜像是否安全的 flag
func (s *ImageUpdateSrv) updateSafeFlagAfterDeletePolicy(ctx context.Context) error {

	// 等待所有已删除的策略先删除检测结果
	policy, _, err := s.policyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{Deleted: consts.TrueString})
	if err != nil {
		logging.Get().Err(err).Msg("updateSafeFlagAfterDeletePolicy SearchDetectPolicy")
		return err
	}

	logging.Get().Info().Int("policy", len(policy)).Msg("updateSafeFlagAfterDeletePolicy find detect policy")

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
		logging.Get().Info().Int("policy", len(policy)).Msg("updateSafeFlagAfterDeletePolicy " +
			"find deleted detect policy but not ready")
		return nil
	}

	logging.Get().Info().Int("policy", len(policy)).Msg("updateSafeFlagAfterDeletePolicy " +
		"find deleted detect policy and ready update image")

	if err := s.updateImageSafeFlag(ctx); err != nil {
		logging.Get().Err(err).Msg("updateSafeFlagAfterDeletePolicy updateImageSafeFlag")
		return err
	}
	logging.Get().Info().Msg("updateSafeFlagAfterDeletePolicy updateImageSafeFlag succeed")

	for i := range configIds {
		if err := s.policyDal.DeleteDetectPolicy(ctx, configIds[i]); err != nil {
			logging.Get().Err(err).Msg("updateSafeFlagAfterDeletePolicy DeleteDetectPolicy")
			return err
		}
	}
	logging.Get().Info().Interface("policyIds", configIds).Msg("updateSafeFlagAfterDeletePolicy update image " +
		"safe flag adn delete deleted delete policy")
	return nil
}

// 更新镜像是否安全的Flag
func (s *ImageUpdateSrv) updateImageSafeFlag(ctx context.Context) error {

	var startID int64
	filter := &model.Filter{Limit: consts.DefaultExportBathSize, SortFiled: "id", SortBy: consts.SortByAsc}

	for {
		images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{
			Fields: []string{"id", "flag"}, StartID: startID, Filter: filter,
		})
		if err != nil {
			logging.Get().Err(err).Msg("SearchImage")
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
				logging.Get().Err(err).Int64("imageID", images[i].ID).Msg("SearchDetectBrief")
				return err
			}
			flag := imagesecModel.ImageDetectBriefResult(brief).AddImageSafeFlag(images[0].Flag)
			if images[0].Flag == flag {
				continue
			}
			updater := map[string]interface{}{"flag": flag}
			if err := s.imageDal.UpdateImage(ctx, imagesecModel.UpdateImageParam{
				ID:      images[i].ID,
				Updater: updater,
			}); err != nil {
				logging.Get().Err(err).Int64("ImageID", images[i].ID).Msg("UpdateImage UpdateImage")
				return err
			}
		}
	}
	return nil
}
