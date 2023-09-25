package imagemeta

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta/metaGlobal"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 在线镜像的漏洞
func (s *ImageUpdateSrv) UpdateVulnFlag(ctx context.Context) error {
	// 仓库镜像增加了镜像
	subOnlineImage := metaGlobal.GetVulnUpdate().SubImage
	go func(subOnlineImage chan *imagesecModel.Image) {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("CreateOnlineVuln recover panic")
			}
		}()

		for im := range subOnlineImage {
			logging.Get().Info().Str("module", "imageMeta").Str("image", im.GetImageName()).Msg("CreateOnlineVuln image not online and set vuln not online")
			if im.UniqueID <= 0 || util.ExistBit1(im.Flag, imagesecModel.FlagImageOnline) {
				continue
			}

			vulns, _, err := s.scanResult.SearchVuln(ctx, imagesecModel.SearchVulnDalParam{
				Fields:        []string{"id", "flag", "unique_id"},
				ImageUniqueID: im.UniqueID,
			})
			if err != nil {
				logging.Get().Err(err).Str("module", "imageMeta").Msg("DeleteOnlineVuln SearchVuln")
				continue
			}
			update := make([]uint64, 0)
			for i := range vulns {
				// 找漏洞关联的镜像
				sub := true
				images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{VulnUniqueID: vulns[i].UniqueID})
				if err != nil {
					logging.Get().Err(err).Str("module", "imageMeta").Msg("DeleteOnlineVuln SearchImage")
					continue
				}
				for _, ima := range images {
					if util.ExistBit1(ima.Flag, imagesecModel.FlagImageOnline) {
						sub = true
					}
				}
				if sub {
					if vulns[i].Flag != util.SetBit0(vulns[i].Flag, imagesecModel.VulnFlagOnlineImage) {
						update = append(update, vulns[i].UniqueID)
					}
				}
			}

			err = s.scanResult.DeleteOnlineVuln(ctx, update)
			if err != nil {
				logging.Get().Err(err).Str("module", "imageMeta").Msg("DeleteOnlineVuln")
				continue
			}

			logging.Get().Info().Str("module", "imageMeta").Int("notOnlineVuln", len(update)).
				Msg("DeleteOnlineVuln")
		}
	}(subOnlineImage)

	addOnlineImage := metaGlobal.GetVulnUpdate().AddImage
	go func(addOnlineImage chan *imagesecModel.Image) {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("CreateOnlineVuln recover panic")
			}
		}()

		for im := range addOnlineImage {
			logging.Get().Info().Str("module", "imageMeta").Int64("image", im.ID).Msg("CreateOnlineVuln")
			if im.UniqueID <= 0 || !util.ExistBit1(im.Flag, imagesecModel.FlagImageOnline) {
				continue
			}
			vulns, _, err := s.scanResult.SearchVuln(ctx, imagesecModel.SearchVulnDalParam{
				ImageUniqueID: im.UniqueID,
			})
			if err != nil {
				logging.Get().Err(err).Str("module", "imageMeta").Msg("CreateOnlineVuln SearchVuln")
				continue
			}
			update := make([]*imagesecModel.Vuln, 0)
			for i := range vulns {
				if vulns[i].Flag != util.SetBit1(vulns[i].Flag, imagesecModel.VulnFlagOnlineImage) {
					update = append(update, vulns[i])
				}
			}
			if err := s.scanResult.CreateVuln(ctx, imagesecModel.CreateVulnParam{OnlineVuln: true, Data: update}); err != nil {
				logging.Get().Err(err).Str("module", "imageMeta").Msg("CreateOnlineVuln")
				continue
			}
			logging.Get().Info().Str("module", "imageMeta").Int("onlineVuln", len(update)).Msg("CreateOnlineVuln")
		}
	}(addOnlineImage)

	return nil
}
