package imagesecReport

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

// 在线镜像的漏洞
func (s *ScanResultReportSrv) UpdateVulnFlag(ctx context.Context) error {

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("CreateOnlineVuln recover panic")
			}
		}()

		for vu := range s.OnlineVulnChan {
			if err := s.scanResultDal.CreateVuln(ctx, imagesecModel.CreateVulnParam{
				OnlineVuln: true,
				Data:       vu,
			}); err != nil {
				logging.Get().Err(err).Str("module", "imageMeta").Msg("CreateOnlineVuln UpdateVulnOnline")
				continue
			}
			logging.Get().Info().Str("module", "imageMeta").Int("onlineVuln", len(vu)).Msg("CreateOnlineVuln update online vuln")
		}
	}()

	return nil
}
