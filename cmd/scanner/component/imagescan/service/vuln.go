package service

import (
	"context"
	"time"

	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

func (s *ScanResultSrv) VulnOverview(ctx context.Context, param imagesecModel.VulnOverviewParam) (*imagesecModel.VulnOverview, error) {
	info, err := s.imageCacheDal.SearchCacheInfo(ctx, imagesecModel.CacheTypVulnOverview)
	if err != nil {
		s.Log.Err(err).Msg("SearchCacheInfo")
		return nil, scani18.NotGetVuln()
	}
	if info.VulnOverview == nil {
		s.Log.Err(err).Msg("SearchCacheInfo VulnOverview is nil")
		return nil, scani18.NotGetVuln()
	}

	return info.VulnOverview, nil
}

func (s *ScanResultSrv) vulnStatistic(ctx context.Context) (*imagesecModel.VulnOverview, error) {
	s.Log.Info().Msg("vulnOverviewHelper start")
	res := &imagesecModel.VulnOverview{
		VulnTotal: 0,
		Severity:  imagesecModel.SeverityCount{},
	}
	for sev := imagesecModel.SeverityUnknownInt; sev <= imagesecModel.SeverityCriticalInt; sev++ {
		_, cnt, err := s.ScanResultDal.SearchVuln(ctx, imagesecModel.SearchVulnDalParam{
			SeverityInt:     []int64{int64(sev)},
			OnlineVuln:      true,
			JustReturnCount: true,
		})
		if err != nil {
			s.Log.Err(err).Msg("vulnOverviewHelper SearchVuln")
			continue
		}
		addVulnOver(res, sev, cnt)
	}

	s.Log.Info().Interface("overview", s.vulnOverview.Get()).
		Msg("vulnOverviewHelper end")
	return res, nil
}

func (s *ScanResultSrv) vulnOverviewHelper(ctx context.Context) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Msg("vulnOverviewHelper recover panic")
			}
		}()

		ticker := time.NewTicker(time.Minute * 5)
		defer ticker.Stop()
		for {
			o, err := s.vulnStatistic(ctx)
			if err != nil {
				s.Log.Err(err).Msg("vulnOverviewHelper SearchVuln")
				continue
			}
			cache := &imagesecModel.CacheInfo{
				DataType:     imagesecModel.CacheTypVulnOverview,
				VulnOverview: o,
			}

			if err := s.imageCacheDal.CreateCacheInfo(ctx, cache); err != nil {
				s.Log.Err(err).Msg("CreateCacheInfo")
				continue
			}

			s.vulnOverview.Set(o)
			<-ticker.C
		}
	}()
}
