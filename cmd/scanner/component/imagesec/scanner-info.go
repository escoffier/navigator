package imagesec

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ScanInstanceService interface {
	SearchScannerInfo(ctx context.Context) ([]imagesecModel.ScannerInstanceInfo, error)
}

type ScanInstanceSrv struct {
	scannerInfoDal imagesecStore.ScanInstanceDal
	Log            *scannerUtils.LogEvent
}

func (s *ScanInstanceSrv) SearchScannerInfo(ctx context.Context) ([]imagesecModel.ScannerInstanceInfo, error) {
	info, err := s.scannerInfoDal.SearchScannerInfo(ctx, imagesecModel.ScanInstanceParam{})
	if err != nil {
		s.Log.Err(err).Msg("SearchScannerInfo")
		return nil, err
	}
	return info, err
}

func NewScanInstanceSrv(scannerInfoDal imagesecStore.ScanInstanceDal) *ScanInstanceSrv {
	return &ScanInstanceSrv{
		scannerInfoDal: scannerInfoDal,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("ScanInstanceSrv"),
			scannerUtils.WithModule(consts.ModuleImagesecSrv))}
}
