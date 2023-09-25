package imagesec

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ScanInstanceService interface {
	SearchScannerInfo(ctx context.Context) ([]imagesecModel.ScannerInstanceInfo, error)
}

type ScanInstanceSrv struct {
	scannerInfoDal imagesecStore.ScanInstanceDal
}

func (s *ScanInstanceSrv) SearchScannerInfo(ctx context.Context) ([]imagesecModel.ScannerInstanceInfo, error) {
	info, err := s.scannerInfoDal.SearchScannerInfo(ctx, imagesecModel.ScanInstanceParam{})
	if err != nil {
		logging.Get().Err(err).Msg("SearchScannerInfo")
		return nil, err
	}
	return info, err
}

func NewScanInstanceSrv(scannerInfoDal imagesecStore.ScanInstanceDal) *ScanInstanceSrv {
	return &ScanInstanceSrv{scannerInfoDal: scannerInfoDal}
}
