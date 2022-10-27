package component

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ScannerInstanceInfoInterface interface {
	CreateOrUpdateInstance(ctx context.Context, data model.ScannerInstanceInfo) (int64, error)
	SearchScannerInfo(ctx context.Context) ([]model.ScannerInstanceInfo, error)
}

type ScannerInstanceInfoSrv struct {
	scannerInfoDal store.ScannerInstanceInfoDal
}

func (s *ScannerInstanceInfoSrv) CreateOrUpdateInstance(ctx context.Context, data model.ScannerInstanceInfo) (int64, error) {
	id, err := s.scannerInfoDal.CreateAndReplace(ctx, data)
	if err != nil {
		logging.Get().Err(err).Interface("ScannerInstanceInfo", data).Msg("CreateOrUpdateInstance")
		return 0, err
	}
	return id, err
}

func (s *ScannerInstanceInfoSrv) SearchScannerInfo(ctx context.Context) ([]model.ScannerInstanceInfo, error) {
	info, err := s.scannerInfoDal.SearchScannerInfo(ctx, store.ScannerInstanceInfoDaoParam{})
	if err != nil {
		logging.Get().Err(err).Msg("SearchScannerInfo")
		return nil, err
	}
	return info, err
}

func NewScannerInstanceInfoSrv(scannerInfoDal store.ScannerInstanceInfoDal) *ScannerInstanceInfoSrv {
	return &ScannerInstanceInfoSrv{scannerInfoDal: scannerInfoDal}
}
