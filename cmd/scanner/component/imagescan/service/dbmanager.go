package service

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
)

type DBManagerService interface {
	UpdateDB(ctx context.Context, param imagesecModel.UpdateDbParam) error
	SearchDB(ctx context.Context, param imagesecModel.SearchDbParam) ([]imagesecModel.ScanDbMeta, int64, error)
}

type DBManagerSrv struct {
	AviraUpdate     types.UpdateDEngin
	ClamavUpdate    types.UpdateDEngin
	ScanDbMetaDal   imagesecStore.ScanDbMetaDal
	NodeInfoDal     imagesecStore.NodeInfoDal
	ScanInstanceDal imagesecStore.ScanInstanceDal
	RpcClient       rpcstream.MessageStream
}

func NewDBManagerSrv(
	aviraUpdateSrv types.UpdateDEngin,
	clamavUpdateSrv types.UpdateDEngin,
	scanDbMetaDal imagesecStore.ScanDbMetaDal,
	nodeInfoDal imagesecStore.NodeInfoDal,
	scanInstanceDal imagesecStore.ScanInstanceDal,
) *DBManagerSrv {
	srv := &DBManagerSrv{
		AviraUpdate:     aviraUpdateSrv,
		ClamavUpdate:    clamavUpdateSrv,
		ScanDbMetaDal:   scanDbMetaDal,
		NodeInfoDal:     nodeInfoDal,
		ScanInstanceDal: scanInstanceDal,
	}
	return srv
}

func (s *DBManagerSrv) UpdateDB(ctx context.Context, param imagesecModel.UpdateDbParam) error {
	var (
		dbMeta *imagesecModel.ScanDbMeta
		err    error
	)

	if param.DbType == consts.AviraName {
		dbMeta, err = s.AviraUpdate.UpdateDB(ctx, param)
	}

	if param.DbType == consts.ClamavName {
		dbMeta, err = s.ClamavUpdate.UpdateDB(ctx, param)
	}

	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("dbType", param.DbType).Msg("update db")
		return err
	}

	if err := s.ScanDbMetaDal.CreateScanDbMeta(ctx, dbMeta); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("dbType", param.DbType).Msg("update db")
		return err
	}

	return nil
}

func (s *DBManagerSrv) SearchDB(ctx context.Context, param imagesecModel.SearchDbParam) (
	[]imagesecModel.ScanDbMeta, int64, error) {
	// TODO implement me
	panic("implement me")
}
