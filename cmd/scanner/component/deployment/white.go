package deployment

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

func (s *DeploySrv) SearchDeployWhiteImage(ctx context.Context, param imagesecModel.SearchDeployWhiteImageParam) ([]imagesecModel.DeployWhiteImage, int64, error) {

	record, cnt, err := s.DeployRecordDal.SearchDeployWhiteImage(ctx, param)
	if err != nil {
		logging.Get().Err(err).Str("module", "deployImage").Msg("SearchDeployRecord")
		return nil, 0, scani18.SearchWhiteImage(err)
	}
	return record, cnt, nil
}

func (s *DeploySrv) CreateDeployWhiteImage(ctx context.Context, data2 []*imagesecModel.DeployWhiteImage) error {
	err := s.DeployRecordDal.CreateDeployWhiteImage(ctx, data2)
	if err != nil {
		logging.Get().Err(err).Str("module", "deployImage").Msg("CreateDeployWhiteImage")
		return scani18.CreateWhiteImage(err)
	}
	return nil
}

func (s *DeploySrv) UpdateDeployWhiteImage(ctx context.Context, data *imagesecModel.DeployWhiteImage) error {
	if data.ID <= 0 {
		return scani18.NotGetID()
	}
	if data.ExpirationAt <= time.Now().UnixMilli() {
		return i18.CreateI18BadReqErr("有效期设置错误", "expiration incorrect")
	}

	err := s.DeployRecordDal.UpdateDeployWhiteImage(ctx, data.ID, data.ToUpdater())
	if err != nil {
		logging.Get().Err(err).Str("module", "deployImage").Msg("UpdateDeployWhiteImage")
		return scani18.UpdateWhiteImage(err)
	}
	return nil
}

func (s *DeploySrv) DeleteDeployWhiteImage(ctx context.Context, id int64) error {
	err := s.DeployRecordDal.DeleteDeployWhiteImage(ctx, id)
	if err != nil {
		logging.Get().Err(err).Str("module", "deployImage").Msg("DeleteDeployWhiteImage")
		return scani18.DeleteWhiteImage(err)
	}
	return nil
}
