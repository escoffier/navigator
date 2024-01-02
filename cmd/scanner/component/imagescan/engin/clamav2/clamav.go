package clamav2

import (
	"context"
	"fmt"

	"gitlab.com/security-rd/go-pkg/logging"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

// Mock 暂时不用,但是为了程序能运行
type ClamavSrv struct {
}

func (s *ClamavSrv) UpdateDB(ctx context.Context, param imagesecModel.UpdateDbParam) (*imagesecModel.ScanConfigDB, error) {
	logging.Get().Info().Str("module", "imagescan").Msg("not implement")
	return nil, fmt.Errorf("not implement")
}

func NewClamavUpdateSrv() *ClamavSrv {
	srv := &ClamavSrv{}
	return srv
}
