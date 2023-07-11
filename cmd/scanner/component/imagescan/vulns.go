package imagescan

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type VulnService interface {
	SearchVuln(ctx context.Context, param imagesecModel.ApiSearchVulnParam) ([]*imagesecModel.VulnView, int64, error)
}

type VulnSrv struct {
	scanResultDal imagesecStore.ScanResultDal
}

func NewVulnSrv(
	scanResultDal imagesecStore.ScanResultDal,
) *VulnSrv {
	return &VulnSrv{scanResultDal: scanResultDal}
}

func (s *VulnSrv) SearchVuln(ctx context.Context, param imagesecModel.ApiSearchVulnParam) ([]*imagesecModel.VulnView, int64, error) {
	vuln, cnt, err := s.scanResultDal.SearchVuln(ctx, param)
	if err != nil {
		logging.Get().Err(err).Interface("param", param).Msg("SearchVuln")
		return nil, 0, err
	}
	vulns := make([]*imagesecModel.VulnView, len(vuln))
	for i := range vuln {
		vulns[i] = vuln[i].GenVulnView()
	}
	return vulns, cnt, nil
}
