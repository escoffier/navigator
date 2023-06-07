package imagesec

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type VulnService interface {
	SearchVuln(ctx context.Context, param imagesecModel.ApiSearchVulnParam) ([]*imagesecModel.VulnView, int64, error)
	GetVulnView(ctx context.Context) imagesecModel.VulnLangConstView
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

func (s *VulnSrv) GetVulnView(ctx context.Context) imagesecModel.VulnLangConstView {

	ans := imagesecModel.VulnLangConstView{
		ZH: imagesecModel.VuluConstView{
			AttackPath: make([]imagesecModel.LabelValue, 0),
			Class:      make([]imagesecModel.LabelValue, 0),
			Severity:   make([]imagesecModel.LabelValue, 0),
		},
		EN: imagesecModel.VuluConstView{
			AttackPath: make([]imagesecModel.LabelValue, 0),
			Class:      make([]imagesecModel.LabelValue, 0),
			Severity:   make([]imagesecModel.LabelValue, 0),
		},
	}

	avEn := imagesecModel.GetVulnAVView(model.LangEn)
	avZH := imagesecModel.GetVulnAVView(model.LangZh)

	for k, v := range avEn {
		ans.EN.AttackPath = append(ans.EN.AttackPath, imagesecModel.LabelValue{Label: v, Value: k})
	}

	for k, v := range avZH {
		ans.ZH.AttackPath = append(ans.ZH.AttackPath, imagesecModel.LabelValue{Label: v, Value: k})
	}

	return ans
}
