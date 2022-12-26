package component

import (
	"context"
	"fmt"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanResultSearchParam struct {
	UniqueTarget    uint64   `json:"uniqueTarget,string"`
	ImageID         int64    `json:"imageID"`
	LayerDigest     string   `json:"layerDigest"`
	Keyword         string   `json:"keyword"`
	AbnormalSoft    string   `json:"abnormalSoft"`
	AbnormalLicense string   `json:"abnormalLicense"`
	AbnormalEnv     string   `json:"abnormalEnv"`
	VulnSeverity    []string `json:"vulnSeverity"`
	License         []string `json:"license"`
}

func (s ScanResultSearchParam) Valid() error {
	if s.ImageID <= 0 {
		return fmt.Errorf("no image id")
	}
	return nil
}

func (s ScanResultSearchParam) ToStoreParam() store.SearchImageScanResultParam {
	param := store.SearchImageScanResultParam{
		ImageID:     s.ImageID,
		LayerDigest: s.LayerDigest,
		Keyword:     s.Keyword,
	}
	if s.AbnormalLicense == consts.TrueString {
		param.Flag = util.SetBit1(param.Flag, model.FlagHasExceptLicense)
	}
	param.License = s.License
	if s.AbnormalEnv == consts.TrueString {
		param.NormalEnv = consts.FalseString
	} else if s.AbnormalEnv == consts.FalseString {
		param.NormalEnv = consts.TrueString
	}

	if s.AbnormalSoft == consts.TrueString {
		param.Flag = util.SetBit1(param.Flag, model.FlagHasSoftware)
	}
	if s.UniqueTarget > 0 {
		param.UniqueTarget = append(param.UniqueTarget, s.UniqueTarget)
	}
	return param
}

type ScanResultInterface interface {
	SearchVirus(ctx context.Context, param ScanResultSearchParam, filter *model.Filter) ([]*model.ImageVirus, int64, error)
	SearchWebShell(ctx context.Context, param ScanResultSearchParam, filter *model.Filter) ([]*model.ImageWebShell, int64, error)
	SearchSensitive(ctx context.Context, param ScanResultSearchParam, filter *model.Filter) ([]*model.ImageSensitiveFile, int64, error)
	SearchSoftware(ctx context.Context, param ScanResultSearchParam, filter *model.Filter) ([]*model.ImageSoftware, int64, error)
	SearchEnv(ctx context.Context, param ScanResultSearchParam, filter *model.Filter) ([]*model.ImageEnv, int64, error)
}

type ImageScanResultSrv struct {
	imageScanResultDal store.ImageScanResultDal
}

func NewImageScanResultSrv(imageScanResultDal store.ImageScanResultDal) *ImageScanResultSrv {
	return &ImageScanResultSrv{imageScanResultDal: imageScanResultDal}
}

func (s *ImageScanResultSrv) SearchVirus(ctx context.Context, param ScanResultSearchParam, filter *model.Filter) ([]*model.ImageVirus, int64, error) {
	res, cnt, err := s.imageScanResultDal.SearchVirus(ctx, param.ToStoreParam(), filter)
	if err != nil {
		logging.Get().Err(err).Interface("Param", param).Msg("SearchVirus")
		return nil, 0, err
	}
	return res, cnt, nil
}

func (s *ImageScanResultSrv) SearchWebShell(ctx context.Context, param ScanResultSearchParam, filter *model.Filter) ([]*model.ImageWebShell, int64, error) {
	res, cnt, err := s.imageScanResultDal.SearchWebShell(ctx, param.ToStoreParam(), filter)
	if err != nil {
		logging.Get().Err(err).Interface("Param", param).Msg("SearchWebShell")
		return nil, 0, err
	}
	return res, cnt, nil
}

func (s *ImageScanResultSrv) SearchSensitive(ctx context.Context, param ScanResultSearchParam, filter *model.Filter) ([]*model.ImageSensitiveFile, int64, error) {
	res, cnt, err := s.imageScanResultDal.SearchSensitive(ctx, param.ToStoreParam(), filter)
	if err != nil {
		logging.Get().Err(err).Interface("Param", param).Msg("SearchSensitive")
		return nil, 0, err
	}
	return res, cnt, nil
}

func (s *ImageScanResultSrv) SearchSoftware(ctx context.Context, param ScanResultSearchParam, filter *model.Filter) ([]*model.ImageSoftware, int64, error) {
	res, cnt, err := s.imageScanResultDal.SearchSoftware(ctx, param.ToStoreParam(), filter)
	if err != nil {
		logging.Get().Err(err).Interface("Param", param).Msg("SearchSoftware")
		return nil, 0, err
	}

	issueToImage, err := s.imageScanResultDal.SearchScanSoftwareToImage(ctx, param.ImageID)
	if err != nil {
		return nil, 0, err
	}

	issueMap := make(map[uint64]uint64)
	for i := range issueToImage {
		issueMap[issueToImage[i].UniqueTarget] = issueToImage[i].Flag
	}
	for i := range res {
		res[i].Flag = issueMap[res[i].UniqueID]
	}
	return res, cnt, nil
}

func (s *ImageScanResultSrv) SearchEnv(ctx context.Context, param ScanResultSearchParam, filter *model.Filter) ([]*model.ImageEnv, int64, error) {
	res, cnt, err := s.imageScanResultDal.SearchImageEnv(ctx, param.ToStoreParam(), filter)
	if err != nil {
		logging.Get().Err(err).Interface("Param", param).Msg("SearchImageEnv")
		return nil, 0, err
	}
	return res, cnt, nil
}
