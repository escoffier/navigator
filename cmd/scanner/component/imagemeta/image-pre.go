package imagemeta

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type PreLibImageSrv struct {
	imageDal      store.ImageDal
	registryDal   imagesecStore.RegistryDal
	vulnDal       store.VulnDalInterface
	scanResultDal store.ImageScanResultDal
}

// 只做数据迁移及兼容老数据，就不管什么服务依赖了
func NewPreLibImageSrv() *PreLibImageSrv {
	db := store.GetRDBInstance()
	imageDal := store.NewScannerOrm(db)
	registryDal := imagesecStore.NewRegistryDao(db)
	vulnDal := store.NewVulnDao(db)
	scanResultDal := store.NewImageScanResultDao(db)

	return &PreLibImageSrv{
		imageDal:      imageDal,
		registryDal:   registryDal,
		vulnDal:       vulnDal,
		scanResultDal: scanResultDal,
	}
}

func (s *PreLibImageSrv) GetImageCorrelateData(ctx context.Context, param imagesecModel.ImageAssociateParam) (
	*imagesecModel.ImageWithCorrelateData2, error) {
	param.Deserialize()

	ans := &imagesecModel.ImageWithCorrelateData{}

	images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.SearchImageParam{InIds: []int64{param.ImageId}}, nil)
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Int64("ImageID", param.ImageId).Msg("ImageWithCorrelateData ImageBaseDetail")
		return nil, err
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("not find image:%d", param.ImageId)
	}
	image := images[0]

	ans.ImageList = image

	imageID := param.ImageId

	registry, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString, ID: image.RegistryID})
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("SearchImageWithScan.SearchRegistry")
		return nil, err
	}
	if len(registry) > 0 {
		ans.Registry = &(registry[0])
	}

	daoParam := ScanResultParamToStoreParam(param.ScanResultSearchParam)

	daoParam.ImageID = imageID

	dataFor211, err := s.GetImageCorrelateDataFor211(ctx, param)
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Int64("imageID", param.ImageId).Msg("GetImageCorrelateData GetImageCorrelateDataFor211")
		return nil, err
	}

	ans.VirusCnt = dataFor211.VirusCnt
	ans.Virus = dataFor211.Virus
	ans.SensitiveCnt = dataFor211.SensitiveCnt
	ans.Sensitive = dataFor211.Sensitive
	ans.EnvCnt = dataFor211.EnvCnt
	ans.Env = dataFor211.Env
	ans.Software = dataFor211.Software
	ans.SoftwareCnt = dataFor211.SoftwareCnt

	if param.WebshellEnable {
		webshell, webshellCnt, err := s.scanResultDal.SearchWebShell(ctx, daoParam, nil)
		if err != nil {
			logging.Get().Err(err).Str("module", "imageMeta").Msg("SearchImageWithScan.SearchWebShell")
			return nil, err
		}
		ans.WebshellCnt = webshellCnt
		ans.Webshell = webshell
	}

	// 查询该镜像的所有漏洞，更详细的查询请使用VulnServiceInterface
	if param.VulnEnable {
		vuln, cnt, err := s.vulnDal.SearchVuln(ctx, store.SearchVulnParam{ImageIds: []int64{imageID},
			OmitFields: param.ScanResultSearchParam.OmitFields}, nil)
		if err != nil {
			logging.Get().Err(err).Str("module", "imageMeta").Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchVuln")
			return nil, err
		}
		ans.Vuln = vuln
		ans.VulnCnt = cnt
	}

	res := ans.Adapt() // 适配成最新的版本

	res.ImageBaseResponse = res.ToImageBaseResponse()
	// 程序中分页
	res = res.AddFilter(param.ScanResultSearchParam.Filter)
	return res, nil
}

func ScanResultParamToStoreParam(s imagesecModel.ScanResultSearchParam) store.SearchImageScanResultParam {
	param := store.SearchImageScanResultParam{
		ImageID:     s.ImageID,
		LayerDigest: s.LayerDigest,
		Keyword:     s.Keyword,
	}
	if s.ExceptionPkgLicense == consts.TrueString {
		param.Flag = util.SetBit1(param.Flag, imagesecModel.FlagHasExceptionPkgLicense)
	}

	if s.ExceptionEnv == consts.TrueString {
		param.NormalEnv = consts.FalseString
	} else if s.ExceptionEnv == consts.FalseString {
		param.NormalEnv = consts.TrueString
	}

	if s.ExceptionPkg == consts.TrueString {
		param.Flag = util.SetBit1(param.Flag, imagesecModel.FlagHasExceptionPKG)
	}
	return param
}

func (s *PreLibImageSrv) GetImageCorrelateDataFor211(ctx context.Context, param imagesecModel.ImageAssociateParam) (
	*imagesecModel.ImageWithCorrelateData, error) {
	imageData, err := s.scanResultDal.SearchScanImage(ctx, param.ScanResultSearchParam)
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Int64("imageID", param.ImageId).Msg("GetImageCorrelateDataFor211 SearchScanImage")
		return nil, err
	}
	if !param.PkgEnable || param.ScanResultSearchParam.ExceptionPkg == consts.TrueString {
		return imageData, nil
	}
	abnormalSoft := make(map[string]uint64)
	for i := range imageData.Software {
		key := fmt.Sprintf("%s|%s", imageData.Software[i].Name, imageData.Software[i].Version)
		abnormalSoft[key] = imageData.Software[i].Flag
	}

	// 查software
	vulns, _, err := s.vulnDal.SearchVuln(ctx, store.SearchVulnParam{
		Fields:   []string{"id", "name", "pkg_name", "pkg_version"},
		ImageIds: []int64{param.ImageId},
	}, nil)

	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Int64("imageID", param.ImageId).Msg("GetImageCorrelateDataFor211 SearchVuln")
		return nil, err
	}

	softExit := make(map[string]bool)
	soft := make([]*model.ImageSoftware, 0)
	keyword := param.ScanResultSearchParam.Keyword
	for i := range vulns {
		key := fmt.Sprintf("%s|%s", vulns[i].PkgName, vulns[i].PkgVersion)
		if !softExit[key] {
			softExit[key] = true

			if keyword != "" && (!strings.Contains(strings.ToLower(vulns[i].PkgName), keyword) &&
				!strings.Contains(strings.ToLower(vulns[i].PkgVersion), keyword)) {
				continue
			}

			so := &model.ImageSoftware{
				Name:    vulns[i].PkgName,
				Version: vulns[i].PkgVersion,
				Flag:    abnormalSoft[key],
			}

			soft = append(soft, so)
		}
	}

	imageData.Software = soft
	imageData.SoftwareCnt = int64(len(soft))

	return imageData, nil
}

func (s *PreLibImageSrv) GetPreImage(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute * 30)
	defer ticker.Stop()
	return nil
}
