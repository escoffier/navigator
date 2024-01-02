package imagemeta

import (
	"context"
	"fmt"
	"strconv"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

type PreRegImageSrv struct {
	imageDal      adaptStore.ImageDal
	registryDal   imagesecStore.RegistryDal
	vulnDal       adaptStore.VulnDalInterface
	scanResultDal adaptStore.ImageScanResultDal
	Log           *scannerUtils.LogEvent
}

// 只做数据迁移及兼容老数据，就不管什么服务依赖了
func NewPreLibImageSrv() *PreRegImageSrv {
	db := store.GetRDBInstance()
	imageDal := adaptStore.NewScannerOrm(db)
	registryDal := imagesecStore.NewRegistryDao(db)
	vulnDal := adaptStore.NewVulnDao(db)
	scanResultDal := adaptStore.NewImageScanResultDao(db)

	return &PreRegImageSrv{
		imageDal:      imageDal,
		registryDal:   registryDal,
		vulnDal:       vulnDal,
		scanResultDal: scanResultDal,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("PreRegImage"),
			scannerUtils.WithModule(consts.ModuleImageMeta),
		),
	}
}

func (s *PreRegImageSrv) GetImageCorrelateData(ctx context.Context, imageID int64) (
	*imagesecModel.ImageWithCorrelateData2, []*imagesecModel.Vuln, error) {

	ans := &imagesecModel.ImageWithCorrelateData{
		Sensitive: make([]*model.ImageSensitiveFile, 0),
		Webshell:  make([]*scannermodel.Webshell, 0),
		Env:       make([]*model.ImageEnv, 0),
		Vuln:      make([]*model.Vuln, 0),
		Software:  make([]*model.ImageSoftware, 0),
		License:   make([]string, 0),
		Virus:     make([]*model.ImageVirus, 0),
	}

	images, _, err := s.imageDal.SearchImage(ctx, imagesecModel.SearchImageParam{InIds: []int64{imageID}}, nil)
	if err != nil {
		s.Log.Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData ImageBaseDetail")
		return nil, nil, err
	}
	if len(images) == 0 {
		return nil, nil, fmt.Errorf("not find image:%d", imageID)
	}
	image := images[0]

	ans.ImageList = image

	daoParam := adaptStore.SearchImageScanResultParam{ImageID: imageID}

	// 2.11版本之前，没有拆分
	imageData, err := s.scanResultDal.SearchScanImage(ctx, imagesecModel.ScanResultSearchParam{ImageID: imageID})
	if err != nil {
		s.Log.Err(err).Int64("imageID", imageID).Msg("GetImageCorrelateDataFor211 SearchScanImage")
	}
	if err == nil {
		ans.Virus = append(ans.Virus, imageData.Virus...)
		ans.Sensitive = append(ans.Sensitive, imageData.Sensitive...)
		ans.Env = append(ans.Env, imageData.Env...)
		ans.Software = append(ans.Software, imageData.Software...)
		ans.Webshell = append(ans.Webshell, imageData.Webshell...)
	}

	webshell, _, err := s.scanResultDal.SearchWebShell(ctx, daoParam, nil)
	if err != nil {
		s.Log.Err(err).Msg("SearchImageWithScan.SearchWebShell")
	}
	ans.Webshell = append(ans.Webshell, webshell...)

	// 查询该镜像的所有漏洞，更详细的查询请使用VulnServiceInterface
	vuln, _, err := s.vulnDal.SearchVuln(ctx, adaptStore.SearchVulnParam{ImageIds: []int64{imageID}}, nil)
	if err != nil {
		s.Log.Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchVuln")
	}

	ans.Vuln = append(ans.Vuln, vuln...)

	env, _, err := s.scanResultDal.SearchImageEnv(ctx, daoParam, nil)
	if err != nil {
		s.Log.Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchImageEnv")
	}
	ans.Env = append(ans.Env, env...)

	sensitive, _, err := s.scanResultDal.SearchSensitive(ctx, daoParam, nil)
	if err != nil {
		s.Log.Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchSensitive")
	}
	ans.Sensitive = append(ans.Sensitive, sensitive...)

	software, _, err := s.scanResultDal.SearchSoftware(ctx, daoParam, nil)
	if err != nil {
		s.Log.Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchSoftware")
	}
	ans.Software = append(ans.Software, software...)

	virus, _, err := s.scanResultDal.SearchVirus(ctx, daoParam, nil)
	if err != nil {
		s.Log.Err(err).Int64("ImageID", imageID).Msg("ImageWithCorrelateData SearchVirus")
	}
	ans.Virus = append(ans.Virus, virus...)

	vulns := make([]*imagesecModel.Vuln, 0)

	for i := range ans.Vuln {
		vu1 := ans.Vuln[i]
		vu := &imagesecModel.Vuln{
			Name:          vu1.Name,
			PkgName:       vu1.PkgName,
			PkgVersion:    vu1.PkgVersion,
			CnnvdName:     vu1.CnnvdName,
			DescriptionEn: vu1.Description,
			DescriptionZh: vu1.Description,
			References:    vu1.Link,
			Class:         vu1.Class,
			Severity:      vu1.SeverityInt,
			Language:      vu1.Language,
			Frame:         vu1.Frame,
			FixedVersion:  vu1.FixedBy,
			Target:        vu1.Target,
		}
		if vu1.Metadata != nil {
			vu.CVSS = map[string]imagesecModel.Cvss{}
			f, _ := strconv.ParseFloat(vu1.Metadata.CVSS.CVSSv3Score, 64)
			vu.CVSS[imagesecModel.CVSSNvd] = imagesecModel.Cvss{
				V3Score:  f,
				V3Vector: vu1.Metadata.CVSS.CVSSv3Vector,
			}
		}
		pk := imagesecModel.Pkg{
			Name:    vu.PkgName,
			Version: vu.PkgVersion,
		}
		vu.PkgUniqueID = pk.GenUniqueID()

		vulns = append(vulns, vu)
	}

	res := ans.Adapt() // 适配成最新的版本

	return res, vulns, nil
}
