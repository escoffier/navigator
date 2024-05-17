package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	imageMetaSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	imagesecScanSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanResultAPI struct {
	ImageSrv      imageMetaSrv.ImageService
	ScanResultSrv imagesecScanSrv.ScanResultService
}

func NewScanResultAPI(
	imageSrv imageMetaSrv.ImageService,
	nodeVulnSrv imagesecScanSrv.ScanResultService,
) *ScanResultAPI {
	return &ScanResultAPI{ImageSrv: imageSrv, ScanResultSrv: nodeVulnSrv}
}

func GetRelatedSearchParam(ctx *gin.Context) imagesecModel.RelatedSearchParam {

	param := imagesecModel.RelatedSearchParam{
		VulnUniqueID: util.GetUint64FromQuery(ctx, "vulnUniqueID"),
		PkgUniqueID:  util.GetUint64FromQuery(ctx, "pkgUniqueID"),
		WebshellMD5:  util.GetKeywordFromQuery(ctx, "webshellMd5"),
		SensitiveMd5: util.GetKeywordFromQuery(ctx, "sensitiveMd5"),
		MalwareMd5:   util.GetKeywordFromQuery(ctx, "malwareMd5"),
		ImageKeyword: util.GetKeywordFromQuery(ctx, "imageKeyword"),

		Filter: imagesecModel.GetFilter(ctx).SetDefault(),
	}
	return param
}

func GetScanResultSearchParamFromCtx(ctx *gin.Context) imagesecModel.ScanResultSearchParam {
	param := imagesecModel.ScanResultSearchParam{
		ImageFromType:       util.GetKeywordFromQuery(ctx, "imageFromType"),
		ImageID:             util.GetInt64FromQuery(ctx, "imageID"),
		ImageUniqueID:       util.GetUint64FromQuery(ctx, "imageUniqueID"),
		VulnUniqueID:        util.GetUint64FromQuery(ctx, "vulnUniqueID"),
		LayerDigest:         util.GetKeywordFromQuery(ctx, "layerDigest"),
		Keyword:             util.GetKeywordFromQuery(ctx, "keyword"),
		ExceptionPkg:        util.GetKeywordFromQuery(ctx, "exceptionPkg"),        // 查看异常软件
		ExceptionLicense:    util.GetKeywordFromQuery(ctx, "exceptionLicense"),    // 查看不允许的开源协议
		ExceptionPkgLicense: util.GetKeywordFromQuery(ctx, "exceptionPkgLicense"), // 查看不允许的开源协议
		ExceptionEnv:        util.GetKeywordFromQuery(ctx, "exceptionEnv"),        // 查看不允许的开源协议
		PasswdEnv:           util.GetKeywordFromQuery(ctx, "passwdEnv"),           // 查看不允许的开源协议
		ExceptionVuln:       util.GetKeywordFromQuery(ctx, "exceptionVuln"),
		ExceptionMalware:    util.GetKeywordFromQuery(ctx, "exceptionMalware"),
		ExceptionSensitive:  util.GetKeywordFromQuery(ctx, "exceptionSensitive"),
		ExceptionWebshell:   util.GetKeywordFromQuery(ctx, "exceptionWebshell"),
		VulnSeverity:        util.GetStringSliceFromQuery(ctx, "vulnSeverity"),
		LicenseSearch:       util.GetStringSliceFromQuery(ctx, "license"),
		DeployRecordID:      util.GetInt64FromQuery(ctx, "deployRecordID"),
		DeployAction:        util.GetKeywordFromQuery(ctx, "deployAction"),
		SecurityPolicyIds:   util.GetInt64SliceFromQuery(ctx, "securityPolicyIds"),
		WebshellRiskLevel:   util.GetStringSliceFromQuery(ctx, "riskLevel"),
		Filter:              imagesecModel.GetFilter(ctx).SetDefault(),
	}
	if param.ImageID <= 0 {
		param.ImageID = util.GetInt64FromQuery(ctx, "id")
	}
	if param.ImageUniqueID <= 0 {
		param.ImageUniqueID = util.GetUint64FromQuery(ctx, "uniqueID")
	}

	return param
}

func (s *ScanResultAPI) SearchVirus(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		DeployRecordID:        param.DeployRecordID,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		MalwareEnable:         true,
		DetectResultEnable:    true,
		CheckDownloadable:     true,
		ScanResultSearchParam: param,
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	response.JSONOK(ctx, response.WithItems(data.Malware),
		response.WithTotalItems(data.MalwareCnt),
		response.WithItemsPerPage(param.Filter.Limit),
		response.WithStartIndex(param.Filter.Offset))
}

func (s *ScanResultAPI) SearchSensitive(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		DeployRecordID:        param.DeployRecordID,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		SensitiveEnable:       true,
		DetectResultEnable:    true,
		CheckDownloadable:     true,
		ScanResultSearchParam: param,
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	response.JSONOK(ctx, response.WithItems(data.Sensitive),
		response.WithTotalItems(data.SensitiveCnt),
		response.WithItemsPerPage(param.Filter.Limit),
		response.WithStartIndex(param.Filter.Offset))
}

func (s *ScanResultAPI) SearchEnv(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		DeployRecordID:        param.DeployRecordID,
		EnvEnable:             true,
		ScanResultSearchParam: param,
		DetectResultEnable:    true,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	response.JSONOK(ctx, response.WithItems(data.Env),
		response.WithTotalItems(data.EnvCnt),
		response.WithItemsPerPage(param.Filter.Limit),
		response.WithStartIndex(param.Filter.Offset))
}

func (s *ScanResultAPI) SearchRelatedSoftware(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	pkg, cnt, err := s.ScanResultSrv.SearchPkg(ctx, param)
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}
	response.JSONOK(ctx, response.WithItems(pkg),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(param.Filter.Limit),
		response.WithStartIndex(param.Filter.Offset))
}

func (s *ScanResultAPI) SearchSoftware(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	filter := param.Filter.DeepCopy()
	param.Filter = nil

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		DeployRecordID:        param.DeployRecordID,
		PkgEnable:             true,
		DetectResultEnable:    true,
		VulnEnable:            true,
		ScanResultSearchParam: param,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	preVulns := data.Vuln
	vulnMap := make(map[uint64][]*imagesecModel.VulnView) // pkg--->[]vuln
	for i := range preVulns {
		key := preVulns[i].PkgUniqueID
		if vulnMap[key] == nil {
			vulnMap[key] = make([]*imagesecModel.VulnView, 0)
		}
		vus := vulnMap[key]
		vus = append(vus, preVulns[i].Simplify())
		vulnMap[key] = vus
	}

	// 整理数据
	pkgMap := make(map[uint64]VulnPKG)
	software := data.Pkg
	for i := range software {
		key := software[i].UniqueID
		if _, ok := pkgMap[key]; !ok {
			vp := VulnPKG{
				PkgName:          software[i].Name,
				PkgVersion:       software[i].Version,
				Filepath:         software[i].Filepath,
				UniqueID:         software[i].UniqueID,
				SeverityOverview: make([]imagesecModel.SeverityGroup, 0),
				Vulns:            make([]*imagesecModel.VulnView, 0),
				License:          software[i].License,
				PolicyDetect:     software[i].PolicyDetect,
			}
			pkgMap[key] = vp
		}
		sf := pkgMap[key]
		sf.Vulns = append(sf.Vulns, vulnMap[key]...)
		for j := range sf.Vulns {
			sf.SeverityOverview = imagesecModel.AddSeverityGroup(sf.SeverityOverview, sf.Vulns[j].SeverityInt)
		}
		pkgMap[key] = sf
	}

	res := make([]VulnPKG, 0)
	for _, vp := range pkgMap {
		// 漏洞级别筛选
		if len(param.VulnSeverity) > 0 {
			add := false
			for i := range vp.Vulns {
				if util.ExistInStringSlice(param.VulnSeverity, vp.Vulns[i].Severity) {
					add = true
					break
				}
			}
			if add {
				res = append(res, vp)
			}
		} else {
			res = append(res, vp)
		}
	}
	// 按层级排序一下,便于前端展示
	for i := range res {
		sort.Sort(imagesecModel.SeverityGroups(res[i].SeverityOverview))
		res[i].SortScore = res[i].GetSortScore()
		res[i].Vulns = make([]*imagesecModel.VulnView, 0)
	}
	sort.Sort(VulnPKGs(res))

	if len(res) <= int(filter.Offset) {
		res = make([]VulnPKG, 0)
	} else if len(res) <= int(filter.Offset+filter.Limit) {
		res = res[int(filter.Offset):]
	} else {
		res = res[int(filter.Offset):int(filter.Offset+filter.Limit)]
	}

	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(data.PkgCnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ScanResultAPI) ImageBaseDetail(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)
	param.Filter = imagesecModel.EmptyFilter()
	apiParam := imagesecModel.ImageAssociateParam{
		ImageFromType:      param.ImageFromType,
		ImageId:            param.ImageID,
		ImageUniqueID:      param.ImageUniqueID,
		DeployRecordID:     param.DeployRecordID,
		VulnEnable:         true,
		MalwareEnable:      true,
		EnvEnable:          true,
		PkgEnable:          true,
		SensitiveEnable:    true,
		WebshellEnable:     true,
		SubtaskEnable:      true,
		RegistryEnable:     true,
		LicenseEnable:      true,
		ContainerEnable:    true,
		RiskPolicyEnable:   true, // 需要查询所有使用到的策略，根据策略决定镜像的问题
		DetectResultEnable: true,
		DetectParam:        imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		NodeInfoEnable:     true,
	}
	if param.DeployRecordID > 0 {
		// 不会根据策略来决定问题
		apiParam.SimplePolicyEnable = true
		apiParam.RiskPolicyEnable = false
	}

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, apiParam)

	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	ans := data.ToImageBaseResponse()
	ans.AdaptI18(ctx)
	ans.Safe = data.CheckSafeByPolicy()

	response.JSONOK(ctx, response.WithItem(ans))
}

func (s *ScanResultAPI) SecurityIssueOverview(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)
	param.Filter = imagesecModel.EmptyFilter()

	assParam := imagesecModel.ImageAssociateParam{
		ImageFromType:      param.ImageFromType,
		ImageId:            param.ImageID,
		ImageUniqueID:      param.ImageUniqueID,
		DeployRecordID:     param.DeployRecordID,
		RiskPolicyEnable:   true,
		DetectResultEnable: true,
		ScanResultSearchParam: imagesecModel.ScanResultSearchParam{
			LayerDigest:       param.LayerDigest,
			SecurityPolicyIds: param.SecurityPolicyIds,
			ImageID:           param.ImageID,
			ImageUniqueID:     param.ImageUniqueID,
		},
		SearchVulnParam: imagesecModel.ApiSearchVulnParam{},
		DetectParam:     imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
	}
	assParam.AddExceptionType(param.ExceptionType)

	if len(param.SecurityPolicyIds) == 0 && param.ImageFromType != imagesecModel.ImageFromDeploy {
		data := imagesecModel.ImageWithCorrelateData2{}
		response.JSONOK(ctx, response.WithItem(data.ToSecurityIssueOverview1()))
	}

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, assParam)
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	if param.ImageFromType == imagesecModel.ImageFromDeploy {
		response.JSONOK(ctx, response.WithItem(data.ToSecurityIssueOverview2()))
		return
	}

	response.JSONOK(ctx, response.WithItem(data.ToSecurityIssueOverview1()))
	return
}

func (s *ScanResultAPI) ImageIssueStatistic(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)
	param.Filter = imagesecModel.EmptyFilter()

	assParam := imagesecModel.ImageAssociateParam{
		ImageFromType:      param.ImageFromType,
		ImageId:            param.ImageID,
		ImageUniqueID:      param.ImageUniqueID,
		DeployRecordID:     param.DeployRecordID,
		VulnEnable:         true,
		MalwareEnable:      true,
		EnvEnable:          true,
		PkgEnable:          true,
		LicenseEnable:      true,
		SensitiveEnable:    true,
		WebshellEnable:     true,
		RegistryEnable:     true,
		DetectResultEnable: true,
		RiskPolicyEnable:   true,
		TrustedEnable:      true,
		ImageInReg:         true,
		DetectParam:        imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		ScanResultSearchParam: imagesecModel.ScanResultSearchParam{
			LayerDigest:       param.LayerDigest,
			SecurityPolicyIds: param.SecurityPolicyIds,
			ImageID:           param.ImageID,
			ImageUniqueID:     param.ImageUniqueID,
		},
	}
	if len(param.SecurityPolicyIds) == 0 {
		assParam.RiskPolicyEnable = false
	}

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, assParam)
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	response.JSONOK(ctx, response.WithItem(data.ToSecurityIssueStatistic()))
	return
}

func (s *ScanResultAPI) GetImageRiskInfo(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	body := imagesecModel.ImageSearchApiParam{}
	if err := ctx.BindJSON(&body); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, err))
		return
	}
	body.JustReturnImage = true
	body.Fields = []string{"id", "image_uuid"}
	body.ImageFromType = param.ImageFromType

	body.Filter = imagesecModel.EmptyFilterForTotalQuery().SetLimit(consts.DefaultMaxLimit)

	images, _, err := s.ImageSrv.ListImageWithScanInfo(ctx, body)
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	ans := make([]ImageRiskStatic, 0)

	for i := range images {
		data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
			ImageId:         images[i].ID,
			VulnEnable:      true,
			MalwareEnable:   true,
			EnvEnable:       true,
			PkgEnable:       true,
			SensitiveEnable: true,
			WebshellEnable:  true,
			RegistryEnable:  true,
			ScanResultSearchParam: imagesecModel.ScanResultSearchParam{
				ImageID:             images[i].ID,
				ExceptionPkg:        consts.TrueString,
				ExceptionPkgLicense: consts.TrueString,
				ExceptionEnv:        consts.TrueString,
			},
		})
		if err != nil {
			logging.Get().Err(err).Int64("ImageID", images[i].ID).Msg("GetImageCorrelateData")
			continue
		}
		// 只要风险镜像
		if data.ImageBaseResponse.RiskScore == consts.NoRiskImageScore {
			continue
		}

		risk := ImageRiskStatic{
			ImageBaseResponse: data.ImageBaseResponse,
			Issue:             data.ToSecurityIssueStatistic(),
			SeverityOverview:  make([]imagesecModel.SeverityGroup, 0),
		}

		for j := range data.Vuln {
			risk.SeverityOverview = imagesecModel.AddSeverityGroup(risk.SeverityOverview, data.Vuln[j].SeverityInt)
		}
		sort.Sort(imagesecModel.SeverityGroups(risk.SeverityOverview))
		// 减少无用数据的返回
		risk.ImageBaseResponse.Suggests = nil
		ans = append(ans, risk)
	}
	// 以镜像UUID名去重
	exit := make(map[uint32]bool)
	res := make([]ImageRiskStatic, 0)
	for i := range ans {
		in := ans[i].ImageBaseResponse.UUID
		if !exit[in] {
			res = append(res, ans[i])
		}
		exit[in] = true
	}

	response.JSONOK(ctx, response.WithItems(res))
}

func (s *ScanResultAPI) GetImageLayer(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	image, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		DeployRecordID:        param.DeployRecordID,
		ImageId:               param.ImageID,
		VulnEnable:            true,
		SensitiveEnable:       true,
		MalwareEnable:         true,
		LicenseEnable:         true,
		EnvEnable:             true,
		WebshellEnable:        true,
		ScanResultSearchParam: imagesecModel.ScanResultSearchParam{AddLayer: true},
		SearchVulnParam:       imagesecModel.ApiSearchVulnParam{AddLayer: true},
		ImageUniqueID:         param.ImageUniqueID,
	})

	if err != nil {
		response.JSONError(ctx, scani18.SearchImageLayer(err))
		return
	}

	lys := image.GenImageLayer()

	response.JSONOK(ctx, response.WithItems(lys))
}

// 获取镜像漏洞-漏洞视角
func (s *ScanResultAPI) GetImageVulns(ctx *gin.Context) {
	vulnParam := GetSearchVulnParamFromCtx(ctx)

	resultParam := GetScanResultSearchParamFromCtx(ctx)

	vulnParam.Filter = vulnParam.Filter.SetSortFiled("severity").SetSortDesc()
	resultParam.Filter = resultParam.Filter.SetSortFiled("severity").SetSortDesc()

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:         resultParam.ImageFromType,
		ImageId:               resultParam.ImageID,
		ImageUniqueID:         resultParam.ImageUniqueID,
		DeployRecordID:        resultParam.DeployRecordID,
		VulnEnable:            true,
		DetectResultEnable:    true,
		ScanResultSearchParam: resultParam,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: resultParam.SecurityPolicyIds},
		SearchVulnParam:       vulnParam,
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	for i := range data.Vuln {
		data.Vuln[i].AdaptI18(ctx)
		data.Vuln[i].Simplify()
	}

	response.JSONOK(ctx, response.WithItems(data.Vuln),
		response.WithTotalItems(data.VulnCnt),
		response.WithItemsPerPage(vulnParam.Filter.Limit),
		response.WithStartIndex(vulnParam.Filter.Offset))
}

// 获取镜像漏洞-软件视角
func (s *ScanResultAPI) GetImageVulnPkg(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	filter := param.Filter.DeepCopy()

	param.Filter = param.Filter.SetLimit(0).SetOffset(0)

	vulnParam := imagesecModel.ApiSearchVulnParam{
		ImageFromType:    param.ImageFromType,
		PkgKeyword:       param.Keyword,
		ImageUniqueID:    param.ImageUniqueID,
		ImageLayerDigest: util.GetKeywordFromQuery(ctx, "layerDigest"),
	}

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		DeployRecordID:        param.DeployRecordID,
		VulnEnable:            true,
		LicenseEnable:         true,
		PkgEnable:             true,
		DetectResultEnable:    true,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		ScanResultSearchParam: param,
		SearchVulnParam:       vulnParam,
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	// 整理数据
	pkgVulnMap := make(map[uint64]*imagesecModel.VulnView)
	for i := range data.Vuln {
		pkgVulnMap[data.Vuln[i].PkgUniqueID] = data.Vuln[i]
	}

	pkgMap := make(map[uint64]VulnPKG)
	for i := range data.Pkg {
		pkg := data.Pkg[i]
		vp := VulnPKG{
			PkgName:          pkg.Name,
			PkgVersion:       pkg.Version,
			UniqueID:         pkg.UniqueID,
			Filepath:         pkg.Filepath,
			SeverityOverview: make([]imagesecModel.SeverityGroup, 0),
			Vulns:            make([]*imagesecModel.VulnView, 0),
			License:          pkg.License,
			PolicyDetect:     pkg.PolicyDetect,
		}
		pkgMap[vp.UniqueID] = vp
	}

	for i := range data.Vuln {
		vu := data.Vuln[i]
		sf, ok := pkgMap[vu.PkgUniqueID]
		if !ok {
			continue
		}
		sf.SeverityOverview = imagesecModel.AddSeverityGroup(sf.SeverityOverview, vu.SeverityInt)
		pkgMap[sf.UniqueID] = sf
	}
	// 按层级排序一下,便于前端展示
	for _, v := range pkgMap {
		sort.Sort(imagesecModel.SeverityGroups(v.SeverityOverview))
	}
	res := make([]VulnPKG, 0)
	for _, vp := range pkgMap {
		vp.SortScore = vp.GetSortScore()
		res = append(res, vp)
	}

	sort.Sort(VulnPKGs(res))
	cnt := len(res)

	if len(res) <= int(filter.Offset) {
		res = make([]VulnPKG, 0)
	} else if len(res) <= int(filter.Offset+filter.Limit) {
		res = res[int(filter.Offset):]
	} else {
		res = res[int(filter.Offset):int(filter.Offset+filter.Limit)]
	}

	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(int64(cnt)),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// 获取镜像漏洞-编程语言
func (s *ScanResultAPI) GetImageVulnLanguage(ctx *gin.Context) {

	param := GetScanResultSearchParamFromCtx(ctx)
	filter := param.Filter.DeepCopy()
	param.Filter = param.Filter.SetLimit(0).SetOffset(0)
	vulnParam := GetSearchVulnParamFromCtx(ctx)
	vulnParam.Filter = imagesecModel.EmptyFilter()

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		DeployRecordID:        param.DeployRecordID,
		VulnEnable:            true,
		DetectResultEnable:    true,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		ScanResultSearchParam: param,
		SearchVulnParam:       vulnParam,
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}
	// 整理数据
	languageMap := make(map[string]*VulnLanguage)
	vulns := data.Vuln
	for i := range vulns {
		if vulns[i].Language == "" {
			continue
		}

		key := fmt.Sprintf("%s|%s", vulns[i].Language, vulns[i].Target)
		if _, ok := languageMap[key]; !ok {
			languageMap[key] = &VulnLanguage{
				LanguageName:     vulns[i].Language,
				LanguagePath:     vulns[i].Target,
				SeverityOverview: make([]imagesecModel.SeverityGroup, 0),
				Vulns:            make([]*imagesecModel.VulnView, 0),
			}
		}
		sf := languageMap[key]
		sf.SeverityOverview = imagesecModel.AddSeverityGroup(sf.SeverityOverview, vulns[i].SeverityInt)
		languageMap[key] = sf
	}
	// 按层级排序一下,便于前端展示
	for _, v := range languageMap {
		sort.Sort(imagesecModel.SeverityGroups(v.SeverityOverview))
		sort.Sort(imagesecModel.VulnViews(v.Vulns))
	}
	res := make([]*VulnLanguage, 0)
	for _, vp := range languageMap {
		vp.SortScore = vp.GetSortScore()
		res = append(res, vp)
	}
	cnt := int64(len(res))
	sort.Sort(VulnLanguages(res))
	if len(res) <= int(filter.Offset) {
		res = make([]*VulnLanguage, 0)
	} else if len(res) <= int(filter.Offset+filter.Limit) {
		res = res[int(filter.Offset):]
	} else {
		res = res[int(filter.Offset):int(filter.Offset+filter.Limit)]
	}

	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// 获取镜像漏洞-Gobinary视角
func (s *ScanResultAPI) GetImageVulnGoBinary(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	filter := param.Filter.DeepCopy()
	param.Filter = param.Filter.SetLimit(0).SetOffset(0)

	vulnParam := GetSearchVulnParamFromCtx(ctx)
	vulnParam.Filter = imagesecModel.EmptyFilter()

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		DeployRecordID:        param.DeployRecordID,
		VulnEnable:            true,
		DetectResultEnable:    true,
		ScanResultSearchParam: param,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		SearchVulnParam:       vulnParam,
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}
	vulns := data.Vuln
	// 整理数据
	gobinaryMap := make(map[string]*VulnGobinary)
	for i := range vulns {
		if vulns[i].Language != consts.VulnLanguageGO {
			continue
		}
		if vulns[i].Target == "" {
			continue
		}

		index := strings.LastIndex(vulns[i].Target, "/")

		vulnGO := VulnGobinary{
			SeverityOverview: make([]imagesecModel.SeverityGroup, 0),
			Vulns:            make([]*imagesecModel.VulnView, 0),
		}
		if index == -1 {
			vulnGO.GoName = vulns[i].Target
			vulnGO.GoPath = "/"
		} else {
			vulnGO.GoName = vulns[i].Target[:index]
			vulnGO.GoPath = vulns[i].Target[index+1:]
		}

		key := fmt.Sprintf("%s|%s", vulnGO.GoName, vulnGO.GoPath)

		if _, ok := gobinaryMap[key]; !ok {
			gobinaryMap[key] = &vulnGO
		}
		sf := gobinaryMap[key]
		sf.Vulns = append(sf.Vulns, vulns[i])
		sf.SeverityOverview = imagesecModel.AddSeverityGroup(sf.SeverityOverview, vulns[i].SeverityInt)
		gobinaryMap[key] = sf
	}
	// 按层级排序一下,便于前端展示
	for _, v := range gobinaryMap {
		sort.Sort(imagesecModel.SeverityGroups(v.SeverityOverview))
		sort.Sort(imagesecModel.VulnViews(v.Vulns))
	}
	res := make([]*VulnGobinary, 0)
	for _, vp := range gobinaryMap {
		vp.SortScore = vp.GetSortScore()
		res = append(res, vp)
	}
	sort.Sort(VulnGobinaries(res))
	cnt := int64(len(res))
	if len(res) <= int(filter.Offset) {
		res = make([]*VulnGobinary, 0)
	} else if len(res) <= int(filter.Offset+filter.Limit) {
		res = res[int(filter.Offset):]
	} else {
		res = res[int(filter.Offset):int(filter.Offset+filter.Limit)]
	}

	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// 获取镜像漏洞-开发框架视角
func (s *ScanResultAPI) GetImageVulnFrame(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	filter := param.Filter.DeepCopy()
	param.Filter = param.Filter.SetLimit(0).SetOffset(0)

	vulnParam := imagesecModel.ApiSearchVulnParam{
		ImageFromType:    param.ImageFromType,
		PkgKeyword:       param.Keyword,
		ImageUniqueID:    param.ImageUniqueID,
		ImageLayerDigest: util.GetKeywordFromQuery(ctx, "layerDigest"),
	}

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		DeployRecordID:        param.DeployRecordID,
		VulnEnable:            true,
		DetectResultEnable:    true,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		ScanResultSearchParam: param,
		SearchVulnParam:       vulnParam,
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}
	vulns := data.Vuln
	// 整理数据
	frameMap := make(map[string]*VulnFrame)
	for i := range vulns {
		if vulns[i].Frame == "" {
			continue
		}
		vulnFrame := &VulnFrame{
			Frame: vulns[i].Frame,
		}

		if _, ok := frameMap[vulns[i].Frame]; !ok {
			frameMap[vulns[i].Frame] = vulnFrame
		}
		sf := frameMap[vulns[i].Frame]
		sf.Vulns = append(sf.Vulns, vulns[i])
		sf.SeverityOverview = imagesecModel.AddSeverityGroup(sf.SeverityOverview, vulns[i].SeverityInt)
		frameMap[vulns[i].Frame] = sf
	}
	// 按层级排序一下,便于前端展示
	for _, v := range frameMap {
		sort.Sort(imagesecModel.SeverityGroups(v.SeverityOverview))
		sort.Sort(imagesecModel.VulnViews(v.Vulns))
	}
	res := make([]*VulnFrame, 0)
	for _, vp := range frameMap {
		vp.SortScore = vp.GetSortScore()
		res = append(res, vp)
	}
	sort.Sort(VulnFrames(res))
	cnt := int64(len(res))
	if len(res) <= int(filter.Offset) {
		res = make([]*VulnFrame, 0)
	} else if len(res) <= int(filter.Offset+filter.Limit) {
		res = res[int(filter.Offset):]
	} else {
		res = res[int(filter.Offset):int(filter.Offset+filter.Limit)]
	}

	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// webshell
func (s *ScanResultAPI) GetImageWebshell(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	filter := imagesecModel.GetFilter(ctx)

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		DeployRecordID:        param.DeployRecordID,
		WebshellEnable:        true,
		CheckDownloadable:     true,
		DetectResultEnable:    true,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		ScanResultSearchParam: param,
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}
	for i := range data.WebshellView {
		data.WebshellView[i].Code = make([]imagesecModel.WebshellCode, 0)
		data.WebshellView[i].AdaptI18(ctx)
	}
	response.JSONOK(ctx, response.WithItems(data.WebshellView),
		response.WithTotalItems(data.WebshellCnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// 漏洞详情
func (s *ScanResultAPI) GetVulnDetail(ctx *gin.Context) {
	param := GetSearchVulnParamFromCtx(ctx)
	vulnParam := imagesecModel.ApiSearchVulnParam{
		VulnUniqueID: param.VulnUniqueID,
	}
	vuln, _, err := s.ScanResultSrv.SearchVuln(ctx, vulnParam)
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}
	if len(vuln) == 0 {
		response.JSONError(ctx, fmt.Errorf("not find vuln"))
		return
	}

	vuln[0].AdaptI18(ctx)

	response.JSONOK(ctx, response.WithItem(vuln[0]))
}

func GetSearchVulnParamFromCtx(ctx *gin.Context) imagesecModel.ApiSearchVulnParam {
	param := imagesecModel.ApiSearchVulnParam{
		ImageFromType:    util.GetKeywordFromQuery(ctx, "imageFromType"),
		PkgKeyword:       util.GetKeywordFromQuery(ctx, "pkgKeyword"),
		LanguageKeyword:  util.GetKeywordFromQuery(ctx, "languageKeyword"),
		TargetKeyword:    util.GetKeywordFromQuery(ctx, "targetKeyword"),
		VulnKeyword:      util.GetKeywordFromQuery(ctx, "vulnKeyword"),
		LanguageName:     util.GetKeywordFromQuery(ctx, "languageName"),
		LanguagePath:     util.GetKeywordFromQuery(ctx, "languagePath"),
		FrameKeyword:     util.GetKeywordFromQuery(ctx, "frame"),
		PkgUniqueID:      util.GetUint64FromQuery(ctx, "pkgUniqueID"),
		VulnUniqueID:     util.GetUint64FromQuery(ctx, "uniqueID"),
		ImageUniqueID:    util.GetUint64FromQuery(ctx, "imageUniqueID"),
		ImageLayerDigest: util.GetKeywordFromQuery(ctx, "layerDigest"),
		CanFixed:         util.GetStringSliceFromQuery(ctx, "canFixed"),
		SeverityStr:      util.GetStringSliceFromQuery(ctx, "severity"),
		NeedKernel:       util.GetStringSliceFromQuery(ctx, "kernelVuln"),
		ClassType:        util.GetStringSliceFromQuery(ctx, "class"),
		AttackPath:       util.GetStringSliceFromQuery(ctx, "attackPath"),
		OnlineImageVuln:  util.GetKeywordFromQuery(ctx, "online"),
		Filter:           imagesecModel.GetFilter(ctx).SetDefault().SetMaxLimit(consts.DefaultPerPage),
	}
	keyword := util.GetKeywordFromQuery(ctx, "keyword")
	if keyword != "" {
		param.VulnKeyword = keyword
	}

	return param
}
