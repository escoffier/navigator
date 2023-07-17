package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	apimodel "gitlab.com/piccolo_su/vegeta/cmd/scanner/api/model"
	imageMetaSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-i18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanResultAPI struct {
	ImageSrv    map[string]imageMetaSrv.ImageService
	NodeVulnSrv imagesecSrv.VulnService
}

func NewScanResultAPI(
	imageSrv map[string]imageMetaSrv.ImageService,
	nodeVulnSrv imagesecSrv.VulnService,
) *ScanResultAPI {
	return &ScanResultAPI{ImageSrv: imageSrv, NodeVulnSrv: nodeVulnSrv}
}

func GetScanResultSearchParamFromCtx(ctx *gin.Context) imagesecModel.ScanResultSearchParam {
	param := imagesecModel.ScanResultSearchParam{
		ImageFromType:      util.GetKeywordFromQuery(ctx, "imageFromType"),
		ImageID:            util.GetInt64FromQuery(ctx, "imageID"),
		ImageUniqueID:      util.GetUint64FromQuery(ctx, "imageUniqueID"),
		LayerDigest:        util.GetKeywordFromQuery(ctx, "layerDigest"),
		Keyword:            util.GetKeywordFromQuery(ctx, "keyword"),
		ExceptionPkg:       util.GetKeywordFromQuery(ctx, "exceptionPkg"),     // 查看异常软件
		ExceptionLicense:   util.GetKeywordFromQuery(ctx, "exceptionLicense"), // 查看不允许的开源协议
		ExceptionEnv:       util.GetKeywordFromQuery(ctx, "exceptionEnv"),     // 查看不允许的开源协议
		PasswdEnv:          util.GetKeywordFromQuery(ctx, "passwdEnv"),        // 查看不允许的开源协议
		ExceptionVuln:      util.GetKeywordFromQuery(ctx, "exceptionVuln"),
		ExceptionMalware:   util.GetKeywordFromQuery(ctx, "exceptionMalware"),
		ExceptionSensitive: util.GetKeywordFromQuery(ctx, "exceptionSensitive"),
		ExceptionWebshell:  util.GetKeywordFromQuery(ctx, "exceptionWebshell"),
		VulnSeverity:       util.GetStringSliceFromQuery(ctx, "vulnSeverity"),
		LicenseSearch:      util.GetStringSliceFromQuery(ctx, "license"),
		SecurityPolicyIds:  util.GetInt64SliceFromQuery(ctx, "securityPolicyIds"),
		WebshellRiskLevel:  util.GetStringSliceFromQuery(ctx, "riskLevel"),
		Filter:             model.GetFilter(ctx).SetDefault(),
	}
	// 对于老接口可能没有这个参数，后期和前端统一后，把这个兼容去了
	if param.ImageFromType == "" {
		param.ImageFromType = imagesecModel.ImageFromRegistry
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

	filter := model.GetFilter(ctx)

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		MalwareEnable:         true,
		DetectResultEnable:    true,
		ScanResultSearchParam: param,
		Filter:                filter,
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	response.JSONOK(ctx, response.WithItems(data.Malware),
		response.WithTotalItems(data.MalwareCnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ScanResultAPI) SearchSensitive(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	filter := model.GetFilter(ctx)
	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		SensitiveEnable:       true,
		DetectResultEnable:    true,
		ScanResultSearchParam: param,
		Filter:                filter,
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	ans := make([]apimodel.ImageSensitiveFile, 0)
	res := data.Sensitive
	for i := range res {
		split := strings.Split(res[i].Name, "/")
		ses := apimodel.ImageSensitiveFile{
			ID:           res[i].ID,
			Path:         res[i].Name,
			Name:         res[i].Name,
			PolicyDetect: res[i].PolicyDetect,
		}
		if len(split) >= 2 {
			ses.Name = split[len(split)-1]
		}

		ans = append(ans, ses)
	}

	response.JSONOK(ctx, response.WithItems(ans),
		response.WithTotalItems(data.SensitiveCnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ScanResultAPI) SearchEnv(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	filter := model.GetFilter(ctx)

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		EnvEnable:             true,
		ScanResultSearchParam: param,
		DetectResultEnable:    true,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		Filter:                filter,
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	response.JSONOK(ctx, response.WithItems(data.Env),
		response.WithTotalItems(data.EnvCnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ScanResultAPI) SearchSoftware(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	filter := model.GetFilter(ctx)

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		PkgEnable:             true,
		DetectResultEnable:    true,
		VulnEnable:            true,
		LicenseEnable:         true,
		ScanResultSearchParam: param,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		Filter:                model.EmptyFilterForTotalQuery(),
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	preVulns := data.Vuln
	vulnMap := make(map[string][]VulnResponse)
	for i := range preVulns {
		key := fmt.Sprintf("%s|%s", preVulns[i].PkgName, preVulns[i].PkgVersion)
		if vulnMap[key] == nil {
			vulnMap[key] = make([]VulnResponse, 0)
		}
		vus := vulnMap[key]
		vus = append(vus, convertNodeVulnView(preVulns[i]))
		vulnMap[key] = vus
	}

	// 整理数据
	pkgMap := make(map[string]VulnPKG)
	software := data.Pkg
	for i := range software {
		key := fmt.Sprintf("%s|%s", software[i].Name, software[i].Version)
		if _, ok := pkgMap[key]; !ok {
			vp := VulnPKG{
				PkgName:          software[i].Name,
				PkgVersion:       software[i].Version,
				UniqueID:         software[i].UniqueID,
				SeverityOverview: make([]imagesecModel.SeverityGroup, 0),
				Vulns:            make([]VulnResponse, 0),
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
		res[i].Vulns = make([]VulnResponse, 0)
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

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType:      param.ImageFromType,
		ImageId:            param.ImageID,
		ImageUniqueID:      param.ImageUniqueID,
		VulnEnable:         true,
		MalwareEnable:      true,
		EnvEnable:          true,
		PkgEnable:          true,
		SensitiveEnable:    true,
		WebshellEnable:     true,
		SubtaskEnable:      true,
		RegistryEnable:     true,
		ContainerEnable:    true,
		RiskPolicyEnable:   true,
		DetectResultEnable: true,
		DetectParam:        imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		NodeInfoEnable:     true,
	})

	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	ans := data.ToImageBaseResponse()
	ans.AdaptI18(ctx)
	ans.Safe = data.CheckSafeByPolicy()

	response.JSONOK(ctx, response.WithItem(ans))
}

func (s *ScanResultAPI) ImageLayers(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	if err := imagesecModel.ImageFromType(param.ImageFromType).Check(); err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageId:         param.ImageID,
		VulnEnable:      true,
		MalwareEnable:   true,
		EnvEnable:       true,
		PkgEnable:       true,
		SensitiveEnable: true,
		WebshellEnable:  true,
		SubtaskEnable:   true,
		RegistryEnable:  true,
		ContainerEnable: true,
	})

	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}
	baseImage := data.ToImageBaseResponse()

	response.JSONOK(ctx, response.WithItem(baseImage))
}

func (s *ScanResultAPI) ImageIssueStatistic(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	assParam := imagesecModel.GetImageAssociateDataParam{
		ImageFromType:      param.ImageFromType,
		ImageId:            param.ImageID,
		ImageUniqueID:      param.ImageUniqueID,
		VulnEnable:         true,
		MalwareEnable:      true,
		EnvEnable:          true,
		PkgEnable:          true,
		SensitiveEnable:    true,
		WebshellEnable:     true,
		RegistryEnable:     true,
		DetectResultEnable: true,
		RiskPolicyEnable:   true,
		DetectParam:        imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		ScanResultSearchParam: imagesecModel.ScanResultSearchParam{
			SecurityPolicyIds: param.SecurityPolicyIds,
			ImageID:           param.ImageID,
			ImageUniqueID:     param.ImageUniqueID,
		},
		Filter: model.EmptyFilterForTotalQuery(),
	}

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, assParam)
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}
	if param.ImageFromType == imagesecModel.ImageFromRegistry {
		response.JSONOK(ctx, response.WithItem(data.ToSecurityIssueOverview()))
		return
	}
	if param.ImageFromType == imagesecModel.ImageFromNode {
		response.JSONOK(ctx, response.WithItem(data.ToSecurityIssueOverview2()))
		return
	}
}

func (s *ScanResultAPI) GetImageRiskInfo(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	body := imagesecModel.ImageListParam{}
	if err := ctx.BindJSON(&body); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, err))
		return
	}
	body.JustReturnImage = true
	body.Fields = []string{"id", "image_uuid"}
	body.ImageFromType = param.ImageFromType

	body.Filter = model.EmptyFilterForTotalQuery().SetLimit(consts.DefaultLimit)

	images, _, err := s.getImageSrv(ctx).ListImageWithScanInfo(ctx, body)
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}

	ans := make([]ImageRiskStatic, 0)

	for i := range images {
		data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
			ImageId:         images[i].ID,
			VulnEnable:      true,
			MalwareEnable:   true,
			EnvEnable:       true,
			PkgEnable:       true,
			SensitiveEnable: true,
			WebshellEnable:  true,
			RegistryEnable:  true,
			ScanResultSearchParam: imagesecModel.ScanResultSearchParam{
				ImageID:          images[i].ID,
				ExceptionPkg:     consts.TrueString,
				ExceptionLicense: consts.TrueString,
				ExceptionEnv:     consts.TrueString,
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
			Issue:             data.ToSecurityIssueOverview(),
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
	// 以镜像名去重
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

	image, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageId:       param.ImageID,
		ImageUniqueID: param.ImageUniqueID,
	})

	if err != nil {
		response.JSONError(ctx, scani18.SearchImageLayer(err))
		return
	}
	response.JSONOK(ctx, response.WithItems(image.Image.Layer))
}

// 获取镜像漏洞-漏洞视角(只是节点镜像使用)
func (s *ScanResultAPI) GetImageVulns(ctx *gin.Context) {
	vulnParam := GetSearchVulnParamFromCtx(ctx)
	param := GetScanResultSearchParamFromCtx(ctx)

	severity := util.GetStringSliceFromQuery(ctx, "severity")
	attackPath := util.GetStringSliceFromQuery(ctx, "attackPath") // 攻击途径
	class := util.GetStringSliceFromQuery(ctx, "class")           // 漏洞类型
	kernel := util.GetStringSliceFromQuery(ctx, "kernelVuln")     // 是否内核漏洞
	if util.ExistInStringSlice(kernel, consts.TrueString) && util.ExistInStringSlice(kernel, consts.FalseString) {
		kernel = nil
	}

	filter := param.Filter.DeepCopy()
	vulnParam.Filter = vulnParam.Filter.SetSortFiled("severity").SetSortDesc()

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
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

	res := make([]VulnResponse, len(data.Vuln))
	for i := range data.Vuln {
		data.Vuln[i].AdaptI18(ctx)

		res[i] = convertNodeVulnView(data.Vuln[i])
	}
	ans := make([]VulnResponse, 0)
	for i := range res {
		if len(attackPath) > 0 && !util.ExistInStringSlice(attackPath, res[i].AttackPath) {
			continue
		}
		if len(class) > 0 && !util.ExistInStringSlice(class, res[i].Class) {
			continue
		}
		if len(kernel) > 0 && ((res[i].KernelVuln && kernel[0] == consts.FalseString) || (!res[i].KernelVuln && kernel[0] == consts.TrueString)) {
			continue
		}
		if len(severity) > 0 && !util.ExistInStringSlice(severity, res[i].Severity) {
			continue
		}
		ans = append(ans, res[i])
	}

	cnt := int64(len(ans))

	if len(ans) <= int(filter.Offset) {
		ans = make([]VulnResponse, 0)
	} else if len(ans) <= int(filter.Offset+filter.Limit) {
		ans = ans[int(filter.Offset):]
	} else {
		ans = ans[int(filter.Offset):int(filter.Offset+filter.Limit)]
	}

	response.JSONOK(ctx, response.WithItems(ans),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// 获取镜像漏洞-软件视角(只是节点镜像使用)
func (s *ScanResultAPI) GetImageVulnPkg(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	filter := param.Filter.DeepCopy()
	param.Filter = param.Filter.SetLimit(0).SetOffset(0)

	vulnParam := imagesecModel.ApiSearchVulnParam{
		ImageFromType:    param.ImageFromType,
		PkgKeyword:       param.Keyword,
		ImageID:          param.ImageID,
		ImageUniqueID:    param.ImageUniqueID,
		ImageLayerDigest: util.GetKeywordFromQuery(ctx, "layerDigest"),
	}

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
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
	pkgVulnMap := make(map[uint64]VulnResponse)
	for i := range data.Vuln {
		pkgVulnMap[data.Vuln[i].PkgUniqueID] = convertNodeVulnView(data.Vuln[i])
	}

	pkgMap := make(map[uint64]VulnPKG)
	for i := range data.Pkg {
		pkg := data.Pkg[i]
		vp := VulnPKG{
			PkgName:          pkg.Name,
			PkgVersion:       pkg.Version,
			UniqueID:         pkg.UniqueID,
			SeverityOverview: make([]imagesecModel.SeverityGroup, 0),
			Vulns:            make([]VulnResponse, 0),
			License:          pkg.License,
			PolicyDetect:     pkg.PolicyDetect,
		}
		if _, ok := pkgVulnMap[pkg.UniqueID]; ok {
			vp.Target = pkgVulnMap[pkg.UniqueID].Target
		}
		pkgMap[vp.UniqueID] = vp
	}

	for i := range data.Vuln {
		vu := data.Vuln[i]
		sf, ok := pkgMap[vu.PkgUniqueID]
		if !ok {
			continue
		}
		// sf.Vulns = append(sf.Vulns, convertNodeVulnView(data.Vuln[i]))
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

// 获取镜像漏洞-编程语言(节点镜像使用)
func (s *ScanResultAPI) GetImageVulnLanguage(ctx *gin.Context) {

	param := GetScanResultSearchParamFromCtx(ctx)

	filter := param.Filter.DeepCopy()
	param.Filter = param.Filter.SetLimit(0).SetOffset(0)
	vulnParam := GetSearchVulnParamFromCtx(ctx)

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
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
				Vulns:            make([]VulnResponse, 0),
			}
		}
		sf := languageMap[key]
		// sf.Vulns = append(sf.Vulns, convertNodeVulnView(vulns[i]))
		sf.SeverityOverview = imagesecModel.AddSeverityGroup(sf.SeverityOverview, vulns[i].SeverityInt)
		languageMap[key] = sf
	}
	// 按层级排序一下,便于前端展示
	for _, v := range languageMap {
		sort.Sort(imagesecModel.SeverityGroups(v.SeverityOverview))
		sort.Sort(VulnLists(v.Vulns))
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

// 获取镜像漏洞-Gobinary视角(节点镜像使用)
func (s *ScanResultAPI) GetImageVulnGoBinary(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	filter := param.Filter.DeepCopy()
	param.Filter = param.Filter.SetLimit(0).SetOffset(0)

	vulnParam := GetSearchVulnParamFromCtx(ctx)

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		VulnEnable:            true,
		DetectResultEnable:    true,
		ScanResultSearchParam: param,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		SearchVulnParam:       vulnParam,
		Filter:                nil,
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

		index := strings.LastIndex(vulns[i].Target, "/")

		vulnGO := VulnGobinary{
			SeverityOverview: make([]imagesecModel.SeverityGroup, 0),
			Vulns:            make([]VulnResponse, 0),
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
		sf.Vulns = append(sf.Vulns, convertNodeVulnView(vulns[i]))
		sf.SeverityOverview = imagesecModel.AddSeverityGroup(sf.SeverityOverview, vulns[i].SeverityInt)
		gobinaryMap[key] = sf
	}
	// 按层级排序一下,便于前端展示
	for _, v := range gobinaryMap {
		sort.Sort(imagesecModel.SeverityGroups(v.SeverityOverview))
		sort.Sort(VulnLists(v.Vulns))
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

// 获取镜像漏洞-开发框架视角(节点镜像使用)
func (s *ScanResultAPI) GetImageVulnFrame(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	filter := param.Filter.DeepCopy()
	param.Filter = param.Filter.SetLimit(0).SetOffset(0)

	vulnParam := imagesecModel.ApiSearchVulnParam{
		ImageFromType:    param.ImageFromType,
		PkgKeyword:       param.Keyword,
		ImageID:          param.ImageID,
		ImageUniqueID:    param.ImageUniqueID,
		ImageLayerDigest: util.GetKeywordFromQuery(ctx, "layerDigest"),
	}

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		VulnEnable:            true,
		DetectResultEnable:    true,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		ScanResultSearchParam: param,
		SearchVulnParam:       vulnParam,
		Filter:                nil,
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
		sf.Vulns = append(sf.Vulns, convertNodeVulnView(vulns[i]))
		sf.SeverityOverview = imagesecModel.AddSeverityGroup(sf.SeverityOverview, vulns[i].SeverityInt)
		frameMap[vulns[i].Frame] = sf
	}
	// 按层级排序一下,便于前端展示
	for _, v := range frameMap {
		sort.Sort(imagesecModel.SeverityGroups(v.SeverityOverview))
		sort.Sort(VulnLists(v.Vulns))
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

// webshell(节点镜像使用)
func (s *ScanResultAPI) GetImageWebshell(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)

	filter := model.GetFilter(ctx)

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		WebshellEnable:        true,
		DetectResultEnable:    true,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		ScanResultSearchParam: param,
		Filter:                filter,
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetImageInfo(err))
		return
	}
	for i := range data.Webshell {
		data.Webshell[i].Code = make([]imagesecModel.WebshellCode, 0)
		data.Webshell[i].AdaptI18(ctx)
	}
	response.JSONOK(ctx, response.WithItems(data.Webshell),
		response.WithTotalItems(data.WebshellCnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// 漏洞详情(只是节点镜像使用)
func (s *ScanResultAPI) GetVulnDetail(ctx *gin.Context) {
	param := GetSearchVulnParamFromCtx(ctx)
	vulnParam := imagesecModel.ApiSearchVulnParam{
		VulnId:       param.VulnId,
		VulnUniqueID: param.VulnUniqueID,
	}
	vuln, _, err := s.NodeVulnSrv.SearchVuln(ctx, vulnParam)
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

func (s *ScanResultAPI) getImageSrv(ctx *gin.Context) imageMetaSrv.ImageService {
	imageFromType := util.GetKeywordFromQuery(ctx, "imageFromType")
	if imageFromType == "" {
		imageFromType = imagesecModel.ImageFromRegistry
	}
	if err := imagesecModel.ImageFromType(imageFromType).Check(); err != nil {
		logging.Get().Error().Msg("not get imageFromType")
		imageFromType = imagesecModel.ImageFromRegistry
	}

	return s.ImageSrv[imageFromType]
}

func GetSearchVulnParamFromCtx(ctx *gin.Context) imagesecModel.ApiSearchVulnParam {
	param := imagesecModel.ApiSearchVulnParam{
		ImageFromType:    util.GetKeywordFromQuery(ctx, "imageFromType"),
		VulnId:           util.GetInt64FromQuery(ctx, "id"),
		PkgKeyword:       util.GetKeywordFromQuery(ctx, "pkgKeyword"),
		LanguageKeyword:  util.GetKeywordFromQuery(ctx, "languageKeyword"),
		TargetKeyword:    util.GetKeywordFromQuery(ctx, "targetKeyword"),
		VulnKeyword:      util.GetKeywordFromQuery(ctx, "keyword"),
		FrameKeyword:     util.GetKeywordFromQuery(ctx, "frame"),
		PkgUniqueID:      util.GetUint64FromQuery(ctx, "pkgUniqueID"),
		VulnUniqueID:     util.GetUint64FromQuery(ctx, "uniqueID"),
		ImageID:          util.GetInt64FromQuery(ctx, "imageID"),
		ImageUniqueID:    util.GetUint64FromQuery(ctx, "imageUniqueID"),
		ImageLayerDigest: util.GetKeywordFromQuery(ctx, "layerDigest"),
		PkgName:          util.GetKeywordFromQuery(ctx, "pkgName"),
		PkgVersion:       util.GetKeywordFromQuery(ctx, "pkgVersion"),
		CanFixed:         util.GetKeywordFromQuery(ctx, "canFixed"),
		SeverityStr:      util.GetStringSliceFromQuery(ctx, "severity"),
		ClassType:        util.GetStringSliceFromQuery(ctx, "classType"),
		NeedKernel:       util.GetKeywordFromQuery(ctx, "kernelVuln"),
		AttackPath:       util.GetStringSliceFromQuery(ctx, "attackPath"),
		VulnClass:        util.GetStringSliceFromQuery(ctx, "class"),
		OnlineImageVuln:  util.GetKeywordFromQuery(ctx, "onlineImageVuln"),
		Filter:           model.GetFilter(ctx).SetDefault(),
	}
	// 对于老接口可能没有这个参数，后期和前端统一后，把这个兼容去了
	if param.ImageFromType == "" {
		param.ImageFromType = imagesecModel.ImageFromNode
	}

	if param.PkgUniqueID > 0 {
		param.PkgName = ""
		param.PkgVersion = ""
	}

	goName := util.GetKeywordFromQuery(ctx, "goName")
	goPath := util.GetKeywordFromQuery(ctx, "goPath")

	if goPath != "/" && goPath != "" {
		goName = goName + "/" + goPath
	}
	if goName != "" {
		param.TargetKeyword = goName
		param.LanguageKeyword = consts.VulnLanguageGO
	}
	languageName := util.GetKeywordFromQuery(ctx, "languageName")
	languagePath := util.GetKeywordFromQuery(ctx, "languagePath")
	if languageName != "" {
		param.LanguageKeyword = languageName
	}
	if languagePath != "" {
		param.TargetKeyword = languagePath
	}

	return param
}
