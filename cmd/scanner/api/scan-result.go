package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	apimodel "gitlab.com/piccolo_su/vegeta/cmd/scanner/api/model"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanResultAPI struct {
	ImageSrv component.ImageSrvInterface
	vulnSrv  component.VulnServiceInterface
}

func NewScanResultAPI(
	imageSrv component.ImageSrvInterface,
	vulnSrv component.VulnServiceInterface,
) *ScanResultAPI {
	return &ScanResultAPI{ImageSrv: imageSrv, vulnSrv: vulnSrv}
}

func GetParamFromCtx(ctx *gin.Context) model.ScanResultSearchParam {
	param := model.ScanResultSearchParam{}
	if uniqueImage, err := strconv.ParseInt(ctx.Query("imageID"), 10, 64); err == nil {
		param.ImageID = uniqueImage
	}

	param.LayerDigest = ctx.Query("layerDigest")
	param.Keyword = ctx.Query("keyword")
	param.AbnormalSoft = ctx.Query("abnormalSoft")       // 查看异常软件
	param.AbnormalLicense = ctx.Query("abnormalLicense") // 查看不允许的开源协议
	param.AbnormalEnv = ctx.Query("abnormalEnv")         // 查看不允许的开源协议
	param.VulnSeverity = util.GetStringSliceFromQuery(ctx, "vulnSeverity")
	param.LicenseSearch = util.GetStringSliceFromQuery(ctx, "license")
	return param
}

func (s *ScanResultAPI) SearchVirus(ctx *gin.Context) {
	param := GetParamFromCtx(ctx)
	filter := model.GetFilter(ctx)
	data, err := s.ImageSrv.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{
		ImageId:               param.ImageID,
		VirusEnable:           true,
		ScanResultSearchParam: param,
		Filter:                filter,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(data.Virus),
		response.WithTotalItems(data.VirusCnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ScanResultAPI) SearchSensitive(ctx *gin.Context) {
	param := GetParamFromCtx(ctx)

	filter := model.GetFilter(ctx)

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{
		ImageId:               param.ImageID,
		SensitiveEnable:       true,
		ScanResultSearchParam: param,
		Filter:                filter,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	ans := make([]apimodel.ImageSensitiveFile, 0)
	res := data.Sensitive
	for i := range res {
		split := strings.Split(res[i].Name, "/")
		ses := apimodel.ImageSensitiveFile{
			ID:   res[i].ID,
			Path: res[i].Name,
			Name: res[i].Name,
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
	param := GetParamFromCtx(ctx)
	filter := model.GetFilter(ctx)

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{
		ImageId:               param.ImageID,
		EnvEnable:             true,
		ScanResultSearchParam: param,
		Filter:                filter,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(data.Env),
		response.WithTotalItems(data.EnvCnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ScanResultAPI) SearchSoftware(ctx *gin.Context) {
	param := GetParamFromCtx(ctx)
	filter := model.GetFilter(ctx)

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{
		ImageId:               param.ImageID,
		SoftwareEnable:        true,
		ScanResultSearchParam: param,
		Filter:                model.EmptyFilterForTotalQuery(),
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	// 再查漏洞
	preVulns, _, err := s.vulnSrv.SearchVulns(ctx, model.SearchVulnParam{ImageIds: []int64{param.ImageID}}, model.EmptyFilterForTotalQuery())
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	vulnMap := make(map[string][]VulnResponse)
	for i := range preVulns {
		key := fmt.Sprintf("%s|%s", preVulns[i].PkgName, preVulns[i].PkgVersion)
		if vulnMap[key] == nil {
			vulnMap[key] = make([]VulnResponse, 0)
		}
		vus := vulnMap[key]
		vus = append(vus, convertVuln(preVulns[i]))
		vulnMap[key] = vus
	}

	// 整理数据
	pkgMap := make(map[string]VulnPKG)
	software := data.Software
	for i := range software {
		key := fmt.Sprintf("%s|%s", software[i].Name, software[i].Version)
		if _, ok := pkgMap[key]; !ok {
			vp := VulnPKG{
				PkgName:          software[i].Name,
				PkgVersion:       software[i].Version,
				UniqueID:         software[i].UniqueID,
				SeverityOverview: make([]model.SeverityGroup, 0),
				Vulns:            make([]VulnResponse, 0),
				License:          software[i].License,
				AbnormalLicense:  util.ExistBit1(software[i].Flag, model.FlagHasExceptLicense),
				AbnormalSoft:     util.ExistBit1(software[i].Flag, model.FlagHasSoftware),
			}
			pkgMap[key] = vp
		}
		sf := pkgMap[key]
		sf.Vulns = append(sf.Vulns, vulnMap[key]...)
		for j := range sf.Vulns {
			sf.SeverityOverview = addSeverityGroup(sf.SeverityOverview, sf.Vulns[j].SeverityInt)
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
		sort.Sort(SeverityGroups(res[i].SeverityOverview))
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
		response.WithTotalItems(data.SoftwareCnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ScanResultAPI) ImageBaseDetail(ctx *gin.Context) {
	param := GetParamFromCtx(ctx)

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{
		ImageId:         param.ImageID,
		VulnEnable:      true,
		VirusEnable:     true,
		EnvEnable:       true,
		SoftwareEnable:  true,
		SensitiveEnable: true,
		WebshellEnable:  true,
		SubtaskEnable:   true,
		RegistryEnable:  true,
		ContainerEnable: true,
	})

	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(data.ImageBaseResponse.SensitiveFixSuggestion) > 0 {
		data.ImageBaseResponse.SensitiveFixSuggestion = data.ImageBaseResponse.SensitiveFixSuggestion[1:]
	}
	if len(data.ImageBaseResponse.VulnFixSuggestion) > 0 {
		data.ImageBaseResponse.VulnFixSuggestion = data.ImageBaseResponse.VulnFixSuggestion[1:]
	}

	response.JSONOK(ctx, response.WithItem(data.ImageBaseResponse))
}

func (s *ScanResultAPI) ImageIssueStatistic(ctx *gin.Context) {
	param := GetParamFromCtx(ctx)
	data, err := s.ImageSrv.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{
		ImageId:         param.ImageID,
		VulnEnable:      true,
		VirusEnable:     true,
		EnvEnable:       true,
		SoftwareEnable:  true,
		SensitiveEnable: true,
		WebshellEnable:  true,
		RegistryEnable:  true,
		ScanResultSearchParam: model.ScanResultSearchParam{
			ImageID:         param.ImageID,
			AbnormalSoft:    consts.TrueString,
			AbnormalLicense: consts.TrueString,
			AbnormalEnv:     consts.TrueString,
		},
		Filter: &model.Filter{Limit: 1, Offset: 0}, // 只记数
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItem(data.ToSecurityIssueOverview()))
}

func (s *ScanResultAPI) GetImageRiskInfo(ctx *gin.Context) {

	body := model.ImageListParam{}
	if err := ctx.BindJSON(&body); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, err))
		return
	}
	body.JustReturnImage = true
	body.Fields = []string{"id", "image_uuid"}

	filter := model.EmptyFilterForTotalQuery()

	images, _, err := s.ImageSrv.ListImageWithScanInfo(ctx, body, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	ans := make([]ImageRiskStatic, 0)

	for i := range images {
		data, err := s.ImageSrv.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{
			ImageId:         images[i].ID,
			VulnEnable:      true,
			VirusEnable:     true,
			EnvEnable:       true,
			SoftwareEnable:  true,
			SensitiveEnable: true,
			WebshellEnable:  true,
			RegistryEnable:  true,
			ScanResultSearchParam: model.ScanResultSearchParam{
				ImageID:         images[i].ID,
				AbnormalSoft:    consts.TrueString,
				AbnormalLicense: consts.TrueString,
				AbnormalEnv:     consts.TrueString,
			},
		})
		if err != nil {
			logging.Get().Err(err).Int64("ImageID", images[i].ID).Msg("GetImageCorrelateData")
			continue
		}
		if data.ImageBaseResponse.RiskScore == 0 || data.ImageBaseResponse.RiskScore == 100 {
			continue
		}

		risk := ImageRiskStatic{
			ImageBaseResponse: data.ImageBaseResponse,
			Issue:             data.ToSecurityIssueOverview(),
			SeverityOverview:  make([]model.SeverityGroup, 0),
		}

		for j := range data.Vuln {
			risk.SeverityOverview = addSeverityGroup(risk.SeverityOverview, data.Vuln[j].SeverityInt)
		}
		sort.Sort(SeverityGroups(risk.SeverityOverview))
		// 减少无用数据的返回
		risk.ImageBaseResponse.VulnFixSuggestion = nil
		risk.ImageBaseResponse.SensitiveFixSuggestion = nil
		ans = append(ans, risk)
	}
	response.JSONOK(ctx, response.WithItems(ans))
}
