package api

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	apimodel "gitlab.com/piccolo_su/vegeta/cmd/scanner/api/model"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanResultAPI struct {
	ScanResultSrv component.ScanResultInterface
	ImageSrv      component.ImageSrvInterface
	vulnSrv       component.VulnServiceInterface
}

func NewScanResultAPI(
	imageSrv component.ImageSrvInterface,
	scanResultSrv component.ScanResultInterface,
	vulnSrv component.VulnServiceInterface,
) *ScanResultAPI {
	return &ScanResultAPI{ImageSrv: imageSrv, ScanResultSrv: scanResultSrv, vulnSrv: vulnSrv}
}

func GetParamFromCtx(ctx *gin.Context) component.ScanResultSearchParam {
	param := component.ScanResultSearchParam{}
	if uniqueImage, err := strconv.ParseInt(ctx.Query("imageID"), 10, 64); err == nil {
		param.ImageID = uniqueImage
	}

	param.LayerDigest = ctx.Query("layerDigest")
	param.Keyword = ctx.Query("keyword")
	param.AbnormalSoft = ctx.Query("abnormalSoft")       // 查看异常软件
	param.AbnormalLicense = ctx.Query("abnormalLicense") // 查看不允许的开源协议
	param.AbnormalEnv = ctx.Query("abnormalEnv")         // 查看不允许的开源协议
	param.VulnSeverity = util.GetStringSliceFromQuery(ctx, "vulnSeverity")
	param.License = util.GetStringSliceFromQuery(ctx, "license")
	return param
}

func (s *ScanResultAPI) SearchVirus(ctx *gin.Context) {
	param := GetParamFromCtx(ctx)
	if err := param.Valid(); err != nil {
		response.JSONError(ctx, err)
		return
	}
	filter := model.GetFilter(ctx)
	res, cnt, err := s.ScanResultSrv.SearchVirus(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ScanResultAPI) SearchWebShell(ctx *gin.Context) {
	param := GetParamFromCtx(ctx)
	if err := param.Valid(); err != nil {
		response.JSONError(ctx, err)
		return
	}
	filter := model.GetFilter(ctx)
	res, cnt, err := s.ScanResultSrv.SearchWebShell(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ScanResultAPI) SearchSensitive(ctx *gin.Context) {
	param := GetParamFromCtx(ctx)
	if err := param.Valid(); err != nil {
		response.JSONError(ctx, err)
		return
	}
	filter := model.GetFilter(ctx)
	res, cnt, err := s.ScanResultSrv.SearchSensitive(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	ans := make([]apimodel.ImageSensitiveFile, 0)
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
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ScanResultAPI) SearchEnv(ctx *gin.Context) {
	param := GetParamFromCtx(ctx)
	if err := param.Valid(); err != nil {
		response.JSONError(ctx, err)
		return
	}
	filter := model.GetFilter(ctx)
	res, cnt, err := s.ScanResultSrv.SearchEnv(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ScanResultAPI) SearchSoftware(ctx *gin.Context) {
	param := GetParamFromCtx(ctx)
	if err := param.Valid(); err != nil {
		response.JSONError(ctx, err)
		return
	}
	filter := model.GetFilter(ctx)
	software, cnt, err := s.ScanResultSrv.SearchSoftware(ctx, param, model.EmptyFilterForTotalQuery())
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	// 再查漏洞
	preVulns, _, err := s.vulnSrv.SearchVulns(ctx, component.SearchVulnParam{ImageIds: []int64{param.ImageID}}, model.EmptyFilterForTotalQuery())
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
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ScanResultAPI) ImageBaseDetail(ctx *gin.Context) {
	param := GetParamFromCtx(ctx)
	if err := param.Valid(); err != nil {
		response.JSONError(ctx, err)
		return
	}
	res, err := s.ImageSrv.ImageBaseDetail(ctx, param.ImageID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(res.SensitiveFixSuggestion) > 0 {
		res.SensitiveFixSuggestion = res.SensitiveFixSuggestion[1:]
	}
	if len(res.VulnFixSuggestion) > 0 {
		res.VulnFixSuggestion = res.VulnFixSuggestion[1:]
	}

	response.JSONOK(ctx, response.WithItem(res))
}

func (s *ScanResultAPI) ImageIssueStatistic(ctx *gin.Context) {
	param := GetParamFromCtx(ctx)
	if err := param.Valid(); err != nil {
		response.JSONError(ctx, err)
		return
	}
	res, err := s.ImageSrv.ImageIssueStatistic(ctx, param.ImageID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItem(res))
}
