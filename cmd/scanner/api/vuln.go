package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type VulnAPISrv struct {
	VulnSrv component.VulnServiceInterface
}

func NewVulnAPISrv(vulnSrv component.VulnServiceInterface) *VulnAPISrv {
	return &VulnAPISrv{VulnSrv: vulnSrv}
}

// 获取镜像漏洞-漏洞视角
func (s *VulnAPISrv) GetImageVulns(ctx *gin.Context) {
	vulnKeyword := ctx.Query("keyword")
	imageID, err := strconv.ParseInt(ctx.Query("imageID"), 10, 64)
	if err != nil || imageID <= 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not get imageID")))
		return
	}
	pkgName := ctx.Query("pkgName")
	pkgVersion := ctx.Query("pkgVersion")
	sources := ctx.Query("sources")
	canFixed := util.GetYesOrNoFromQuery(ctx, "canFixed") // 前端会传y,n，后端做处理

	severityInt := make([]int64, 0)
	severity := strings.Split(ctx.Query("severity"), ",")
	for i := range severity {
		se := model.GetSeverityInt(severity[i])
		if se >= model.SeverityUnknownInt {
			severityInt = append(severityInt, int64(se))
		}
	}

	filter := model.GetFilter(ctx)
	if filter.SortFiled == "" {
		filter.SortFiled = "severity_int"
	}
	if filter.SortBy == "" {
		filter.SortBy = consts.SortByDesc
	}
	param := component.SearchVulnParam{
		VulnKeyword: vulnKeyword,
		ImageIds:    []int64{imageID},
		PkgName:     pkgName,
		PkgVersion:  pkgVersion,
		Sources:     sources,
		CanFixed:    canFixed,
		SeverityInt: severityInt,
	}
	layerDigest := ctx.Query("layerDigest")
	if layerDigest != "" {
		layers, _, err := s.VulnSrv.SearchLayerVuln(ctx, component.SearchScanLayerParam{
			ImageID:      imageID,
			LayerDigests: []string{layerDigest},
		}, nil)
		if err != nil {
			response.JSONError(ctx, err)
			return
		}
		uniqueVulns := make([]uint64, 0)
		for i := range layers {
			uniqueVulns = append(uniqueVulns, layers[i].VulnInfo...)
		}
		param.UniqueVulns = util.DeDuplicationUint64Slice(uniqueVulns)
	}

	vulns, cnt, err := s.VulnSrv.SearchVulns(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	res := make([]VulnResponse, len(vulns))
	for i := range vulns {
		res[i] = convertVuln(vulns[i])
	}

	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(int64(cnt)),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// 获取镜像漏洞-软件视角
func (s *VulnAPISrv) GetImageVulnPkg(ctx *gin.Context) {
	imageID, err := strconv.ParseInt(ctx.Query("imageID"), 10, 64)
	if err != nil || imageID <= 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not get imageID")))
		return
	}
	pkgKeyword := ctx.Query("keyword")
	filter := model.GetFilter(ctx)
	if filter.SortFiled == "" {
		filter.SortFiled = "severity_int"
	}
	if filter.SortBy == "" {
		filter.SortBy = consts.SortByDesc
	}
	param := component.SearchVulnParam{
		PkgKeyword: pkgKeyword,
		ImageIds:   []int64{imageID},
	}

	layerDigest := ctx.Query("layerDigest")
	if layerDigest != "" {
		layers, _, err := s.VulnSrv.SearchLayerVuln(ctx, component.SearchScanLayerParam{
			ImageID:      imageID,
			LayerDigests: []string{layerDigest},
		}, nil)
		if err != nil {
			response.JSONError(ctx, err)
			return
		}
		uniqueVulns := make([]uint64, 0)
		for i := range layers {
			uniqueVulns = append(uniqueVulns, layers[i].VulnInfo...)
		}
		param.UniqueVulns = uniqueVulns
	}

	preVulns, _, err := s.VulnSrv.SearchVulns(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	vulns := make([]VulnResponse, 0)
	for i := range preVulns {
		vulns = append(vulns, convertVuln(preVulns[i]))
	}

	// 整理数据
	pkgMap := make(map[string]VulnPKG)
	for i := range vulns {
		key := fmt.Sprintf("%s|%s", vulns[i].PkgName, vulns[i].PkgVersion)
		if _, ok := pkgMap[key]; !ok {
			pkgMap[key] = VulnPKG{
				PkgName:          vulns[i].PkgName,
				PkgVersion:       vulns[i].PkgVersion,
				SeverityOverview: make([]model.SeverityGroup, 0),
				Vulns:            make([]VulnResponse, 0),
				Target:           vulns[i].Target,
			}
		}
		sf := pkgMap[key]
		sf.Vulns = vulns
		sf.SeverityOverview = addSeverityGroup(sf.SeverityOverview, vulns[i].SeverityInt)
		pkgMap[key] = sf
	}
	// 按层级排序一下,便于前端展示
	for _, v := range pkgMap {
		sort.Sort(SeverityGroups(v.SeverityOverview))
		sort.Sort(VulnLists(v.Vulns))
	}
	res := make([]VulnPKG, 0)
	for _, vp := range pkgMap {
		res = append(res, vp)
	}
	sort.Sort(VulnPKGs(res))
	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(int64(len(res))),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// 获取镜像漏洞-编程语言
func (s *VulnAPISrv) GetImageVulnLanguage(ctx *gin.Context) {
	imageID, err := strconv.ParseInt(ctx.Query("imageID"), 10, 64)
	if err != nil || imageID <= 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not get imageID")))
		return
	}
	languageKeyword := ctx.Query("keyword")

	filter := model.GetFilter(ctx)
	if filter.SortFiled == "" {
		filter.SortFiled = "severity_int"
	}
	if filter.SortBy == "" {
		filter.SortBy = consts.SortByDesc
	}
	param := component.SearchVulnParam{
		LanguageKeyword: strings.ToLower(languageKeyword),
		ImageIds:        []int64{imageID},
	}

	layerDigest := ctx.Query("layerDigest")
	if layerDigest != "" {
		layers, _, err := s.VulnSrv.SearchLayerVuln(ctx, component.SearchScanLayerParam{
			ImageID:      imageID,
			LayerDigests: []string{layerDigest},
		}, nil)
		if err != nil {
			response.JSONError(ctx, err)
			return
		}
		uniqueVulns := make([]uint64, 0)
		for i := range layers {
			uniqueVulns = append(uniqueVulns, layers[i].VulnInfo...)
		}
		param.UniqueVulns = uniqueVulns
	}

	vulns, _, err := s.VulnSrv.SearchVulns(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	// 整理数据
	languageMap := make(map[string]*VulnLanguage)
	for i := range vulns {
		if vulns[i].Language == "" {
			continue
		}

		key := fmt.Sprintf("%s|%s", vulns[i].Language, vulns[i].Target)
		if _, ok := languageMap[key]; !ok {
			languageMap[key] = &VulnLanguage{
				LanguageName:     vulns[i].Language,
				LanguagePath:     vulns[i].Target,
				SeverityOverview: make([]model.SeverityGroup, 0),
				Vulns:            make([]VulnResponse, 0),
			}
		}
		sf := languageMap[key]
		sf.Vulns = append(sf.Vulns, convertVuln(vulns[i]))
		sf.SeverityOverview = addSeverityGroup(sf.SeverityOverview, vulns[i].SeverityInt)
		languageMap[key] = sf
	}
	// 按层级排序一下,便于前端展示
	for _, v := range languageMap {
		sort.Sort(SeverityGroups(v.SeverityOverview))
		sort.Sort(VulnLists(v.Vulns))
	}
	res := make([]*VulnLanguage, 0)
	for _, vp := range languageMap {
		res = append(res, vp)
	}
	sort.Sort(VulnLanguages(res))

	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(int64(len(res))),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// 获取镜像漏洞-Gobinary视角
func (s *VulnAPISrv) GetImageVulnGoBinary(ctx *gin.Context) {
	imageID, err := strconv.ParseInt(ctx.Query("imageID"), 10, 64)
	if err != nil || imageID <= 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not get imageID")))
		return
	}
	targetKeyword := ctx.Query("keyword")

	filter := model.GetFilter(ctx)
	if filter.SortFiled == "" {
		filter.SortFiled = "severity_int"
	}
	if filter.SortBy == "" {
		filter.SortBy = consts.SortByDesc
	}
	param := component.SearchVulnParam{
		TargetKeyword: targetKeyword,
		ImageIds:      []int64{imageID},
	}
	layerDigest := ctx.Query("layerDigest")
	if layerDigest != "" {
		layers, _, err := s.VulnSrv.SearchLayerVuln(ctx, component.SearchScanLayerParam{
			ImageID:      imageID,
			LayerDigests: []string{layerDigest},
		}, nil)
		if err != nil {
			response.JSONError(ctx, err)
			return
		}
		uniqueVulns := make([]uint64, 0)
		for i := range layers {
			uniqueVulns = append(uniqueVulns, layers[i].VulnInfo...)
		}
		param.UniqueVulns = uniqueVulns
	}
	vulns, _, err := s.VulnSrv.SearchVulns(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	// 整理数据
	gobinaryMap := make(map[string]*VulnGobinary)
	for i := range vulns {
		if vulns[i].Language != consts.VulnLanguageGO {
			continue
		}

		index := strings.LastIndex(vulns[i].Target, "/")

		vulnGO := VulnGobinary{
			SeverityOverview: make([]model.SeverityGroup, 0),
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
		sf.Vulns = append(sf.Vulns, convertVuln(vulns[i]))
		sf.SeverityOverview = addSeverityGroup(sf.SeverityOverview, vulns[i].SeverityInt)
		gobinaryMap[key] = sf
	}
	// 按层级排序一下,便于前端展示
	for _, v := range gobinaryMap {
		sort.Sort(SeverityGroups(v.SeverityOverview))
		sort.Sort(VulnLists(v.Vulns))
	}
	res := make([]*VulnGobinary, 0)
	for _, vp := range gobinaryMap {
		res = append(res, vp)
	}
	sort.Sort(VulnGobinaries(res))
	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(int64(len(res))),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// 获取镜像漏洞-开发框架视角
func (s *VulnAPISrv) GetImageVulnFrame(ctx *gin.Context) {
	imageID, err := strconv.ParseInt(ctx.Query("imageID"), 10, 64)
	if err != nil || imageID <= 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not get imageID")))
		return
	}
	frameKeyword := ctx.Query("keyword")

	filter := model.GetFilter(ctx)
	if filter.SortFiled == "" {
		filter.SortFiled = "severity_int"
	}
	if filter.SortBy == "" {
		filter.SortBy = consts.SortByDesc
	}

	param := component.SearchVulnParam{
		FrameKeyword: frameKeyword,
		ImageIds:     []int64{imageID},
	}

	layerDigest := ctx.Query("layerDigest")
	if layerDigest != "" {
		layers, _, err := s.VulnSrv.SearchLayerVuln(ctx, component.SearchScanLayerParam{
			ImageID:      imageID,
			LayerDigests: []string{layerDigest},
		}, nil)
		if err != nil {
			response.JSONError(ctx, err)
			return
		}
		uniqueVulns := make([]uint64, 0)
		for i := range layers {
			uniqueVulns = append(uniqueVulns, layers[i].VulnInfo...)
		}
		param.UniqueVulns = uniqueVulns
	}

	vulns, _, err := s.VulnSrv.SearchVulns(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
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
		sf.Vulns = append(sf.Vulns, convertVuln(vulns[i]))
		sf.SeverityOverview = addSeverityGroup(sf.SeverityOverview, vulns[i].SeverityInt)
		frameMap[vulns[i].Frame] = sf
	}
	// 按层级排序一下,便于前端展示
	for _, v := range frameMap {
		sort.Sort(SeverityGroups(v.SeverityOverview))
		sort.Sort(VulnLists(v.Vulns))
	}
	res := make([]*VulnFrame, 0)
	for _, vp := range frameMap {
		res = append(res, vp)
	}
	sort.Sort(VulnFrames(res))

	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(int64(len(res))),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (v *VulnAPISrv) SetVulnToRedis(ctx *gin.Context) {
	data := model.ImageRiskOverRedis{}
	if err := ctx.BindJSON(&data); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
		return
	}

	if err := v.VulnSrv.SetImageRiskToRedis(ctx, data); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
		return
	}

	response.JSONOK(ctx)
}

func convertVuln(vuln *model.Vuln) VulnResponse {
	if vuln == nil {
		return VulnResponse{}
	}
	res := VulnResponse{
		ID:          vuln.ID,
		Name:        vuln.Name,
		SeverityInt: vuln.SeverityInt,
		Severity:    vuln.Severity,
		FixedBy:     vuln.FixedBy,
		UniqueVuln:  vuln.UniqueVuln,
		Language:    vuln.Language,
		PkgName:     vuln.PkgName,
		PkgVersion:  vuln.PkgVersion,
		Target:      vuln.Target,
		Class:       vuln.Class,
		Frame:       vuln.Frame,
	}
	if vuln.Attr != nil {
		res.AttackPath = vuln.Attr["AV"]
	}
	return res
}

type VulnResponse struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"` // 形如CVE-2021-28831
	SeverityInt int    `json:"severityInt"`
	Severity    string `json:"severity"`
	PkgName     string `json:"pkgName"`    // 软件包来源
	PkgVersion  string `json:"pkgVersion"` // 软件包版本
	FixedBy     string `json:"fixedBy"`    // 修复建议
	UniqueVuln  uint64 `json:"uniqueVuln,string"`
	Language    string `json:"language"`   // 把编程语言
	AttackPath  string `json:"attackPath"` // 攻击路径
	Target      string ` json:"target"`    // 制品路径
	Class       string `json:"class"`      // 代表是系统包还是语言包 os-pkgs
	Frame       string `json:"frame"`      // 开发框架筛选
}

type VulnLists []VulnResponse

func (vl VulnLists) Len() int {
	return len(vl)
}

func (vl VulnLists) Less(i, j int) bool {
	return vl[i].SeverityInt >= vl[j].SeverityInt
}

func (vl VulnLists) Swap(i, j int) {
	vl[i], vl[j] = vl[j], vl[i]
}

type VulnPKG struct {
	PkgName          string                `json:"pkgName"`
	PkgVersion       string                `json:"pkgVersion"`
	SeverityOverview []model.SeverityGroup `json:"severityOverview"`
	Vulns            []VulnResponse        `json:"vulns"`
	Target           string                `json:"target"`
}

type VulnPKGs []VulnPKG

func (vf VulnPKGs) Len() int {
	return len(vf)
}

func (vf VulnPKGs) Less(i, j int) bool {
	if len(vf[i].SeverityOverview) > 0 && len(vf[j].SeverityOverview) == 0 {
		return true
	} else if len(vf[i].SeverityOverview) == 0 && len(vf[j].SeverityOverview) > 0 {
		return false
	} else {
		for k := range vf[i].SeverityOverview {
			if len(vf[j].SeverityOverview)-1 < k {
				return true
			} else if vf[i].SeverityOverview[k].SeverityInt > vf[j].SeverityOverview[k].SeverityInt {
				return true
			} else if vf[i].SeverityOverview[k].SeverityInt < vf[j].SeverityOverview[k].SeverityInt {
				return false
			} else if vf[i].SeverityOverview[k].SeverityInt == vf[j].SeverityOverview[k].SeverityInt {
				return vf[i].SeverityOverview[k].Count >= vf[j].SeverityOverview[k].Count
			}
		}
		if len(vf[i].SeverityOverview) < len(vf[j].SeverityOverview) {
			return false
		}
	}
	return true
}

func (vf VulnPKGs) Swap(i, j int) {
	vf[i], vf[j] = vf[j], vf[i]
}

type VulnLanguage struct {
	LanguageName     string                `json:"languageName"`
	LanguagePath     string                `json:"languagePath"`
	SeverityOverview []model.SeverityGroup `json:"severityOverview"`
	Vulns            []VulnResponse        `json:"vulns"`
	Target           string                `json:"target"`
}

type VulnLanguages []*VulnLanguage

func (vf VulnLanguages) Len() int {
	return len(vf)
}

func (vf VulnLanguages) Less(i, j int) bool {
	if len(vf[i].SeverityOverview) > 0 && len(vf[j].SeverityOverview) == 0 {
		return true
	} else if len(vf[i].SeverityOverview) == 0 && len(vf[j].SeverityOverview) > 0 {
		return false
	} else {
		for k := range vf[i].SeverityOverview {
			if len(vf[j].SeverityOverview)-1 < k {
				return true
			} else if vf[i].SeverityOverview[k].SeverityInt > vf[j].SeverityOverview[k].SeverityInt {
				return true
			} else if vf[i].SeverityOverview[k].SeverityInt < vf[j].SeverityOverview[k].SeverityInt {
				return false
			} else if vf[i].SeverityOverview[k].SeverityInt == vf[j].SeverityOverview[k].SeverityInt {
				return vf[i].SeverityOverview[k].Count >= vf[j].SeverityOverview[k].Count
			}
		}
		if len(vf[i].SeverityOverview) < len(vf[j].SeverityOverview) {
			return false
		}
	}
	return true
}

func (vf VulnLanguages) Swap(i, j int) {
	vf[i], vf[j] = vf[j], vf[i]
}

type VulnGobinary struct {
	GoName           string                `json:"goName"`
	GoPath           string                `json:"goPath"`
	SeverityOverview []model.SeverityGroup `json:"severityOverview"`
	Vulns            []VulnResponse        `json:"vulns"`
}

type VulnGobinaries []*VulnGobinary

func (vf VulnGobinaries) Len() int {
	return len(vf)
}

func (vf VulnGobinaries) Less(i, j int) bool {
	if len(vf[i].SeverityOverview) > 0 && len(vf[j].SeverityOverview) == 0 {
		return true
	} else if len(vf[i].SeverityOverview) == 0 && len(vf[j].SeverityOverview) > 0 {
		return false
	} else {
		for k := range vf[i].SeverityOverview {
			if len(vf[j].SeverityOverview)-1 < k {
				return true
			} else if vf[i].SeverityOverview[k].SeverityInt > vf[j].SeverityOverview[k].SeverityInt {
				return true
			} else if vf[i].SeverityOverview[k].SeverityInt < vf[j].SeverityOverview[k].SeverityInt {
				return false
			} else if vf[i].SeverityOverview[k].SeverityInt == vf[j].SeverityOverview[k].SeverityInt {
				return vf[i].SeverityOverview[k].Count >= vf[j].SeverityOverview[k].Count
			}
		}
		if len(vf[i].SeverityOverview) < len(vf[j].SeverityOverview) {
			return false
		}
	}
	return true
}

func (vf VulnGobinaries) Swap(i, j int) {
	vf[i], vf[j] = vf[j], vf[i]
}

type VulnFrame struct {
	Frame            string                `json:"frame"`
	SeverityOverview []model.SeverityGroup `json:"severityOverview"`
	Vulns            []VulnResponse        `json:"vulns"`
}

type VulnFrames []*VulnFrame

func (vf VulnFrames) Len() int {
	return len(vf)
}

func (vf VulnFrames) Less(i, j int) bool {
	if len(vf[i].SeverityOverview) > 0 && len(vf[j].SeverityOverview) == 0 {
		return true
	} else if len(vf[i].SeverityOverview) == 0 && len(vf[j].SeverityOverview) > 0 {
		return false
	} else {
		for k := range vf[i].SeverityOverview {
			if len(vf[j].SeverityOverview)-1 < k {
				return true
			} else if vf[i].SeverityOverview[k].SeverityInt > vf[j].SeverityOverview[k].SeverityInt {
				return true
			} else if vf[i].SeverityOverview[k].SeverityInt < vf[j].SeverityOverview[k].SeverityInt {
				return false
			} else if vf[i].SeverityOverview[k].SeverityInt == vf[j].SeverityOverview[k].SeverityInt {
				return vf[i].SeverityOverview[k].Count >= vf[j].SeverityOverview[k].Count
			}
		}
		if len(vf[i].SeverityOverview) < len(vf[j].SeverityOverview) {
			return false
		}
	}
	return true
}

func (vf VulnFrames) Swap(i, j int) {
	vf[i], vf[j] = vf[j], vf[i]
}

type SeverityGroups []model.SeverityGroup

func (sgs SeverityGroups) Len() int {
	return len(sgs)
}

func (sgs SeverityGroups) Less(i, j int) bool {
	if sgs[i].SeverityInt > sgs[j].SeverityInt {
		return true
	} else if sgs[i].SeverityInt < sgs[j].SeverityInt {
		return false
	} else if sgs[i].SeverityInt == sgs[j].SeverityInt {
		return sgs[i].Count > sgs[j].Count
	}
	return true
}

func (sgs SeverityGroups) Swap(i, j int) {
	sgs[i], sgs[j] = sgs[j], sgs[i]
}

func addSeverityGroup(sgs []model.SeverityGroup, severityInt int) []model.SeverityGroup {
	add := false
	for i := range sgs {
		if sgs[i].SeverityInt == severityInt {
			add = true
			sgs[i].Count++
		}
	}
	if !add {
		sgs = append(sgs, model.SeverityGroup{
			SeverityInt: severityInt,
			Count:       1,
			Severity:    model.GetSeverity(severityInt),
		})
	}
	return sgs
}
