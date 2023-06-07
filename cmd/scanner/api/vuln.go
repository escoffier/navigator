package api

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
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

	vulnKeyword := util.GetKeywordFromQuery(ctx, "keyword")
	imageID := util.GetInt64FromQuery(ctx, "imageID")

	if imageID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get imageID"))
		return
	}

	pkgName := util.GetKeywordFromQuery(ctx, "pkgName")
	pkgVersion := util.GetKeywordFromQuery(ctx, "pkgVersion")
	sources := util.GetKeywordFromQuery(ctx, "sources")
	canFixed := util.GetKeywordFromQuery(ctx, "canFixed")

	severityInt := make([]int64, 0)
	severity := strings.Split(ctx.Query("severity"), ",")
	for i := range severity {
		se := model.GetSeverityInt(severity[i])
		if se >= model.SeverityUnknownInt {
			severityInt = append(severityInt, int64(se))
		}
	}

	attackPath := util.GetStringSliceFromQuery(ctx, "attackPath") // 攻击途径
	class := util.GetStringSliceFromQuery(ctx, "class")           // 漏洞类型
	kernel := util.GetStringSliceFromQuery(ctx, "kernelVuln")     // 是否内核漏洞
	if util.ExistInStringSlice(kernel, consts.TrueString) && util.ExistInStringSlice(kernel, consts.FalseString) {
		kernel = nil
	}

	filter := model.GetFilter(ctx)
	param := model.SearchVulnParam{
		VulnKeyword: vulnKeyword,
		ImageIds:    []int64{imageID},
		PkgName:     pkgName,
		PkgVersion:  pkgVersion,
		Sources:     sources,
		CanFixed:    canFixed,
		SeverityInt: severityInt,
	}
	// 查层级
	layerDigest := ctx.Query("layerDigest")
	if layerDigest != "" {
		layers, _, err := s.VulnSrv.SearchLayerVuln(ctx, model.SearchScanLayerParam{
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
		param.UniqueVulns = util.DuplicateUint64Slice(uniqueVulns)

		/* 2.12之后应该使用这种方式查询,等扫描重构之后再使用
		param.LayerSearch = &model.LayerSearch{
			ImageID:     imageID,
			LayerDigest: layerDigest,
		}
		param.ImageIds = nil
		*/
	}
	vulns, _, err := s.VulnSrv.SearchVulns(ctx, param,
		model.EmptyFilterForTotalQuery().SetSortFiled("severity_int").SetSortDesc())
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	res := make([]VulnResponse, len(vulns))
	for i := range vulns {
		res[i] = convertVuln(vulns[i])
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

// 获取镜像漏洞-软件视角(仓库镜像)
func (s *VulnAPISrv) GetImageVulnPkg(ctx *gin.Context) {
	imageID := util.GetInt64FromQuery(ctx, "imageID")
	if imageID <= 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not get imageID")))
		return
	}

	pkgKeyword := util.GetKeywordFromQuery(ctx, "keyword")
	filter := model.GetFilter(ctx)

	param := model.SearchVulnParam{
		PkgKeyword: pkgKeyword,
		ImageIds:   []int64{imageID},
	}

	// 查层级
	layerDigest := util.GetKeywordFromQuery(ctx, "layerDigest")
	if layerDigest != "" {
		param.LayerSearch = &model.LayerSearch{
			ImageID:     imageID,
			LayerDigest: layerDigest,
		}
		param.ImageIds = nil
	}
	preVulns, _, err := s.VulnSrv.SearchVulns(ctx, param, model.EmptyFilterForTotalQuery())
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
				SeverityOverview: make([]imagesecModel.SeverityGroup, 0),
				Vulns:            make([]VulnResponse, 0),
				Target:           vulns[i].Target,
			}
		}
		sf := pkgMap[key]
		sf.SeverityOverview = imagesecModel.AddSeverityGroup(sf.SeverityOverview, vulns[i].SeverityInt)
		pkgMap[key] = sf
	}
	// 按层级排序一下,便于前端展示
	for _, v := range pkgMap {
		sort.Sort(imagesecModel.SeverityGroups(v.SeverityOverview))
	}
	res := make([]VulnPKG, 0)
	for _, vp := range pkgMap {
		vp.SortScore = vp.GetSortScore()
		vp.Vulns = make([]VulnResponse, 0)
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
func (s *VulnAPISrv) GetImageVulnLanguage(ctx *gin.Context) {

	imageID := util.GetInt64FromQuery(ctx, "imageID")
	if imageID <= 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not get imageID")))
		return
	}

	languageKeyword := util.GetKeywordFromQuery(ctx, "keyword")
	filter := model.GetFilter(ctx)

	param := model.SearchVulnParam{
		PkgKeyword: strings.ToLower(languageKeyword),
		ImageIds:   []int64{imageID},
	}

	// 查层级
	layerDigest := util.GetKeywordFromQuery(ctx, "layerDigest")
	if layerDigest != "" {
		param.LayerSearch = &model.LayerSearch{
			ImageID:     imageID,
			LayerDigest: layerDigest,
		}
		param.ImageIds = nil
	}

	vulns, _, err := s.VulnSrv.SearchVulns(ctx, param, model.EmptyFilterForTotalQuery())
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
				SeverityOverview: make([]imagesecModel.SeverityGroup, 0),
				Vulns:            make([]VulnResponse, 0),
			}
		}
		sf := languageMap[key]
		sf.Vulns = append(sf.Vulns, convertVuln(vulns[i]))
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
		vp.Vulns = make([]VulnResponse, 0)
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
func (s *VulnAPISrv) GetImageVulnGoBinary(ctx *gin.Context) {
	imageID := util.GetInt64FromQuery(ctx, "imageID")
	if imageID <= 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not get imageID")))
		return
	}

	targetKeyword := util.GetKeywordFromQuery(ctx, "keyword")
	filter := model.GetFilter(ctx)

	param := model.SearchVulnParam{
		PkgKeyword: targetKeyword,
		ImageIds:   []int64{imageID},
	}

	// 查层级
	layerDigest := util.GetKeywordFromQuery(ctx, "layerDigest")
	if layerDigest != "" {
		param.LayerSearch = &model.LayerSearch{
			ImageID:     imageID,
			LayerDigest: layerDigest,
		}
		param.ImageIds = nil
	}

	vulns, _, err := s.VulnSrv.SearchVulns(ctx, param, model.EmptyFilterForTotalQuery())
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
		sf.Vulns = append(sf.Vulns, convertVuln(vulns[i]))
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
		vp.Vulns = make([]VulnResponse, 0)
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
func (s *VulnAPISrv) GetImageVulnFrame(ctx *gin.Context) {

	imageID := util.GetInt64FromQuery(ctx, "imageID")
	if imageID <= 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not get imageID")))
		return
	}

	frameKeyword := util.GetKeywordFromQuery(ctx, "keyword")
	filter := model.GetFilter(ctx)

	param := model.SearchVulnParam{
		PkgKeyword: frameKeyword,
		ImageIds:   []int64{imageID},
	}

	// 查层级
	layerDigest := util.GetKeywordFromQuery(ctx, "layerDigest")
	if layerDigest != "" {
		param.LayerSearch = &model.LayerSearch{
			ImageID:     imageID,
			LayerDigest: layerDigest,
		}
		param.ImageIds = nil
	}
	vulns, _, err := s.VulnSrv.SearchVulns(ctx, param, model.EmptyFilterForTotalQuery())
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
		vp.Vulns = make([]VulnResponse, 0)
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

func (s *VulnAPISrv) SetVulnToRedis(ctx *gin.Context) {
	data := model.ImageRiskOverRedis{}
	if err := ctx.BindJSON(&data); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
		return
	}

	if err := s.VulnSrv.SetImageRiskToRedis(ctx, data); err != nil {
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
		UniqueID:    vuln.UniqueVuln,
		Language:    vuln.Language,
		PkgName:     vuln.PkgName,
		PkgVersion:  vuln.PkgVersion,
		Target:      vuln.Target,
		Frame:       vuln.Frame,
		CnnvdName:   vuln.CnnvdName,
		Class:       vuln.Class,
		KernelVuln:  util.ExistBit1(vuln.Flag, model.VulnFlagKernel),
		Attr:        vuln.Attr,
	}
	if vuln.Attr != nil {
		res.AttackPath = vuln.Attr["AV"]
	}
	if util.ExistBit1(vuln.Flag, model.VulnFlagClassOSPkg) || vuln.Class == report.ClassOSPkg {
		res.Class = report.ClassOSPkg
	} else if util.ExistBit1(vuln.Flag, model.VulnFlagClassLangPkg) || vuln.Class == report.ClassLangPkg {
		res.Class = report.ClassLangPkg
	}
	return res
}

func convertNodeVulnView(vuln *imagesecModel.VulnView) VulnResponse {
	if vuln == nil {
		return VulnResponse{}
	}
	res := VulnResponse{
		ID:             vuln.ID,
		Name:           vuln.Name,
		SeverityInt:    vuln.SeverityInt,
		Severity:       vuln.Severity,
		FixedBy:        vuln.FixedVersion,
		UniqueID:       vuln.UniqueID,
		PkgUniqueID:    vuln.PkgUniqueID,
		Language:       vuln.Language,
		PkgName:        vuln.PkgName,
		PkgVersion:     vuln.PkgVersion,
		Target:         vuln.Target,
		Frame:          vuln.Frame,
		CnnvdName:      vuln.CnnvdName,
		Class:          vuln.Class,
		ClassView:      vuln.ClassView,
		KernelVuln:     vuln.KernelVuln,
		AttackPath:     vuln.AttackPath,
		AttackPathView: vuln.AttackPathView,
		PolicyDetect:   vuln.PolicyDetect,
	}
	return res
}

type VulnResponse struct {
	ID             int64                      `json:"id"`
	Name           string                     `json:"name"`      // 形如CVE-2021-28831
	CnnvdName      string                     `json:"cnnvdName"` // CNNVD
	SeverityInt    int64                      `json:"severityInt"`
	Severity       string                     `json:"severity"`
	PkgName        string                     `json:"pkgName"`    // 软件包来源
	PkgVersion     string                     `json:"pkgVersion"` // 软件包版本
	FixedBy        string                     `json:"fixedBy"`    // 修复建议
	UniqueID       uint64                     `json:"uniqueID,string"`
	PkgUniqueID    uint64                     `json:"pkgUniqueID,string"`
	Language       string                     `json:"language"`       // 把编程语言
	AttackPath     string                     `json:"attackPath"`     // 攻击路径
	AttackPathView string                     `json:"attackPathView"` // 攻击路径
	Target         string                     `json:"target"`         // 制品路径
	Class          string                     `json:"class"`          // 代表是系统包还是语言包 os-pkgs
	ClassView      string                     `json:"classView"`
	Frame          string                     `json:"frame"`      // 开发框架筛选
	KernelVuln     bool                       `json:"kernelVuln"` // 是否是内核漏洞
	Attr           map[string]string          `json:"attr"`
	PolicyDetect   imagesecModel.PolicyDetect `json:"policyDetect"` // 对各个策略的检测结果
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
	PkgName          string                        `json:"pkgName"`
	PkgVersion       string                        `json:"pkgVersion"`
	UniqueID         uint64                        `json:"uniqueID,string"`
	SeverityOverview []imagesecModel.SeverityGroup `json:"severityOverview"`
	Vulns            []VulnResponse                `json:"vulns"`
	License          []string                      `json:"license"` // 软件的开源协议
	Target           string                        `json:"target"`
	SortScore        int64                         `json:"sortScore"`
	PolicyDetect     imagesecModel.PolicyDetect    `json:"policyDetect"`
}

type ImageRiskStatic struct {
	ImageBaseResponse imagesecModel.ImageBaseResponse `json:"imageBaseResponse"`
	Issue             model.SecurityIssueOverview     `json:"issue"`
	SeverityOverview  []imagesecModel.SeverityGroup   `json:"severityOverview"`
}

// 为了排序方便，一般情况下，单个镜像单个级别的漏洞不会超过1000个
func (vp VulnPKG) GetSortScore() int64 {
	var score int64
	for i := range vp.SeverityOverview {
		if vp.SeverityOverview[i].SeverityInt <= 0 {
			continue
		}
		level := int64(math.Pow10((int(vp.SeverityOverview[i].SeverityInt - 1)) * 3))
		score += level * vp.SeverityOverview[i].Count
	}
	return score
}

func (vp VulnPKG) GenUniqueVuln() uint64 {
	key := fmt.Sprintf(consts.UniqueSoftwareFamat, vp.PkgName, vp.PkgVersion)
	uid := util.GenerateUUID64(key)
	return uid
}

type VulnPKGs []VulnPKG

func (vf VulnPKGs) Len() int {
	return len(vf)
}

func (vf VulnPKGs) Less(i, j int) bool {
	return vf[i].SortScore > vf[j].SortScore
}

func (vf VulnPKGs) Swap(i, j int) {
	vf[i], vf[j] = vf[j], vf[i]
}

type VulnLanguage struct {
	LanguageName     string                        `json:"languageName"`
	LanguagePath     string                        `json:"languagePath"`
	SeverityOverview []imagesecModel.SeverityGroup `json:"severityOverview"`
	Vulns            []VulnResponse                `json:"vulns"`
	Target           string                        `json:"target"`
	SortScore        int64                         `json:"sortScore"`
}

func (vp VulnLanguage) GetSortScore() int64 {
	var score int64
	for i := range vp.SeverityOverview {
		if vp.SeverityOverview[i].SeverityInt <= 0 {
			continue
		}
		level := int64(math.Pow10((int(vp.SeverityOverview[i].SeverityInt - 1)) * 3))
		score += level * vp.SeverityOverview[i].Count
	}
	return score
}

type VulnLanguages []*VulnLanguage

func (vf VulnLanguages) Len() int {
	return len(vf)
}

func (vf VulnLanguages) Less(i, j int) bool {
	return vf[i].SortScore > vf[j].SortScore
}

func (vf VulnLanguages) Swap(i, j int) {
	vf[i], vf[j] = vf[j], vf[i]
}

type VulnGobinary struct {
	GoName           string                        `json:"goName"`
	GoPath           string                        `json:"goPath"`
	SeverityOverview []imagesecModel.SeverityGroup `json:"severityOverview"`
	Vulns            []VulnResponse                `json:"vulns"`
	SortScore        int64                         `json:"sortScore"`
}

func (vp VulnGobinary) GetSortScore() int64 {
	var score int64
	for i := range vp.SeverityOverview {
		if vp.SeverityOverview[i].SeverityInt <= 0 {
			continue
		}
		level := int64(math.Pow10((int(vp.SeverityOverview[i].SeverityInt - 1)) * 3))
		score += level * vp.SeverityOverview[i].Count
	}
	return score
}

type VulnGobinaries []*VulnGobinary

func (vf VulnGobinaries) Len() int {
	return len(vf)
}

func (vf VulnGobinaries) Less(i, j int) bool {
	return vf[i].SortScore > vf[j].SortScore
}

func (vf VulnGobinaries) Swap(i, j int) {
	vf[i], vf[j] = vf[j], vf[i]
}

type VulnFrame struct {
	Frame            string                        `json:"frame"`
	SeverityOverview []imagesecModel.SeverityGroup `json:"severityOverview"`
	Vulns            []VulnResponse                `json:"vulns"`
	SortScore        int64                         `json:"sortScore"`
}

func (vp VulnFrame) GetSortScore() int64 {
	var score int64
	for i := range vp.SeverityOverview {
		if vp.SeverityOverview[i].SeverityInt <= 0 {
			continue
		}
		level := int64(math.Pow10((int(vp.SeverityOverview[i].SeverityInt - 1)) * 3))
		score += level * vp.SeverityOverview[i].Count
	}
	return score
}

type VulnFrames []*VulnFrame

func (vf VulnFrames) Len() int {
	return len(vf)
}

func (vf VulnFrames) Less(i, j int) bool {
	return vf[i].SortScore > vf[j].SortScore
}

func (vf VulnFrames) Swap(i, j int) {
	vf[i], vf[j] = vf[j], vf[i]
}
