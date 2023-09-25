package api

import (
	"fmt"
	"math"
	"net/http"

	"github.com/gin-gonic/gin"

	imagescanSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type VulnAPISrv struct {
	VulnSrv imagescanSrv.ScanResultService
}

func NewVulnAPISrv(vulnSrv imagescanSrv.ScanResultService) *VulnAPISrv {
	return &VulnAPISrv{VulnSrv: vulnSrv}
}

func (vi *VulnAPISrv) SearchVuln(ctx *gin.Context) {
	vulnParam := GetSearchVulnParamFromCtx(ctx)

	// 默认只查在线镜像的漏洞
	vulnParam.OnlineImageVuln = consts.TrueString

	vulnParam.Filter = vulnParam.Filter.SetMaxLimit(consts.DefaultPerPage)

	vuln, cnt, err := vi.VulnSrv.SearchVuln(ctx, vulnParam)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(vuln),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(vulnParam.Filter.Limit),
		response.WithStartIndex(vulnParam.Filter.Offset))
}

func (vi *VulnAPISrv) Statistic(ctx *gin.Context) {
	res, err := vi.VulnSrv.VulnOverview(ctx, imagesecModel.VulnOverviewParam{OnlineImage: consts.TrueString})
	if err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
		return
	}
	response.JSONOK(ctx, response.WithItem(res), response.WithExportFileStatus(0))
}

type VulnPKG struct {
	PkgName          string                        `json:"pkgName"`
	PkgVersion       string                        `json:"pkgVersion"`
	Filepath         string                        `json:"filepath"`
	UniqueID         uint64                        `json:"uniqueID,string"`
	SeverityOverview []imagesecModel.SeverityGroup `json:"severityOverview"`
	Vulns            []*imagesecModel.VulnView     `json:"vulns"`
	// fixme 第张帅
	License      []string                   `json:"license"` // 软件的开源协议
	SortScore    int64                      `json:"sortScore"`
	PolicyDetect imagesecModel.PolicyDetect `json:"policyDetect"`
}

type ImageRiskStatic struct {
	ImageBaseResponse imagesecModel.ImageBaseResponse `json:"imageBaseResponse"`
	Issue             imagesecModel.SecurityStatistic `json:"issue"`
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
	Vulns            []*imagesecModel.VulnView     `json:"vulns"`
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
	Vulns            []*imagesecModel.VulnView     `json:"vulns"`
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
	Vulns            []*imagesecModel.VulnView     `json:"vulns"`
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
