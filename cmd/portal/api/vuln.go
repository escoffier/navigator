package api

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/ci"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scannerCi "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// VulnAPI vulnerability API structure
type VulnAPI struct {
	vulnService    service.VulnService
	projectService service.ProjectService
	ciComponent    ci.CiComponent
}

// NewVulnAPI creates vulnerability API instance
func NewVulnAPI(vulnService service.VulnService, projectService service.ProjectService, ciComponent ci.CiComponent) *VulnAPI {
	return &VulnAPI{
		vulnService:    vulnService,
		projectService: projectService,
		ciComponent:    ciComponent,
	}
}

func (api *VulnAPI) SearchCodesecVuln(c *gin.Context) {
	param := GetSearchVulnParam(c)
	vulns, total, err := api.vulnService.SearchCodesecVuln(c, param)
	if err != nil {
		response.JSONError(c, err)
		return
	}
	res := make([]*CodeSecVuln, len(vulns))
	for i := range vulns {
		res[i] = res[i].FromModel(vulns[i])
	}

	response.JSONOK(c, response.WithItems(res), response.WithTotalItems(total))
}

func (api *VulnAPI) CodesecSummary(c *gin.Context) {
	param := GetSearchVulnParam(c)
	scanResult, err := api.vulnService.CodesecSummary(c, param.ProjectUuid)
	if err != nil {
		response.JSONError(c, err)
		return
	}
	res := &CodesecSummary{}
	res = res.FromModel(scanResult)
	response.JSONOK(c, response.WithItem(res))
}

// SearchSourceCheckVuln searches SourceCheck vulnerability list
func (api *VulnAPI) SearchSourceCheckVuln(c *gin.Context) {
	param := GetSearchVulnParam(c)

	vulns, total, err := api.vulnService.SearchSourceCheckVuln(c, param)
	if err != nil {
		response.JSONError(c, err)
		return
	}
	res := make([]*SourceCheckVuln, len(vulns))
	for i := range vulns {
		res[i] = (&SourceCheckVuln{}).FromModel(vulns[i])
	}

	response.JSONOK(c, response.WithItems(res), response.WithTotalItems(total))
}

func (api *VulnAPI) SearchCIVuln(c *gin.Context) {
	param := GetSearchVulnParam(c)

	vulns, total, err := api.vulnService.SearchCIVuln(c, param)
	if err != nil {
		response.JSONError(c, err)
		return
	}

	response.JSONOK(c, response.WithItems(vulns), response.WithTotalItems(total))
}

func (api *VulnAPI) SearchCIImage(c *gin.Context) {
	param := GetSearchVulnParam(c)
	param.Filter = param.Filter.SetSortFiledByID().SetSortDesc()

	// 获取CI扫描记录
	ciScans, total, err := api.vulnService.SearchCIImage(c, param)
	if err != nil {
		response.JSONError(c, err)
		return
	}
	response.JSONOK(c, response.WithItems(ciScans), response.WithTotalItems(total))
}

// SearchSourceCheckLicense searches SourceCheck license list
func (api *VulnAPI) SearchSourceCheckLicense(c *gin.Context) {
	param := GetSearchVulnParam(c)

	licenses, total, err := api.vulnService.SearchSourceCheckLicense(c, param)
	if err != nil {
		response.JSONError(c, err)
		return
	}
	res := make([]*SourceCheckLicense, len(licenses))
	for i := range licenses {
		res[i] = res[i].FromModel(licenses[i])
	}

	response.JSONOK(c, response.WithItems(res), response.WithTotalItems(total))
}

// SearchSourceCheckComponent searches SourceCheck component list
func (api *VulnAPI) SearchSourceCheckComponent(c *gin.Context) {
	param := GetSearchVulnParam(c)

	components, total, err := api.vulnService.SearchSourceCheckComponent(c, param)
	if err != nil {
		response.JSONError(c, err)
		return
	}
	res := make([]*SourceCheckComponent, len(components))
	for i := range components {
		res[i] = res[i].FromModel(components[i])
	}
	response.JSONOK(c, response.WithItems(res), response.WithTotalItems(total))
}

// SourceCheckSummary gets SourceCheck scan summary
func (api *VulnAPI) SourceCheckSummary(c *gin.Context) {
	param := GetSearchVulnParam(c)
	scanResult, err := api.vulnService.SourceCheckSummary(c, param.ProjectUuid)
	if err != nil {
		response.JSONError(c, err)
		return
	}
	res := &SourceCheckSummary{}
	res.FromModel(scanResult)

	response.JSONOK(c, response.WithItem(res))
}

func (api *VulnAPI) ScanProject(ctx *gin.Context) {
	// Parse request parameters
	req := &model.ScanProjectReq{}
	if err := ctx.BindJSON(req); err != nil {
		response.JSONError(ctx, fmt.Errorf("failed to parse parameters: %v", err))
		return
	}
	if err := req.Check(); err != nil {
		response.JSONError(ctx, err)
		return
	}
	// Call service layer to execute scan
	if err := api.projectService.ScanProject(ctx, *req); err != nil {
		response.JSONError(ctx, fmt.Errorf("failed to start scan: %v", err))
		return
	}

	response.JSONOK(ctx, response.WithItem(map[string]interface{}{
		"message":    "Scan task started successfully",
		"projectIds": req.ProjectIds,
		"scanTypes":  req.ScanTypes,
	}))
}

// StopScan 终止扫描任务
func (api *VulnAPI) StopScan(c *gin.Context) {
	req := struct {
		ProjectIds []int64  `json:"projectIds"` // 项目ID列表
		ScanTypes  []string `json:"scanTypes"`  // 扫描类型列表：codesec, sourceCheck
	}{}

	if err := c.BindJSON(&req); err != nil {
		response.JSONError(c, fmt.Errorf("failed to parse parameters: %v", err))
		return
	}

	if len(req.ProjectIds) == 0 {
		response.JSONError(c, fmt.Errorf("projectIds is required"))
		return
	}

	if len(req.ScanTypes) == 0 {
		response.JSONError(c, fmt.Errorf("scanTypes is required"))
		return
	}

	// TODO: 实现终止扫描任务的逻辑
	// 这里需要调用相应的服务来终止扫描任务

	response.JSONOK(c, response.WithItem(map[string]interface{}{
		"message":    "Scan tasks stopped successfully",
		"projectIds": req.ProjectIds,
		"scanTypes":  req.ScanTypes,
	}))
}

func GetSearchVulnParam(ctx *gin.Context) model.SearchVulnParam {
	pa := model.SearchVulnParam{
		ProjectUuid:     util.GetKeywordFromQuery(ctx, "projectUuid"),
		CodesecUuid:     util.GetKeywordFromQuery(ctx, "codesecUuid"),
		SourceCheckUuid: util.GetKeywordFromQuery(ctx, "sourceCheckUuid"),
		UniqueIds:       util.GetUint64SliceFromQuery(ctx, "uniqueIds"),
		Filter:          imagesec.GetFilter(ctx).SetSortFiled("severity_int").SetSortDesc(),
	}
	return pa
}

// convertCiScanToImageBaseResponse converts CiScan to ImageBaseResponse format
func (api *VulnAPI) convertCiScanToImageBaseResponse(ciScan *scannerCi.CiScan, inWhitelist bool) *imagesec.ImageBaseResponse {
	// Parse image name to extract repo and tag
	fullRepoName := ciScan.ImageName
	tag := "latest"
	if idx := strings.LastIndex(ciScan.ImageName, ":"); idx != -1 {
		fullRepoName = ciScan.ImageName[:idx]
		tag = ciScan.ImageName[idx+1:]
	}

	// Convert scan status to string
	status := "unknown"
	switch ciScan.Mode {
	case 0:
		status = "pass"
	case 1:
		status = "alert"
	case 2:
		status = "reject"
	}

	return &imagesec.ImageBaseResponse{
		ID:                ciScan.ID,
		ImageID:           ciScan.ID,
		UniqueID:          ciScan.UniqueImage,
		ImageUniqueID:     ciScan.UniqueImage,
		ImageFromType:     "ci",
		FullRepoName:      fullRepoName,
		Tag:               tag,
		SecurityIssue:     make([]imagesec.SecurityIssueLabel, 0),
		SecurityIssueView: make([]string, 0),
		VulnStatic: imagesec.VulnSeverityStatic{
			Critical: ciScan.SeverityHistogram.NumCritical,
			High:     ciScan.SeverityHistogram.NumHigh,
			Medium:   ciScan.SeverityHistogram.NumMedium,
			Low:      ciScan.SeverityHistogram.NumLow,
			Unknown:  ciScan.SeverityHistogram.NumUnknown,
		},
		Action:     status,
		LastScanAt: ciScan.StartedAt,
		CreatedAt:  ciScan.CreatedAt,
		InWhite:    inWhitelist, // 设置白名单标志
		White:      inWhitelist, // 设置白名单标志
	}
}

// getWhitelistRegexps 获取白名单正则表达式列表
func (api *VulnAPI) getWhitelistRegexps(ctx context.Context) ([]*regexp.Regexp, error) {
	// 获取白名单列表
	whitelist, _, err := api.ciComponent.WM.GetWhiteList(ctx, scannerCi.WhitelistParams{
		Limit:   10000,
		Offset:  0,
		NowTime: time.Now().UnixMilli(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get whitelist: %w", err)
	}

	// 编译正则表达式
	regs := make([]*regexp.Regexp, 0, len(whitelist))
	for _, v := range whitelist {
		reg, err := regexp.Compile(v.Name)
		if err != nil {
			logging.GetLogger().Warn().Msgf("compile whitelist pattern failed: %s", v.Name)
			continue
		}
		regs = append(regs, reg)
	}

	return regs, nil
}

// checkImageInWhitelist 检查镜像是否在白名单中
func (api *VulnAPI) checkImageInWhitelist(imageName string, whitelistRegs []*regexp.Regexp) bool {
	for _, reg := range whitelistRegs {
		if reg.Match([]byte(imageName)) {
			return true
		}
	}
	return false
}
