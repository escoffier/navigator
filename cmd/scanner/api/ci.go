package api

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/ci"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scanner_ci "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type CiApiSrv struct {
	Component ci.CiComponent
}

func NewCiSrv(c ci.CiComponent) *CiApiSrv {
	return &CiApiSrv{Component: c}
}

func (c *CiApiSrv) GetImageTop5(ctx *gin.Context) {
	res, err := c.Component.IM.GetImageTop5(ctx)
	if err != nil {
		logging.Get().Err(err).Msgf("GetImageTop5 error ")
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res))
}

func (c *CiApiSrv) GetImageOverView(ctx *gin.Context) {
	interval := c.GetParseInt(ctx, "interval")
	res, err := c.Component.IM.GetImageOverView(ctx, int(interval))
	if err != nil {
		logging.Get().Err(err).Msgf("GetImageOverView error ")
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res))
}

func (c *CiApiSrv) GetSensitives(ctx *gin.Context) {
	limit := c.GetParseInt(ctx, "limit")
	offset := c.GetParseInt(ctx, "offset")
	imageID := c.GetParseInt(ctx, "image_id")
	search := ctx.Query("keyword")
	matchPolicy := ctx.Query("match_policy")
	match := false
	if matchPolicy == "true" {
		match = true
	}
	res, cnt, err := c.Component.IM.GetSensitives(ctx, int(limit), int(offset), imageID, search, match)
	if err != nil {
		logging.Get().Err(err).Msgf("get sensitive error")
		response.JSONError(ctx, fmt.Errorf("get sensitive error"))
		return
	}
	response.JSONOK(ctx, response.WithItems(res), response.WithTotalItems(cnt))
}

func (c *CiApiSrv) GetImageDetail(ctx *gin.Context) {
	id := c.GetParseInt(ctx, "id")
	res, err := c.Component.IM.GetImageDetail(ctx, id)
	if err != nil {
		logging.Get().Err(err).Msgf("GetImageDetail error ")
		response.JSONError(ctx, err)
		return
	}
	inWhitelist, err := c.Component.WM.MatchWhiteList(ctx, res.ImageName)
	if err != nil {
		logging.Get().Err(err).Msgf("GetImageDetail error ")
		response.JSONError(ctx, fmt.Errorf("get whitelist error"))
	}
	res.InWhitelist = inWhitelist
	response.JSONOK(ctx, response.WithItem(res))
}

func (c *CiApiSrv) GetImageList(ctx *gin.Context) {
	image := ctx.Query("image")
	kind := ctx.Query("kind")
	taskName := ctx.Query("taskname")
	status := ctx.Query("status")
	startTime := c.GetParseInt(ctx, "start_time")
	endTime := c.GetParseInt(ctx, "end_time")
	limit := c.GetParseInt(ctx, "limit")
	offset := c.GetParseInt(ctx, "offset")
	kindAttribute := ctx.Query("kind_attribute")
	// statusStr := strings.Split(status, ",")
	// var params scanner_ci.ImageParams
	// for _, v := range statusStr {
	// 	tmp, err := strconv.ParseInt(v, 10, 64)
	// 	if err != nil {
	// 		params.Status = append(params.Status, int(tmp))
	// 	}
	// }
	params := scanner_ci.ImageParams{
		Image:         image,
		Kind:          kind,
		TaskName:      taskName,
		Status:        status,
		StartTime:     startTime,
		EndTime:       endTime,
		Limit:         int(limit),
		Offset:        int(offset),
		KindAttribute: kindAttribute,
	}
	res, cnt, err := c.Component.IM.GetImageList(ctx, params)
	if err != nil {
		logging.Get().Err(err).Msgf("get image list error")
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res), response.WithTotalItems(cnt))
}

// GetCiPolicy used for ci-tool requesting policy
func (c *CiApiSrv) GetCiPolicy(ctx *gin.Context) {
	ciCtl := c.Component.PM

	name := ctx.Param("name")
	p, err := ciCtl.GetPolicyByName(context.Background(), name)
	if err != nil {
		logging.Get().Err(err).Msg("get policy failed")
		response.JSONError(ctx, fmt.Errorf("get policy failed"))
		return
	}

	logging.Get().Info().Msg("get policy ok")
	ctx.JSON(http.StatusOK, p)
}

func (c *CiApiSrv) GetCiPolicies(ctx *gin.Context) {
	policies, err := c.Component.PM.GetPolicies(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("get policies failed")
		response.JSONError(ctx, fmt.Errorf("get policies failed"))
		return
	}
	// todo: use response.JSONOK() which need ci agent change too
	ctx.JSON(http.StatusOK, policies)
}

func (c *CiApiSrv) GetCiPolicyList(ctx *gin.Context) {
	limit := c.GetParseInt(ctx, "limit")
	offset := c.GetParseInt(ctx, "offset")
	name := ctx.Query("name")
	res, cnt, err := c.Component.PM.GetPolicyList(ctx, limit, offset, name)
	if err != nil {
		logging.Get().Err(err).Msg("get Policy list error")
		response.JSONError(ctx, fmt.Errorf("get Policy list error"))
		return
	}
	response.JSONOK(ctx, response.WithItems(res), response.WithTotalItems(cnt))
}

func (c *CiApiSrv) CreateCiPolicy(ctx *gin.Context) {
	policyAPI := scanner_ci.CiPolicyAPI{}
	err := ctx.BindJSON(&policyAPI)
	if err != nil {
		logging.Get().Err(err).Msg("bad request format")
		response.JSONError(ctx, fmt.Errorf("bad request format"))
		return
	}
	if len(policyAPI.VulnWhitelist) > 0 {
		for _, v := range policyAPI.VulnWhitelist {
			if v.Object != "all" {
				if !strings.Contains(v.Object, "@") {
					str := fmt.Sprintf("%v软件包格式错误", v.Object)
					logging.Get().Err(err).Msg(str)
					ctx.JSON(http.StatusInternalServerError, response.HTTPEnvelope{
						Error: &response.HTTPError{
							Code:    1,
							Message: str,
						},
					})
					return
				}
			}
		}
	}
	policy := policyAPI.TransToPolicy()
	policyID, err := c.Component.PM.CreatePolicy(ctx, &policy)
	if err != nil {
		str := ""
		if strings.Contains(err.Error(), "Duplicate entry") {
			str = fmt.Sprintf("策略名称%s重复", policy.Name)
		} else {
			str = fmt.Sprintf("create policy error")
		}
		logging.Get().Err(err).Msg(str)
		ctx.JSON(http.StatusInternalServerError, response.HTTPEnvelope{
			Error: &response.HTTPError{
				Code:    1,
				Message: str,
			},
		})
		return
	}
	response.JSONOK(ctx, response.WithItem(policyID), response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(policyID)), Name: policy.Name}))
}

func (c *CiApiSrv) UpdatePolicy(ctx *gin.Context) {
	policyAPI := scanner_ci.CiPolicyAPI{}
	err := ctx.BindJSON(&policyAPI)
	if err != nil {
		logging.Get().Err(err).Msg("bad request format")
		response.JSONError(ctx, fmt.Errorf("bad request format"))
		return
	}
	policy := policyAPI.TransToPolicy()
	err = c.Component.PM.UpdatePolicy(ctx, &policy)
	if err != nil {
		logging.Get().Err(err).Msgf("update policy error policyID :%v", policy.ID)
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(policy.ID)), Name: policy.Name}))
}

func (c *CiApiSrv) DeleteCiPolicy(ctx *gin.Context) {
	id, err := strconv.ParseInt(ctx.Query("id"), 10, 64)
	if err != nil {
		logging.Get().Err(err).Msg("bad request format")
		response.JSONError(ctx, fmt.Errorf("bad request format"))
		return
	}
	err = c.Component.PM.DeleteCiPolicy(ctx, id)
	if err != nil {
		logging.Get().Err(err).Msgf("delete Ci policy %v error", id)
		response.JSONError(ctx, fmt.Errorf("delete ci policy error"))
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(id))}))
}

func (c *CiApiSrv) CiPolicyDetail(ctx *gin.Context) {
	id, err := strconv.ParseInt(ctx.Query("id"), 10, 64)
	if err != nil {
		logging.Get().Err(err).Msg("bad request format")
		response.JSONError(ctx, fmt.Errorf("bad request format"))
		return
	}
	policy, err := c.Component.PM.GetPolicyDetail(ctx, id)
	if err != nil {
		logging.Get().Err(err).Msgf("get policy error policyID :%v", id)
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(policy))
}

// MatchVulnerability used for scan tool request image vulns
func (c *CiApiSrv) MatchVulnerability(ctx *gin.Context) {
	logging.Get().Debug().Msg("recv vuln analyze request")

	imageArtifact := scanner_ci.ImageArtifact{}
	err := ctx.BindJSON(&imageArtifact)
	if err != nil {
		logging.Get().Err(err).Msg("bad request format")
		response.JSONError(ctx, fmt.Errorf("bad request format"))
		return
	}

	ciCtl := c.Component.Ctrl
	// if err != nil {
	// 	logging.Get().Err(err).Msg("create ci controller failed")
	// 	response.JSONError(ctx, fmt.Errorf("create ci controller failed"))
	// 	return
	// }

	logging.Get().Debug().Msg("start match")
	res, err := ciCtl.VulnerabilityMatch(imageArtifact)
	if err != nil {
		logging.Get().Err(err).Msg("analyze vuln failed")
		response.JSONError(ctx, fmt.Errorf("analyze failed"))
		return
	}
	logging.Get().Debug().Msg("match vuln end")

	rsp := &scanner_ci.ImageVulnerabilities{
		ImageName: imageArtifact.ImageName,
		UUID:      imageArtifact.UUID,
		Results:   res,
	}
	ctx.JSON(http.StatusOK, rsp)
}

func (c *CiApiSrv) TiDbVersion(ctx *gin.Context) {
	logging.Get().Debug().Msg("recv ti db version request")
	dirExist := func(path string) bool {
		_, err := os.Stat(path)
		if err != nil {
			if os.IsExist(err) {
				return true
			}
			return false
		}
		return true
	}

	var versionFile string
	updatePath := filepath.Join(global.ScannerOpts.PvcPath, "offline")
	if dirExist(updatePath) {
		versionFile = filepath.Join(updatePath, "trivy_init_version")
	} else {
		versionFile = filepath.Join(global.ScannerOpts.PvcPath, "trivy_init_version")
	}

	// open db version file
	type rsp struct {
		TiDBVersion string `json:"ti_db_version"`
	}
	data, err := ioutil.ReadFile(versionFile)
	if err != nil {
		logging.Get().Err(err).Msg("read version file failed")
		response.JSONError(ctx, err)
		return
	}
	versionContent := strings.TrimSpace(string(data))
	logging.Get().Debug().Str("version", versionContent).Msg("ti db version")

	response.JSONOK(ctx, response.WithItem(rsp{
		TiDBVersion: versionContent,
	}))
}

func (c *CiApiSrv) SaveResult(ctx *gin.Context) {
	result := scanner_ci.PolicyResult{}
	err := ctx.BindJSON(&result)
	if err != nil {
		logging.Get().Err(err).Msg("bad request")
		response.JSONError(ctx, fmt.Errorf("bad request"))
		return
	}
	ciCtl := c.Component.Ctrl
	err = ciCtl.SaveResult(result)
	if err != nil {
		logging.Get().Err(err).Msg("save result failed")
		response.JSONError(ctx, fmt.Errorf("save result failed"))
		return
	}

	// async send to webhook url
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		err := c.Component.WH.TriggerWebhook(ctx, result)
		if err != nil {
			logging.Get().Err(err).Msg("TriggerWebhook failed")
			return
		}
	}()

	ctx.JSON(http.StatusOK, nil)
}

func (c *CiApiSrv) CreateWhitelist(ctx *gin.Context) {
	whitelist := []scanner_ci.CiWhitelistReq{}
	err := ctx.BindJSON(&whitelist)
	if err != nil {
		logging.Get().Err(err).Msg("bad request")
		response.JSONError(ctx, fmt.Errorf("bad request"))
		return
	}
	var errStrings []string
	mp := make(map[string]struct{})
	for k := range whitelist {
		if _, ok := mp[whitelist[k].Name]; !ok {
			_, err := regexp.Compile(whitelist[k].Name)
			mp[whitelist[k].Name] = struct{}{}
			if err != nil {
				logging.Get().Err(err).Msgf("%s 正则编译失败", whitelist[k].Name)
				errStrings = append(errStrings, fmt.Sprintf("%s 不是有效的正则表达式，请参考RE2语法", whitelist[k].Name))
			}
		}
	}
	if len(errStrings) != 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusNotAcceptable, fmt.Errorf(strings.Join(errStrings, "\n"))))
		return
	}

	err = c.Component.WM.CreateWhitelist(ctx, whitelist)
	if err != nil {
		logging.Get().Err(err).Msgf("create whitelist err ")
		if strings.Contains(err.Error(), "白名单") {
			response.JSONError(ctx, err)
		} else {
			response.JSONError(ctx, fmt.Errorf("create whitelist err"))
		}
		return
	}
	var creates []string
	for k := range mp {
		creates = append(creates, k)
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{Name: strings.Join(creates, ",")}))
}

func (c *CiApiSrv) DeleteWhitelist(ctx *gin.Context) {
	id := c.GetParseInt(ctx, "id")
	err := c.Component.WM.DeleteWhitelist(ctx, id)
	if err != nil {
		logging.Get().Err(err).Msgf("delete whitelist err id %v", id)
		response.JSONError(ctx, fmt.Errorf("delete whitelist err id %v", id))
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(id))}))
}

func (c *CiApiSrv) MatchWhitelist(ctx *gin.Context) {
	name := ctx.Query("name")
	if name == "" {
		logging.Get().Error().Msg("bad request")
		response.JSONError(ctx, fmt.Errorf("bad request"))
		return
	}
	whitelist, _, err := c.Component.WM.GetWhiteList(ctx, scanner_ci.WhitelistParams{Limit: 10000, Offset: 0, NowTime: time.Now().UnixMilli()})
	if err != nil {
		logging.Get().Err(err).Msg("get whitelist error")
		response.JSONError(ctx, fmt.Errorf("get whitelist error"))
		return
	}
	regs := []*regexp.Regexp{}
	for _, v := range whitelist {
		reg, err := regexp.Compile(v.Name)
		if err != nil {
			logging.Get().Warn().Msgf("compile failed %s", v.Name)
			continue
		}
		regs = append(regs, reg)
	}

	type Res struct {
		Flag bool `json:"flag"`
	}
	tmp := Res{}
	for k := range regs {
		if regs[k].Match([]byte(name)) {
			tmp.Flag = true
		}
	}

	response.JSONOK(ctx, response.WithItem(tmp))
}

func (c *CiApiSrv) UpdateWhitelist(ctx *gin.Context) {
	whitelist := []scanner_ci.CiWhitelistReq{}
	err := ctx.BindJSON(&whitelist)
	if err != nil {
		logging.Get().Err(err).Msg("bad request")
		response.JSONError(ctx, fmt.Errorf("bad request"))
		return
	}
	err = c.Component.WM.UpdateWhitelist(ctx, whitelist)
	if err != nil {
		logging.Get().Err(err).Msgf("update whitelist err Name %v", whitelist[0].Name)
		response.JSONError(ctx, fmt.Errorf("update whitelist err Name %v", whitelist[0].Name))
		return
	}
	var creates []string
	for k := range whitelist {
		creates = append(creates, whitelist[k].Name)
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{Name: strings.Join(creates, ",")}))
}

func (c *CiApiSrv) GetWhitelist(ctx *gin.Context) {
	name := ctx.Query("name")
	limit := c.GetParseInt(ctx, "limit")
	offset := c.GetParseInt(ctx, "offset")
	startTime := c.GetParseInt(ctx, "start_time")
	endTime := c.GetParseInt(ctx, "end_time")
	res, cnt, err := c.Component.WM.GetWhiteList(ctx, scanner_ci.WhitelistParams{Image: name, Limit: int(limit), Offset: int(offset),
		StartTime: startTime, EndTime: endTime})
	if err != nil {
		logging.Get().Err(err).Msg("Get White List error")
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res), response.WithTotalItems(cnt))
}

func (c *CiApiSrv) GetRecordPkgs(ctx *gin.Context) {
	search := ctx.Query("search")
	limit := c.GetParseInt(ctx, "limit")
	offset := c.GetParseInt(ctx, "offset")
	imageID := c.GetParseInt(ctx, "image_id")
	res, cnt, err := c.Component.IM.GetRecordPkgs(ctx, limit, offset, search, imageID)
	if err != nil {
		logging.Get().Err(err).Msg("Get GetRecordPkgs error")
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res), response.WithTotalItems(cnt))
}

func (c *CiApiSrv) GetVulnDetail(ctx *gin.Context) {
	var (
		uniqueVuln uint64
		err        error
	)

	uniqueVulnStr := ctx.Query("uniqueVuln")
	logging.Get().Debug().Str("uniqueVulnStr", uniqueVulnStr).Msg("recv get vuln req")
	if uniqueVulnStr == "" {
		vulnName := ctx.Query("vulnName")
		pkgName := ctx.Query("pkgName")
		pkgVersion := ctx.Query("pkgVersion")
		logging.Get().Debug().Str("vuln", vulnName).Str("pkgName", pkgName).Str("pkgVersion", pkgVersion).Msg("recv get vuln req")

		if vulnName == "" || pkgName == "" || pkgVersion == "" {
			response.JSONError(ctx, fmt.Errorf("vulnName,pkgName,pkgVersion must not empty"))
			return
		}
		uniqueVuln = util.GenerateUUID64(fmt.Sprintf(consts.UniqueVulnFamat, vulnName, pkgName, pkgVersion))
	} else {
		uniqueVuln, err = strconv.ParseUint(uniqueVulnStr, 10, 64)
		if err != nil {
			logging.Get().Err(err).Msg("parse uniq vuln err")
			response.JSONError(ctx, fmt.Errorf("not get uniqueVuln"))
			return
		}
	}
	logging.Get().Debug().Uint64("uniqVuln", uniqueVuln).Msg("get vuln hash")

	vulns, _, _, err := c.Component.IM.SearchVulns(ctx, scanner_ci.SearchVulnParam{UniqueVulns: []uint64{uniqueVuln}}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(vulns) == 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not fond vuln")))
		return
	}

	// 数据转换，兼容前端
	vuln := vulns[0]
	res := scanner_ci.VulnDetail{
		VulninfoApi: scanner_ci.VulnDetailInfo{
			ID:          vuln.ID,
			UniqueVuln:  vuln.UniqueVuln,
			Name:        vuln.Name,
			Severity:    vuln.Severity,
			Pkgname:     vuln.PkgName,
			Pkgversion:  vuln.PkgVersion,
			Links:       vuln.Link,
			Fixedby:     vuln.FixedBy,
			Description: vuln.Description,
			CvssMap:     c.Component.IM.TransCvss3ToPercent(vuln.Metadata.CVSS.CVSSv3Vector),
		}}
	if vuln.Metadata != nil {
		res.VulninfoApi.Cvss = vuln.Metadata.CVSS
		res.VulninfoApi.Cnvd = vuln.Metadata.CNVDs
		res.VulninfoApi.CNNVDs = vuln.Metadata.CNNVDs
	}

	response.JSONOK(ctx, response.WithItem(res))
}

func (c *CiApiSrv) GetRecordVulns(ctx *gin.Context) {
	vulnKeyword := ctx.Query("keyword")
	imageID := c.GetParseInt(ctx, "imageID")
	if imageID <= 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not get imageID")))
		return
	}
	pkgName := ctx.Query("pkgName")
	pkgVersion := ctx.Query("pkgVersion")
	sources := ctx.Query("sources")
	canFixed := ctx.Query("canFixed")
	severityInts := make([]int64, 0)
	class := util.GetStringSliceFromQuery(ctx, "class")
	severityStr := ctx.Query("severity")
	matchPolicy := ctx.Query("match_policy")
	match := false
	if matchPolicy != "" {
		match = true
	}
	if severityStr != "" {
		severityStrs := strings.Split(severityStr, ",")
		for _, severity := range severityStrs {
			severityInt := model.GetSeverityInt(strings.ToUpper(severity))
			if severityInt > 0 {
				severityInts = append(severityInts, int64(severityInt))
			}
		}
	}

	filter := model.GetFilter(ctx)
	if filter.SortFiled == "" {
		filter.SortFiled = "severity_int"
	}
	if filter.SortBy == "" {
		filter.SortBy = consts.SortByDesc
	}
	param := scanner_ci.SearchVulnParam{
		VulnKeyword: vulnKeyword,
		ImageID:     imageID,
		PkgName:     pkgName,
		PkgVersion:  pkgVersion,
		Sources:     sources,
		CanFixed:    canFixed,
		SeverityInt: severityInts,
		Class:       class,
		MatchPolicy: match,
	}
	vulns, levels, cnt, err := c.Component.IM.SearchVulns(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res := make([]scanner_ci.VulnList, len(vulns))

	for i := range vulns {
		res[i] = scanner_ci.VulnList{
			ID:          vulns[i].ID,
			Name:        vulns[i].Name,
			SeverityInt: vulns[i].SeverityInt,
			Severity:    vulns[i].Severity,
			FixedBy:     vulns[i].FixedBy,
			UniqueVuln:  vulns[i].UniqueVuln,
			Language:    vulns[i].Language,
			PkgName:     vulns[i].PkgName,
			PkgVersion:  vulns[i].PkgVersion,
			Match:       vulns[i].Match,
			White:       vulns[i].White,
			Class:       vulns[i].Class,
		}
	}
	sort.Sort(scanner_ci.VulnLists(res))
	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(int64(cnt)), response.WithItem(levels))
}

func (c *CiApiSrv) CreateWebhook(ctx *gin.Context) {
	wh := ci.WebhookReq{}
	err := ctx.BindJSON(&wh)
	if err != nil {
		logging.Get().Err(err).Msg("bad request")
		response.JSONError(ctx, fmt.Errorf("bad request"))
		return
	}
	err = c.Component.WH.CreateWebhook(ctx, wh)
	if err != nil {
		logging.Get().Err(err).Msg("CreateWebhook error")
		response.JSONError(ctx, fmt.Errorf("CreateWebhook error"))
		return
	}
	response.JSONOK(ctx)
}

func (c *CiApiSrv) UpDateWebhook(ctx *gin.Context) {
	wh := ci.WebhookReq{}
	err := ctx.BindJSON(&wh)
	if err != nil {
		logging.Get().Err(err).Msg("bad request")
		response.JSONError(ctx, fmt.Errorf("bad request"))
		return
	}
	err = c.Component.WH.UpdateWebhook(ctx, wh)
	if err != nil {
		logging.Get().Err(err).Msg("UpDateWebhook error")
		response.JSONError(ctx, fmt.Errorf("UpDateWebhook error"))
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{Name: fmt.Sprintf("  enable:%v,url:%s,secret:%s,options:%s", wh.Enable, wh.URL, wh.Secret, wh.Options)}))
}

func (c *CiApiSrv) GetWebhook(ctx *gin.Context) {
	res, err := c.Component.WH.GetWebhook(ctx)
	if err != nil {
		logging.Get().Err(err).Msg("GetWebhook error")
		response.JSONError(ctx, fmt.Errorf("GetWebhook error"))
		return
	}
	response.JSONOK(ctx, response.WithItem(res))
}

func (c *CiApiSrv) GetWebhookRecords(ctx *gin.Context) {
	limit := c.GetParseInt(ctx, "limit")
	offset := c.GetParseInt(ctx, "offset")
	res, cnt, err := c.Component.WH.GetWebhookRecords(ctx, int(limit), int(offset))
	if err != nil {
		logging.Get().Err(err).Msg("GetWebhookRecords error")
		response.JSONError(ctx, fmt.Errorf("GetWebhookRecords error"))
		return
	}
	response.JSONOK(ctx, response.WithItems(res), response.WithTotalItems(cnt))
}

func (c *CiApiSrv) GetParseInt(ctx *gin.Context, s string) int64 {
	str := ctx.Query(s)
	if str == "" {
		return 0
	}
	num, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		logging.Get().Err(err).Msgf("Parse %v error str :%v", s, str)
		return 0
	}
	return num
}
