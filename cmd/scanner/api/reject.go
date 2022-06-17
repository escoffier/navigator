package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type RejectAPI struct {
	Srv component.ImageRejectSrv
}

// Overview
// @Summary Overview
// @Title 首页统计
// @Author guolingkai@tensorsecurity.cn
// @Description 首页统计
// @Tags image reject
// @Param graph query string true "展示时间 24hour等"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.ImageRejectOverview{}}}
// @Router	/api/v1/imagereject/overview [get]
func (r *RejectAPI) Overview(ctx *gin.Context) {
	graph := ctx.Query("graph")
	overview, err := r.Srv.GetOverview(ctx, graph)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*overview))
}

// ListRejectRecord
// @Summary ListRejectRecord
// @Title 获取阻断记录
// @Author guolingkai@tensorsecurity.cn
// @Description 展示阻断信息列表
// @Tags image reject
// @Param search query string true "镜像名模糊搜索"
// @Param library query string true "仓库筛选"
// @Param reject_reason query string true "阻断理由筛选"
// @Success 200 {object} ApiWithItem{data=ApiItems{items=[]model.RejectRecord{}}}
// @Router	/api/v1/imagereject/overview [get]
func (r *RejectAPI) ListRejectRecord(ctx *gin.Context) {
	search := ctx.Query("search")
	filter := model.GetFilter(ctx)
	libraries := make([]string, 0)
	library := ctx.Query("library")
	if library != "" {
		libraries = append(libraries, strings.Split(library, ",")...)
	}
	rejectReason := strings.Split(ctx.Query("reject_reason"), ",")
	rjr := make([]int64, 0)
	for _, rr := range rejectReason {
		if i, err := strconv.ParseInt(rr, 10, 64); err == nil {
			rjr = append(rjr, i)
		}
	}
	rjr = util.DeDuplicationInt64Slice(rjr)
	var flag uint64
	for _, rj := range rjr {
		flag = 1<<rj + flag
	}

	// 默认只以阻断时间排序
	if filter.SortFiled == "" {
		filter.SortFiled = "reject_at"
	}
	filter = filter.SetDefault()

	rgs, cnt, err := r.Srv.ListRejectRecord(ctx, search, libraries, flag, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(rgs),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// ListWhitelist
// @Summary ListWhitelist
// @Title 白名单列表
// @Author guolingkai@tensorsecurity.cn
// @Description 获取白名单列表
// @Tags image reject
// @Success 200 {object} ApiWithItem{data=ApiItem{items=[]model.ImageWhitelist{}}}
// @Router	/api/v1/imagereject/whitelist [get]
func (r *RejectAPI) ListWhitelist(ctx *gin.Context) {
	search := ctx.Query("search")
	filter := model.GetFilter(ctx)
	iws, cnt, err := r.Srv.ListImageWhitelist(ctx, search, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(iws),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// DeleteWhitelist
// @Summary DeleteWhitelist
// @Title 删除白名单
// @Author guolingkai@tensorsecurity.cn
// @Description 删除白名单
// @Tags image reject
// @Param id path int true "白名单ID"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/imagereject/whitelist/:id [delete]
func (r *RejectAPI) DeleteWhitelist(ctx *gin.Context) {
	id, _ := strconv.ParseInt(ctx.Param("id"), 10, 64)
	err := r.Srv.DeleteImageWhitelist(ctx, id)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: fmt.Sprintf("Whitelist %d", id),
		ID:   strconv.Itoa(int(id)),
		Link: "api/v2/containerSec/scanner/imagereject/whitelist" + strconv.Itoa(int(id)),
	}))
}

// CreateWhitelist
// @Summary CreateWhitelist
// @Title 创建白名单
// @Author guolingkai@tensorsecurity.cn
// @Description 创建白名单
// @Tags image reject
// @Param body body	model.ImageWhitelist true "JSON数据"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.ImageWhitelist{}}}
// @Router	/api/v1/imagereject/whitelist [post]
func (r *RejectAPI) CreateWhitelist(ctx *gin.Context) {
	wi := new(model.ImageWhitelist)
	if err := ctx.BindJSON(wi); err != nil {
		response.JSONError(ctx, fmt.Errorf("解析传参出错：%s", err.Error()))
		return
	}
	res, err := r.Srv.CreateImageWhitelist(ctx, wi.FullRepoName, wi.Library, wi.Tag, wi.Digest)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res), response.WithTarget(&response.TargetRef{
		Name: fmt.Sprintf("whitelist %d for repo: %s%s:%s", wi.ID, wi.Library, wi.FullRepoName, wi.Tag),
		ID:   strconv.Itoa(int(wi.ID)),
		Link: "api/v2/containerSec/scanner/imagereject/whitelist",
	}))
}

// RejectReasons
// @Summary RejectReasons
// @Title 获取阻断原因
// @Author guolingkai@tensorsecurity.cn
// @Description 获取阻断原因的map
// @Tags image reject
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.RejectReasonMap{}}}
// @Router	/api/v1/imagereject/reasons [get]
func (r *RejectAPI) RejectReasons(ctx *gin.Context) {
	res := model.RejectReasonMap{
		En: model.GetRejectReason(model.LangEn),
		Zh: model.GetRejectReason(model.LangZh),
	}
	response.JSONOK(ctx, response.WithItem(res))
}

// DeletePolicy
// @Summary DeletePolicy
// @Title 删除单条策略
// @Author guolingkai@tensorsecurity.cn
// @Description 删除单条策略
// @Tags image reject
// @Param id path int true "policy ID"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/imagereject/policy/single/:id [delete]
func (r *RejectAPI) DeletePolicy(ctx *gin.Context) {
	id, _ := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err := r.Srv.DeletePolicy(ctx, id); err != nil {
		response.JSONError(ctx, err)
		return
	}
	name := ""
	policy, err := r.Srv.SearchRejectPolicy(ctx, "", "")
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	for i := range policy {
		if policy[i].ID == id {
			name = policy[i].Name
			break
		}
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: name,
		ID:   strconv.Itoa(int(id)),
		Link: "api/v2/containerSec/scanner/imagereject/policy/single/" + strconv.Itoa(int(id)),
	}))
}

// ListPolicy
// @Summary ListPolicy
// @Title 获取策略列表
// @Author guolingkai@tensorsecurity.cn
// @Description 获取策略列表
// @Tags image reject
// @Success 200 {object} ApiWithItem{data=ApiItems{items=[]model.RejectPolicy{}}}
// @Router	/api/v1/imagereject/policy/single [get]
func (r *RejectAPI) ListPolicy(ctx *gin.Context) {
	res, err := r.Srv.SearchRejectPolicy(ctx, "", consts.FalseString)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res))
}

// CreatePolicy
// @Summary CreatePolicy
// @Title 新增策略
// @Author guolingkai@tensorsecurity.cn
// @Description 新增策略接口
// @Tags image reject
// @Param body body	model.RejectPolicy true "策略JSON数据"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/imagereject/policy/single [post]
func (r *RejectAPI) CreatePolicy(ctx *gin.Context) {
	policy := new(model.RejectPolicy)
	if err := ctx.BindJSON(policy); err != nil {
		response.JSONError(ctx, err)
		return
	}

	logging.GetLogger().Debug().Msgf("received info %v\n", policy)
	policy.IsGlobal = false

	if err := r.Srv.CreateSinglePolicy(ctx, *policy); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: policy.Name,
		Link: "api/v2/containerSec/scanner/imagereject/policy/single",
	}))
}

// UpdateGlobalPolicy
// @Summary UpdateGlobalPolicy
// @Title 更新全局策略
// @Author liuqiang@tensorsecurity.cn
// @Description 更新全局策略
// @Tags image reject
// @Param body body	model.GlobalRejectPolicy true "全局策略JSON数据"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/imagereject/policy/global [put]
func (r *RejectAPI) UpdateGlobalPolicy(ctx *gin.Context) {
	global := new(model.GlobalRejectPolicy)
	if err := ctx.BindJSON(&global); err != nil {
		response.JSONError(ctx, err)
		return
	}

	logging.GetLogger().Info().Msgf("received info is %v\n", global)

	if err := r.Srv.CreateGlobalPolicy(ctx, *global); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: "global policy",
		Link: "api/v2/containerSec/scanner/imagereject/policy/global",
	}))
}

// GetGlobalPolicy
// @Summary GetGlobalPolicy
// @Title 获取全局策略
// @Author liuqiang@tensorsecurity.cn
// @Description 获取全局策略
// @Tags image reject
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.GlobalRejectPolicy{}}}
// @Router	/api/v1/imagereject/policy/global [get]
func (r *RejectAPI) GetGlobalPolicy(ctx *gin.Context) {
	policies, err := r.Srv.SearchRejectPolicy(ctx, "", consts.TrueString)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(policies) == 0 {
		defaultPolicy := model.GlobalRejectPolicy{
			CICDEnable:    false,
			K8sEnable:     false,
			Mode:          model.RejectPolicySafeModel,
			OnlineMonitor: false,
		}
		response.JSONOK(ctx, response.WithItem(defaultPolicy))
		return
	}
	res := model.GlobalRejectPolicy{
		CICDEnable:    policies[0].CicdEnable,
		K8sEnable:     policies[0].K8sEnable,
		Mode:          policies[0].Mode,
		OnlineMonitor: policies[0].OnlineMonitor,
	}

	response.JSONOK(ctx, response.WithItem(res))
}

// UpdatePolicy
// @Summary UpdatePolicy
// @Title 更新策略
// @Author liuqiang@tensorsecurity.cn
// @Description 更新策略接口
// @Tags image reject
// @Param body body	model.RejectPolicy true "JSON数据"
// @Param id path int true "策略ID"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/imagereject/policy/single/:id [put]
func (r *RejectAPI) UpdatePolicy(ctx *gin.Context) {
	id, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	policy := new(model.RejectPolicy)
	if err := ctx.BindJSON(&policy); err != nil {
		response.JSONError(ctx, err)
		return
	}

	logging.GetLogger().Debug().Msgf("收到的内容为 %v\n", policy)
	if err := r.Srv.UpdateSinglePolicy(ctx, id, *policy); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: policy.Name,
		ID:   strconv.Itoa(int(id)),
		Link: "api/v2/containerSec/scanner/imagereject/policy/single" + strconv.Itoa(int(id)),
	}))
}

// RSAGenerate 生成RSA密钥对
// @Summary 可信镜像
// @Title 生成RSA密钥对
// @Author liuyang@tensorsecurity.cn
// @Description 生成RSA密钥对
// @Tags image-reject
// @Param json body model.ImageRsa true "请求参数"
// @Success 200 {object} gin.Context
// @Router	/api/v1/imagereject/trustedImages/rsa [post]
func (r *RejectAPI) RSAGenerate(ctx *gin.Context) {
	var req = new(model.ImageRsa)
	err := ctx.BindJSON(req)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	result, err := r.Srv.RSAGenerate(ctx, req)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	targetRef := response.TargetRef{
		Name: req.Name,
		Link: "api/v2/containerSec/scanner/imagereject/trustedImages/rsa",
	}
	bys, err := json.Marshal(targetRef)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s_private.pem", req.Name))
	ctx.Header("Content-Type", "application/octet-stream")
	ctx.Header("Accept-Length", strconv.Itoa(len(result)))
	ctx.Header("targetref", string(bys))
	_, _ = ctx.Writer.Write(result)
}

// RSAUpdate 修改指定RSA密钥对
// @Summary 可信镜像
// @Title 修改指定RSA密钥对
// @Author liuyang@tensorsecurity.cn
// @Description 修改指定RSA密钥对
// @Tags image-reject
// @Param object body model.ImageRsa true "请求参数"
// @Param integer path id true "RSA id"
// @Success 200 {object} response.HTTPEnvelope{}
// @Failure 400 {object} response.HTTPEnvelope{}
// @Router	/api/v1/imagereject/trustedImages/rsa/:id [put]
func (r *RejectAPI) RSAUpdate(ctx *gin.Context) {
	id, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("%s 不是一个有效的ID", ctx.Param("id")))
		return
	}

	var req = new(model.ImageRsa)
	if err := ctx.BindJSON(req); err != nil {
		response.JSONError(ctx, err)
		return
	}

	if err := r.Srv.RSAUpdate(ctx, id, req); err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: req.Name,
		ID:   strconv.Itoa(int(id)),
		Link: "api/v2/containerSec/scanner/imagereject/trustedImages/rsa" + strconv.Itoa(int(id)),
	}))
}

// RSAList 获取RSA列表
// @Summary 可信镜像
// @Title 判断是否为可信镜像
// @Author liuyang@tensorsecurity.cn
// @Description 判断是否为可信镜像
// @Tags image-reject
// @Param integer query offset  true "偏移量"
// @Param integer query limit true "条数"
// @Success 200 {object} response.HTTPEnvelope{Data: []model}
// @Failure 400 {object} response.HTTPEnvelope{}
// @Router	/api/v1/imagereject/trustedImages/rsa [get]
func (r *RejectAPI) RSAList(ctx *gin.Context) {
	offset, err := strconv.ParseInt(ctx.Query("offset"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("%s 不是一个有效的偏移量", ctx.Query("offset")))
		return
	}
	limit, err := strconv.ParseInt(ctx.Query("limit"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("%s 不是一个有效的条数", ctx.Query("limit")))
		return
	}

	result, count, err := r.Srv.RSAList(ctx, limit, offset)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(result), response.WithTotalItems(count))
}

// RSADetail 获取某个RSA详情
// @Summary 可信镜像
// @Title 判断是否为可信镜像
// @Author liuyang@tensorsecurity.cn
// @Description 判断是否为可信镜像
// @Tags image-reject
// @Param object body model.IsTrustedImagesReq true "请求参数" // todo
// @Success 200 {object} response.HTTPEnvelope{Data: model.ImageRsa}
// @Router	/api/v1/imagereject/trustedImages/rsa/:id [get]
func (r *RejectAPI) RSADetail(ctx *gin.Context) {
	id, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("%s 不是一个有效的ID", ctx.Param("id")))
		return
	}

	result, err := r.Srv.RSADetail(ctx, id)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItem(result))
}

// RSADelete 删除某个RSA
// @Summary 可信镜像
// @Title 判断是否为可信镜像
// @Author liuyang@tensorsecurity.cn
// @Description 判断是否为可信镜像
// @Tags image-reject
// @Param integer path id true "RSA id"
// @Success 200 {object} response.HTTPEnvelope{}
// @Router	/api/v1/imagereject/trustedImages/rsa/:id [delete]
func (r *RejectAPI) RSADelete(ctx *gin.Context) {
	id, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("%s 不是一个有效的ID", ctx.Param("id")))
	}
	detail, err := r.Srv.RSADetail(ctx, id)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if err := r.Srv.RSADelete(ctx, id); err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: detail.Name,
		ID:   strconv.Itoa(int(id)),
		Link: "api/v2/containerSec/scanner/imagereject/trustedImages/rsa/" + strconv.Itoa(int(id)),
	}))
}

// SignImageTrusted 签名镜像是否可信
// @Router /api/v1/imagereject/trustedImages/sign [post]
func (r *RejectAPI) SignImageTrusted(ctx *gin.Context) {
	var s = new(model.SignImageTrustedReq)
	if err := ctx.BindJSON(s); err != nil {
		response.JSONError(ctx, err)
		return
	}

	err := r.Srv.SignImageTrusted(ctx, s)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: s.Image,
		ID:   s.Digest,
		Link: "api/v2/containerSec/scanner/imagereject/trustedImages/sign",
	}))
}

func NewRejectAPISrv(srv component.ImageRejectSrv) *RejectAPI {
	return &RejectAPI{
		Srv: srv,
	}
}
