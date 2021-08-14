package api

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type RejectApi struct {
	Srv component.ImageRejectSrv
}

// DeletePolicy
// @Summary DeletePolicy
// @Title DeletePolicy
// @Author guolingkai@tensorsecurity.cn
// @Description 删除单条策略
// @Tags reject
// @Param id path string true "policy ID"
// @Success 200 {object} ApiWithItem{data{}}
// @Router	/api/v1/imagereject/policy/:id [delete]
func (s *RejectApi) DeletePolicy(ctx *gin.Context) {
	id, _ := strconv.ParseInt(ctx.Param("id"), 10, 64)
	s.Srv.DeletePolicy(ctx, id)
	response.JSONOK(ctx)
}

// overview
// @Summary overview
// @Title overview
// @Author guolingkai@tensorsecurity.cn
// @Description 删除单条策略
// @Tags reject
// @Param graph query string true "展示时间 24hour等"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.ImageRejectOverview{}}}
// @Router	/api/v1/imagereject/overview [get]
func (s *RejectApi) Overview(ctx *gin.Context) {
	graph := ctx.Query("graph")
	overview, err := s.Srv.GetOverview(ctx, graph)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*overview))
}

// images
// @Summary images
// @Title images
// @Author guolingkai@tensorsecurity.cn
// @Description 展示阻断信息列表
// @Tags reject
// @Param search query string true "image like "
// @Param library query string true "仓库筛选 "
// @Param reject_reason query string true "阻断理由筛选 "
// @Success 200 {object} ApiWithItem{data=ApiItems{items=[]model.RejectRecord{}}}
// @Router	/api/v1/imagereject/overview [get]
func (s *RejectApi) ListRejectRecord(ctx *gin.Context) {
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
	// 默认只以阻断时间排序
	if filter.SortFiled == "" {
		filter.SortFiled = "reject_at"
	}
	filter = filter.SetDefault()

	rgs, cnt, err := s.Srv.ListRejectRecord(ctx, search, libraries, rjr, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(rgs),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *RejectApi) ListWhitelist(ctx *gin.Context) {
	search := ctx.Query("search")
	filter := model.GetFilter(ctx)
	iws, cnt, err := s.Srv.ListImageWhitelist(ctx, search, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(iws),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *RejectApi) DeleteWhitelist(ctx *gin.Context) {
	id, _ := strconv.ParseInt(ctx.Param("id"), 10, 64)
	err := s.Srv.DeleteImageWhitelist(ctx, id)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

func (s *RejectApi) CreateWhitelist(ctx *gin.Context) {
	wi := new(model.ImageWhitelist)
	if err := ctx.BindJSON(wi); err != nil {
		response.JSONError(ctx, fmt.Errorf("解析传参出错：%s", err.Error()))
		return
	}
	res, err := s.Srv.CreateImageWhitelist(ctx, wi.FullRepoName, wi.Library, wi.Tag, wi.Digest)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res))
}

func NewRejectApiSrv(srv component.ImageRejectSrv) *RejectApi {
	return &RejectApi{
		Srv: srv,
	}
}
